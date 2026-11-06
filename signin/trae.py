#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Trae CN 每日签到领积分 —— 纯云端实现。

服务端契约：status / claim 两条 POST，``Authorization: Cloud-IDE-JWT``，
claim 强制 ``x-device-id``（缺头 9004），9074 为活动期限流，业务码在 HTTP 200
的 ``code`` 字段。流程为 status → claim → 复查 status（0/3/8s 三轮确认），
写操作不重试，仅对 9074 按 30/60/120s 退避。

JWT 与设备号由 Secret 注入，**不随机伪造、也不用 UUID 兜底**（UUID 形态会触发
9074 风控）。JWT 有效期约 20 天，过期需重新导出 Secret。

设备号两种形态都接受：旧版 8-20 位纯数字；Trae CN 3.4.15+ 为
``aha-<32位hex>``（客户端把 ``guaranteedDeviceId`` 原样放进 ``x-device-id``）。
"""
from __future__ import annotations

import re
import time
from typing import Any

from . import common
from .common import Http, Result, make, short

DEFAULT_BASE_URL = "https://api.trae.cn"
STATUS_PATH = "/trae/api/v2/ug/checkin_credits/status"
CLAIM_PATH = "/trae/api/v2/ug/checkin_credits/claim"
BODY = {"req_source": 1}

#: 9074 限流业务码的同轮退避节奏。
CLAIM_BACKOFFS = (0.0, 30.0, 60.0, 120.0)
#: 领后 status 复查节奏。
CONFIRM_WAITS = (0.0, 3.0, 8.0)

DEVICE_HEADER_MAP = {
    "device_id": "x-device-id",
    "device_brand": "x-device-brand",
    "device_type": "x-device-type",
    "os_version": "x-os-version",
    "app_version": "x-app-version",
}

#: 客户端真实设备号：3.4.15+ 为 ``aha-<32位hex>``，旧版为 8-20 位纯数字。
VALID_DEVICE_ID = re.compile(r"^(?:aha-[0-9a-fA-F]{16,40}|\d{8,20})$")
UUID_DEVICE_ID = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")


def device_id_issue(acc: dict) -> str | None:
    """设备号形态诊断；返回 None 表示可安全发起 claim。

    status 不校验设备头，所以这里只在**准备领取前**拦截：既避免用 UUID
    白跑一轮并触发 9074 风控，也不影响「今日已签到」这类只读结果。
    """
    value = str(acc.get("device_id") or "").strip()
    if not value:
        return "未配置 device_id"
    if VALID_DEVICE_ID.match(value):
        return None
    if UUID_DEVICE_ID.match(value):
        return "device_id 是 telemetry.devDeviceId（UUID 形态），会触发 9074 风控"
    return "device_id 形态未识别（应为 aha-<hex> 或 8-20 位纯数字）"


def build_headers(acc: dict) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "Cloud-IDE-JWT " + acc["token"],
        "X-User-Region": str(acc.get("region") or "cn"),
        "User-Agent": "Trae/%s" % (acc.get("app_version") or "unknown"),
    }
    for field_name, header_name in DEVICE_HEADER_MAP.items():
        value = acc.get(field_name)
        if value:
            headers[header_name] = str(value)
    extra = acc.get("headers")
    if isinstance(extra, dict):
        headers.update({str(k): str(v) for k, v in extra.items()})
    return headers


def _business(app: str, name: str, code: Any, payload: Any) -> Result | None:
    """业务码 → 结果；``code=0`` 返回 None 表示成功。"""
    if code is None or str(code) == "0":
        return None
    text_code = str(code)
    if text_code == "1001":
        return make(app, name, "AUTH_REJECTED",
                    "服务端无法认证（code=1001）：JWT 已过期，请在桌面端重新登录并更新 Secret")
    if text_code == "9004":
        return make(app, name, "ERROR",
                    "下单参数错误（code=9004）：claim 强制 x-device-id，请确认 device_id 是"
                    "客户端真实设备号（3.4.15+ 为 aha-<32位hex>，旧版 8-20 位纯数字），"
                    "不要用 telemetry.devDeviceId 的 UUID")
    if text_code == "9074":
        return make(app, name, "RATE_LIMITED",
                    "当前参与用户太多（code=9074）：可能是服务端限流，也可能是设备号形态"
                    "不被接受（UUID 会触发风控）；已按退避重试仍失败，等下一轮调度补跑")
    if text_code == "710010702" or text_code.startswith("71001"):
        return make(app, name, "ERROR", "服务端返回系统错误 code=%s：%s" % (
            code, short((payload or {}).get("message") if isinstance(payload, dict) else payload, 80)))
    return make(app, name, "ERROR", "业务失败 code=%s：%s" % (
        code, short((payload or {}).get("message") if isinstance(payload, dict) else payload, 80)))


def _check_status(http: Http, app: str, name: str) -> tuple[Result | None, dict]:
    code, payload, err = http.request(STATUS_PATH, "POST", body=BODY)
    failure = common.transport_error(app, name, code, payload, err)
    if failure:
        return failure, {}
    if code != 200:
        return make(app, name, "ERROR", "查询失败：HTTP %s %s" % (code, short(payload))), {}
    body = payload if isinstance(payload, dict) else {}
    failure = _business(app, name, body.get("code"), body)
    if failure:
        return failure, {}
    return None, body


def run(acc: dict, *, dry_run: bool = False) -> Result:
    """status →（未签）claim → 复查确认。"""
    app, name = "trae", str(acc.get("name") or "Trae CN")
    base_url = str(acc.get("base_url") or DEFAULT_BASE_URL)
    budget = float(acc.get("budget_seconds") or 210)
    http = Http(base_url, build_headers(acc), timeout=20.0, budget=budget)

    failure, status = _check_status(http, app, name)
    if failure:
        return failure
    credits = status.get("credits")
    if status.get("checked_in") is True:
        return make(app, name, "ALREADY", "今日已签到（%s Credits）" % (credits or "?"),
                    credits=credits)
    if dry_run:
        issue = device_id_issue(acc)
        return make(app, name, "DRY_RUN",
                    "[dry-run] 今日未签到，将发起 claim" + ("；⚠️ %s" % issue if issue else ""),
                    detail={"device_id_issue": issue} if issue else {})

    # 设备号形态不对时不发 claim：UUID 会被判 9074，缺头会被判 9004，都是白跑。
    issue = device_id_issue(acc)
    if issue and not acc.get("allow_unsafe_device_id"):
        return make(app, name, "ERROR",
                    "跳过 claim：%s。请在电脑上重跑 python tools/export_secrets.py 并更新"
                    " SIGNIN_ACCOUNTS（Trae 3.4.15+ 的 device_id 形如 aha-<32位hex>）；"
                    "确认要强行发送可在该账号里加 allow_unsafe_device_id=true" % issue,
                    detail={"device_id_issue": issue})

    # claim 是写操作：HTTP 层不重试；仅对 9074 限流做有预算的同轮退避。
    rate_limited = False
    claim_body: dict = {}
    for backoff in CLAIM_BACKOFFS:
        if backoff and not http.budget.can_wait(backoff):
            break
        if backoff:
            time.sleep(backoff)
        ccode, cpayload, cerr = http.request(CLAIM_PATH, "POST", body=BODY, retry=False)
        failure = common.transport_error(app, name, ccode, cpayload, cerr)
        if failure:
            return failure
        if ccode != 200:
            return make(app, name, "ERROR", "领取失败：HTTP %s %s" % (ccode, short(cpayload)))
        claim_body = cpayload if isinstance(cpayload, dict) else {}
        biz = claim_body.get("code")
        if biz is None or str(biz) == "0":
            rate_limited = False
            break
        if str(biz) != "9074":
            return _business(app, name, biz, claim_body) or \
                make(app, name, "ERROR", "领取失败 code=%s" % biz)
        rate_limited = True
    if rate_limited:
        return make(app, name, "RATE_LIMITED",
                    "命中限流 9074，退避重试后仍未成功，等下一轮调度补跑")

    amount = claim_body.get("credits") or credits
    if claim_body.get("checked_in") is True:
        return make(app, name, "CLAIMED", "签到成功 +%s Credits" % (amount or "?"),
                    credits=amount)
    # 服务端受理但不回显结果：按 0/3/8s 复查 status 确认。
    for wait in CONFIRM_WAITS:
        if wait and not http.budget.can_wait(wait):
            break
        if wait:
            time.sleep(wait)
        failure, confirmed = _check_status(http, app, name)
        if failure:
            continue
        if confirmed.get("checked_in") is True:
            return make(app, name, "CLAIMED",
                        "签到成功（复查确认）+%s Credits" % (confirmed.get("credits") or amount or "?"),
                        credits=confirmed.get("credits") or amount)
    return make(app, name, "ERROR",
                "领取请求已发出但复查未确认签到，请稍后用 status 复查（不重复提交 claim）")
