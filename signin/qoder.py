#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Qoder（CN / 国际版）每日 100 Credits 领取 —— 纯云端实现。

服务端契约：

- ``GET /sash/api/v1/me/campaigns`` → ``POST .../{campaignId}/claim``（幂等），
  ``Cosy-ClientType: 10`` 必需，缺了服务端**静默返回空列表**（不是报错）；
- 每日活动 ``act-YYYYMMDD-NNN`` 按 UTC+8 每天 10:00 轮换，服务端只对
  **带完整设备风控头**的请求下发该活动；
- CN 用 ``openapi.qoder.com.cn``，国际版用 ``openapi.qoder.sh``，各自独立 token。

凭据与 ``Cosy-MachineToken/Code/Type`` 等静态设备标识均由 ``SIGNIN_ACCOUNTS``
Secret 注入；不编造设备号，没配就不发对应头并明确提示原因。
"""
from __future__ import annotations

import time
from typing import Any

from . import common
from .common import Http, Result, make, short

DEFAULT_BASE_URL = "https://openapi.qoder.com.cn"
CAMPAIGNS_PATH = "/sash/api/v1/me/campaigns"
CLAIM_PATH = "/sash/api/v1/me/campaigns/%s/claim"

#: 缺 Cosy-ClientType 时服务端静默返回空活动列表。
BASE_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "Qoder/claim",
    "Cosy-ClientType": "10",
}

#: 配置字段 → 请求头。值来自本机 ``runtime-info`` / ``auth.machine-id`` 输出。
RISK_HEADER_MAP = {
    "machine_token": "Cosy-MachineToken",
    "machine_code": "Cosy-MachineCode",
    "machine_type": "Cosy-MachineType",
    "machine_id": "Cosy-MachineId",
    "machine_os": "Cosy-MachineOS",
    "machine_hostname": "Cosy-MachineHostname",
    "version": "Cosy-Version",
}


def build_headers(acc: dict) -> dict[str, str]:
    headers = dict(BASE_HEADERS)
    headers["Authorization"] = "Bearer " + acc["token"]
    for field_name, header_name in RISK_HEADER_MAP.items():
        value = acc.get(field_name)
        if value:
            headers[header_name] = str(value)
    extra = acc.get("risk_headers")
    if isinstance(extra, dict):
        headers.update({str(k): str(v) for k, v in extra.items()})
    return headers


def _ts(value: Any) -> float | None:
    """活动窗口时间戳；服务端秒/毫秒两种形状都兼容。"""
    if not isinstance(value, (int, float)):
        return None
    return float(value) / 1000.0 if value > 10 ** 12 else float(value)


def is_active(campaign: dict, now: float) -> bool:
    start, end = _ts(campaign.get("startAt")), _ts(campaign.get("endAt"))
    if start is not None and now < start:
        return False
    return not (end is not None and now >= end)


def campaigns_of(payload: Any) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    rows = payload.get("campaigns")
    return [x for x in rows if isinstance(x, dict)] if isinstance(rows, list) else []


def select_campaigns(payload: Any, now: float) -> dict[str, list[dict]]:
    """只认 CLAIM_BENEFIT + 时间窗内的活动，再按 claimStatus 分流。"""
    benefit = [c for c in campaigns_of(payload) if c.get("actionType") == "CLAIM_BENEFIT"]
    active = [c for c in benefit if is_active(c, now)]
    return {
        "active": active,
        "todo": [c for c in active if c.get("claimStatus") == "CLAIMABLE"],
        "claimed": [c for c in active if c.get("claimStatus") == "CLAIMED"],
        "all": benefit,
    }


def _key(c: dict) -> str:
    return str(c.get("campaignKey") or c.get("campaignId") or "?")


def _amount(c: dict) -> Any:
    benefit = c.get("benefit")
    value = benefit.get("amount") if isinstance(benefit, dict) else None
    return value if isinstance(value, (int, float)) else None


def _sum(values: list[Any]) -> Any:
    present = [v for v in values if v is not None]
    return sum(present) if present else None


def _snapshot(rows: list[dict]) -> list[dict]:
    """留证：服务端当时到底返回了什么，方便排查「没有活动」的静默过滤。"""
    return [{"id": _key(c), "status": c.get("claimStatus") or "?",
             "action": c.get("actionType") or "?"} for c in rows[:10]]


def run(acc: dict, *, dry_run: bool = False) -> Result:
    """查活动 → 分类 → 幂等领取。全程不落盘、不改本机客户端状态。"""
    app, name = "qoder", str(acc.get("name") or "Qoder")
    base_url = str(acc.get("base_url") or DEFAULT_BASE_URL)
    http = Http(base_url, build_headers(acc), timeout=20.0,
                budget=float(acc.get("budget_seconds") or 90))

    code, payload, err = http.request(CAMPAIGNS_PATH, "GET")
    failure = common.transport_error(app, name, code, payload, err)
    if failure:
        return failure
    if code != 200 or not isinstance(payload, dict):
        return make(app, name, "ERROR", "查询活动失败：HTTP %s %s" % (code, short(payload)))

    picked = select_campaigns(payload, time.time())
    todo = picked["todo"]
    has_risk_header = any(acc.get(k) for k in ("machine_token", "machine_code", "machine_type")) \
        or bool(acc.get("risk_headers"))

    def inactive_note(text: str) -> str:
        if not has_risk_header:
            text += "；未配置设备风控头（machine_token/code/type），服务端会静默不下发每日活动"
        return text

    if not todo:
        if picked["claimed"]:
            keys = "、".join(_key(c) for c in picked["claimed"])
            return make(app, name, "ALREADY", "本窗口已领取（%s）" % keys,
                        credits=_sum([_amount(c) for c in picked["claimed"]]),
                        detail={"campaigns": _snapshot(picked["claimed"])})
        if picked["active"]:
            rows = "；".join("%s=%s" % (_key(c), c.get("claimStatus") or "?")
                            for c in picked["active"])
            return make(app, name, "PENDING", "活动存在但当前不可领取：%s" % rows,
                        detail={"campaigns": _snapshot(picked["active"])})
        result = make(app, name, "INACTIVE", inactive_note("当前没有可领取的 Credits 活动"),
                      detail={"campaigns": _snapshot(picked["all"])})
        # 没配设备风控头时「没有活动」是静默过滤造成的，属于配置问题而非正常空跑。
        if not has_risk_header:
            result.needs_attention = True
        return result

    keys = "、".join(_key(c) for c in todo)
    amount = _sum([_amount(c) for c in todo])
    if dry_run:
        return make(app, name, "DRY_RUN", "[dry-run] 可领取活动：%s" % keys, credits=amount)

    # 写操作不重试：超时若发生在服务端处理完成后，重试会重复提交。
    total: Any = None
    claimed: list[str] = []
    failures: list[str] = []
    for campaign in todo:
        cid = campaign.get("campaignId")
        ccode, cbody, cerr = http.request(CLAIM_PATH % cid, "POST", body=b"",
                                          retry=False)
        if ccode in (401, 403):
            return common.transport_error(app, name, ccode, cbody, cerr) or \
                make(app, name, "ERROR", "领取被拒绝 HTTP %s" % ccode)
        data = cbody.get("data") if isinstance(cbody, dict) and isinstance(cbody.get("data"), dict) \
            else cbody
        ok = ccode == 200 and isinstance(data, dict) and data.get("status") == "CLAIMED"
        if not ok:
            failures.append("%s: HTTP %s %s" % (_key(campaign), ccode, short(cerr or cbody, 100)))
            continue
        value = _amount(data) if isinstance(data, dict) else None
        if value is None:
            value = _amount(campaign)
        total = value if total is None else (total + (value or 0))
        claimed.append(_key(campaign))
        if data.get("replayed"):
            failures.append("%s: 服务端返回幂等重放" % _key(campaign))

    if failures and not claimed:
        return make(app, name, "ERROR", "领取失败：%s" % "；".join(failures))
    report = "成功领取 %s Credits（%s）" % ("" if total is None else total,
                                        "、".join(claimed) or keys)
    if failures:
        report += "；部分失败：%s" % "；".join(failures)
    return make(app, name, "CLAIMED", report, credits=total,
                detail={"campaigns": _snapshot(todo), "replayed": bool(failures)})
