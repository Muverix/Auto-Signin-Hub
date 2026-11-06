#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""豆包（电脑版）「签到领额度」+ 任务奖励清扫 —— 纯云端实现。

服务端契约：AGW 公共查询参数七个缺一不可；签到接口幂等（重复调用
``idempotent=true``）；鉴权只靠 Cookie、无签名；``710012*`` = 登录过期，
``code=2`` = 活动换季。签到后清扫 ``v3/detail`` 里 ``task_status==2``
（已完成待领取）的任务/里程碑奖励。

完整 Cookie 头由 Secret 直接注入。会话在服务端过期后只存在于客户端内存，
Cookie 库可能仍是旧的，因此豆包 Cookie 是四个平台里**最容易过期**的；
失败时重新登录客户端并更新 Secret 即可。
"""
from __future__ import annotations

from typing import Any

from . import common
from .common import Http, Result, make, short

DEFAULT_BASE_URL = "https://www.doubao.com"
DEFAULT_CAMPAIGN = "pc_incentive_task_mvp_v3"

#: 公共查询参数缺一不可（缺了报 invalid param / system error）。
COMMON_QUERY = "&".join((
    "version_code=20800",
    "language=zh",
    "device_platform=web",
    "doubao_device_platform=web",
    "aid=497858",
    "real_aid=497858",
    "pkg_type=release_version",
))

CHECKIN_PATH = "/alice/ug/campaign/landing/checkin/"
DETAIL_PATH = "/alice/ug/campaign/v3/detail/"
LANDING_PATH = "/alice/ug/campaign/landing/get"
CLAIM_PATH = "/alice/ug/campaign/item/reward/claim/"


def build_headers(acc: dict, base_url: str) -> dict[str, str]:
    headers = {
        "Cookie": acc["cookie"],
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": base_url,
        "Referer": base_url + "/pc/agent-explore",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
        ),
    }
    extra = acc.get("headers")
    if isinstance(extra, dict):
        headers.update({str(k): str(v) for k, v in extra.items()})
    return headers


def _business(app: str, name: str, body: dict, *, campaign: str) -> Result | None:
    """业务码 → 结果；``code=0`` 返回 None。"""
    code = body.get("code")
    if code is None or str(code) == "0":
        return None
    text = str(code)
    if text.startswith("710012"):
        return make(app, name, "NO_AUTH",
                    "登录已过期（code=%s）：请在电脑上重新登录豆包客户端并更新 Cookie Secret" % code)
    if text == "2":
        return make(app, name, "ERROR",
                    "活动不在期或已换季（code=2 campaign not found）：请更新 campaign_code")
    if text == "710010702":
        return make(app, name, "ERROR",
                    "服务端返回系统错误（code=710010702）。这可能是服务端故障，"
                    "接口幂等，等下一轮调度自动补签")
    return make(app, name, "ERROR", "业务失败 code=%s msg=%s" % (
        code, short(body.get("msg") or body.get("message"), 80)))


def _sweep_rewards(http: Http, app: str, name: str, campaign: str) -> dict[str, Any]:
    """清扫已完成待领取的任务奖励（task_status=2），不代做任务。"""
    code, payload, err = http.request(DETAIL_PATH, "POST",
                                      body={"campaign_group_code": campaign},
                                      query=COMMON_QUERY)
    body = payload if isinstance(payload, dict) else {}
    if code != 200 or str(body.get("code")) != "0":
        return {"error": "活动详情查询失败(http=%s code=%s)" % (code, body.get("code"))}
    data = body.get("data") or {}
    items = (data.get("tasks") or []) + (data.get("milestones") or [])
    claimable = [t for t in items if isinstance(t, dict) and t.get("task_status") == 2]
    claimed: list[dict] = []
    failures: list[str] = []
    for task in claimable:
        item_code = task.get("campaign_code") or ""
        title = task.get("title") or item_code
        ccode, cbody, cerr = http.request(
            CLAIM_PATH, "POST",
            body={"task_id": "", "campaign_group_code": campaign,
                  "campaign_item_code": item_code, "AgwCommonParam": {}},
            query=COMMON_QUERY, retry=False)
        cp = cbody if isinstance(cbody, dict) else {}
        cd = cp.get("data") or {}
        biz = cd.get("biz_error") or {}
        if ccode == 200 and str(cp.get("code")) == "0" and not biz:
            rewards = task.get("reward_summaries") or [{}]
            claimed.append({"code": item_code, "title": title,
                            "amount": rewards[0].get("reward_amount")})
        else:
            failures.append("%s: %s" % (title, biz.get("message") or cerr or ccode))
    return {"claimed": claimed, "failures": failures,
            "pending": sum(1 for t in items if isinstance(t, dict) and t.get("task_status") == 1)}


def run(acc: dict, *, dry_run: bool = False) -> Result:
    """签到（幂等）→ 顺手清扫任务奖励。"""
    app, name = "doubao", str(acc.get("name") or "豆包")
    base_url = str(acc.get("base_url") or DEFAULT_BASE_URL)
    campaign = str(acc.get("campaign_code") or DEFAULT_CAMPAIGN)
    http = Http(base_url, build_headers(acc, base_url), timeout=20.0,
                budget=float(acc.get("budget_seconds") or 90))

    if dry_run:
        code, payload, err = http.request(LANDING_PATH, "POST",
                                          body={"scene": campaign}, query=COMMON_QUERY)
        body = payload if isinstance(payload, dict) else {}
        ok = code == 200 and str(body.get("code")) == "0"
        return make(app, name, "DRY_RUN" if ok else "ERROR",
                    "[dry-run] 活动落地页可达" if ok else
                    "[dry-run] 活动不可达：HTTP %s code=%s %s" % (code, body.get("code"), err or ""),
                    detail={"campaign_code": campaign})

    code, payload, err = http.request(CHECKIN_PATH, "POST",
                                      body={"scene": campaign}, query=COMMON_QUERY)
    failure = common.transport_error(app, name, code, payload, err)
    if failure:
        return failure
    body = payload if isinstance(payload, dict) else {}
    failure = _business(app, name, body, campaign=campaign)
    if failure:
        return failure
    data = body.get("data") or {}

    sweep = _sweep_rewards(http, app, name, campaign) if not acc.get("no_sweep") else {}
    claimed = sweep.get("claimed") or []
    task_amount = sum((c.get("amount") or 0) for c in claimed)
    amount = data.get("reward_amount")
    days = data.get("continuous_days")

    parts: list[str] = []
    if data.get("idempotent"):
        status = "ALREADY"
        parts.append("今日已签到 +%s额度（连签%s天）" % (amount if amount is not None else "?",
                                                  days if days is not None else "?"))
    else:
        status = "CLAIMED"
        parts.append("签到成功 +%s额度（连签%s天）" % (amount if amount is not None else "?",
                                                 days if days is not None else "?"))
    if claimed:
        status = "CLAIMED"
        parts.append("任务奖励 %d 项 +%s额度（%s）" % (
            len(claimed), task_amount, "、".join(str(c["title"]) for c in claimed)))
    if sweep.get("pending"):
        parts.append("%d 项任务未完成" % sweep["pending"])
    if sweep.get("failures"):
        parts.append("领取失败：%s" % "; ".join(sweep["failures"]))
    if sweep.get("error"):
        parts.append("[%s]" % sweep["error"])

    earned = (amount or 0) + task_amount
    return make(app, name, status, "；".join(parts), credits=earned or None,
                detail={"campaign_code": campaign, "checkin_date": data.get("checkin_date"),
                        "continuous_days": days, "task_rewards": claimed})
