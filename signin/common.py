#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""融合签到的公共层：零第三方依赖的 HTTP、结果模型、Secrets 配置、汇总与通知。

凭据一律由环境变量注入（GitHub Actions 容器里没有桌面客户端，不读本机登录态、
不调用设备组件）。服务端契约按以下原则实现：

- 幂等优先：先查状态，未签才领；写操作默认不重试，防止超时重复提交；
- 只重试网络不可达 / 429 / 5xx，退避 5/15/30s，401/403/业务码不重试；
- 时间预算：预算耗尽主动收尾，已领到的部分照常记录；
- 输出脱敏：token / cookie / 设备标识统一替换为 ``[REDACTED]``；
- 每个平台独立：一个平台失败不影响其它平台。
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

#: 正常业务态（不算失败、不触发提醒）。其余状态一律 needs_attention=True。
OK_STATUSES = frozenset({"CLAIMED", "ALREADY", "INACTIVE", "OK", "DRY_RUN", "SKIPPED"})

#: 平台 → 凭据字段（缺该字段的账号视为未配置，直接跳过）。
APPS = ("qoder", "trae", "doubao")
CREDENTIAL_FIELD = {"qoder": "token", "trae": "token", "doubao": "cookie"}
APP_LABEL = {"workbuddy": "WorkBuddy", "qoder": "Qoder", "trae": "Trae CN", "doubao": "豆包"}

#: 每个平台也支持单独一个 JSON 数组 Secret，便于分批配置。
ARRAY_ENV = {"qoder": "QODER_ACCOUNTS", "trae": "TRAE_ACCOUNTS", "doubao": "DOUBAO_ACCOUNTS"}
#: 单账号快捷变量（只要一个账号时用，省去写 JSON）。
SINGLE_ENV = {
    "qoder": ("QODER_TOKEN", "token"),
    "trae": ("TRAE_TOKEN", "token"),
    "doubao": ("DOUBAO_COOKIE", "cookie"),
}
#: 快捷变量的可选补充字段。特别是 Trae：只有 TRAE_TOKEN 会缺 device_id，
#: 运行侧会跳过 claim，因此导出工具的 env 格式会同时给 TRAE_DEVICE_ID。
SINGLE_EXTRA = {
    "qoder": {"QODER_BASE_URL": "base_url", "QODER_MACHINE_TOKEN": "machine_token"},
    "trae": {"TRAE_DEVICE_ID": "device_id", "TRAE_APP_VERSION": "app_version"},
    "doubao": {"DOUBAO_CAMPAIGN_CODE": "campaign_code"},
}


# ---------------------------------------------------------------- 结果模型

@dataclass
class Result:
    """一次「平台 × 账号」运行的统一结果。"""

    app: str
    account: str
    status: str
    report: str
    credits: Any = None
    needs_attention: bool = False
    detail: dict = field(default_factory=dict)

    def line(self) -> str:
        icon = "✅" if not self.needs_attention else "⚠️"
        amount = "" if self.credits in (None, "") else "  +%s" % self.credits
        return "%s %-10s %-12s %-16s %s%s" % (
            icon, APP_LABEL.get(self.app, self.app), self.account,
            self.status, self.report, amount)


def make(app: str, account: str, status: str, report: str, **extra: Any) -> Result:
    """构造结果；状态不在白名单里自动标记 needs_attention。"""
    return Result(app=app, account=account, status=status, report=redact(report),
                  needs_attention=status not in OK_STATUSES, **extra)


def short(value: Any, limit: int = 200) -> str:
    """压成单行并截断，用于错误上报（避免整页响应体刷屏）。"""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    text = " ".join(text.split())
    return text[:limit] + ("…" if len(text) > limit else "")


def dig(obj: Any, dotted: str) -> Any:
    """按点路径取值；缺路径返回 None。"""
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def redact(text: str, extra: tuple[str, ...] = ()) -> str:
    """脱敏：已登记的凭据值 + 调用方临时追加的值。"""
    out = str(text)
    for secret in sorted(set(_SENSITIVE) | set(extra), key=len, reverse=True):
        if secret and len(secret) >= 8:
            out = out.replace(secret, "[REDACTED]")
    return out


_SENSITIVE: set[str] = set()


def register_secret(value: Any) -> None:
    if isinstance(value, str) and len(value.strip()) >= 8:
        _SENSITIVE.add(value.strip())


# ---------------------------------------------------------------- HTTP

class Budget:
    """一次运行的网络时间预算；预算耗尽时主动收尾，不再发新请求。"""

    def __init__(self, seconds: float = 120.0) -> None:
        self.seconds = float(seconds)
        self.started = time.monotonic()

    def remaining(self) -> float:
        return self.seconds - (time.monotonic() - self.started)

    def can_wait(self, delay: float) -> bool:
        return self.remaining() > delay + 5.0


class Http:
    """零依赖 HTTP 客户端：只重试网络错误 / 429 / 5xx，写操作默认不重试。"""

    NETWORK_DELAYS = (5.0, 15.0, 30.0)

    def __init__(self, base_url: str, headers: dict[str, str] | None = None,
                 *, timeout: float = 20.0, budget: float = 120.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {k: str(v) for k, v in (headers or {}).items()}
        self.timeout = timeout
        self.budget = Budget(budget)

    def _raw(self, url: str, method: str, body: Any, headers: dict[str, str]):
        data = None
        hdrs = dict(headers)
        if isinstance(body, (bytes, bytearray)):
            data = bytes(body)  # Qoder claim 等接口要求 POST 空体
        elif body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read(1 << 20)
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read(1 << 20)
            except OSError:
                return exc.code, b""
        except (urllib.error.URLError, OSError) as exc:
            return 0, str(exc).encode("utf-8")

    def request(self, path: str, method: str = "GET", body: Any = None, *,
                headers: dict[str, str] | None = None, retry: bool = True,
                query: str = "") -> tuple[int, Any, str | None]:
        """返回 ``(http_code, json_or_text, err)``；``code=0`` 表示网络不可达。"""
        url = path if path.startswith("http") else self.base_url + path
        if query:
            url += ("&" if "?" in url else "?") + query
        hdrs = {**self.headers, **(headers or {})}
        attempt = 0
        while True:
            code, raw = self._raw(url, method, body, hdrs)
            text = raw.decode("utf-8", "replace")
            if code == 0:
                err = redact(short(text, 300))
            else:
                err = None
            try:
                payload: Any = json.loads(text)
            except ValueError:
                payload = text if code else None
            retryable = code == 0 or code == 429 or 500 <= code < 600
            if not (retry and retryable and attempt < len(self.NETWORK_DELAYS)):
                return code, payload, err
            delay = self.NETWORK_DELAYS[attempt]
            if not self.budget.can_wait(delay):
                return code, payload, err
            time.sleep(delay)
            attempt += 1


def transport_error(app: str, account: str, code: int, payload: Any,
                    err: str | None) -> Result | None:
    """传输层统一映射：断网 / 预算 / 401 / 403（业务码由各平台自己处理）。"""
    if code == 0:
        return make(app, account, "NETWORK", "网络不可达：%s" % (err or "unknown"))
    if code == 401:
        return make(app, account, "AUTH_REJECTED",
                    "登录态被拒绝（HTTP 401），请重新登录客户端并更新 Secret")
    if code == 403:
        return make(app, account, "FORBIDDEN", "被服务端拒绝（HTTP 403），请确认账号资格")
    if code == 429:
        return make(app, account, "RATE_LIMITED", "请求过于频繁（HTTP 429），等下一轮调度补跑")
    if code >= 500:
        return make(app, account, "NETWORK", "服务端错误 HTTP %s：%s" % (code, short(payload)))
    return None


# ---------------------------------------------------------------- 凭据配置

def _as_list(value: Any) -> list[dict]:
    if isinstance(value, dict):
        return [dict(value)]
    if isinstance(value, list):
        return [dict(x) for x in value if isinstance(x, dict)]
    return []


def load_config() -> dict[str, list[dict]]:
    """从 Secrets 读凭据。优先级：SIGNIN_ACCOUNTS → 平台数组 → 单值快捷变量。

    ``SIGNIN_ACCOUNTS`` 形如 ``{"qoder":[{...}], "trae":[{...}], "doubao":[{...}]}``；
    也接受数组形式（每项带 ``app`` 字段）。缺失或字段不全的账号会被过滤掉，
    这样「没配的平台」自动跳过，不会让整条流水线变红。
    """
    data: dict[str, list[dict]] = {app: [] for app in APPS}
    raw = os.environ.get("SIGNIN_ACCOUNTS", "").strip()
    if raw:
        try:
            obj = json.loads(raw)
        except ValueError as exc:
            raise ValueError("SIGNIN_ACCOUNTS 不是合法 JSON：%s" % exc) from exc
        if isinstance(obj, dict):
            for app in APPS:
                data[app] = _as_list(obj.get(app))
        elif isinstance(obj, list):
            for item in obj:
                if not isinstance(item, dict):
                    continue
                app = str(item.pop("app", "")).strip().lower()
                if app in APPS:
                    data[app].append(item)
    for app, env in ARRAY_ENV.items():
        if data[app]:
            continue
        value = os.environ.get(env, "").strip()
        if value:
            try:
                data[app] = _as_list(json.loads(value))
            except ValueError as exc:
                raise ValueError("%s 不是合法 JSON：%s" % (env, exc)) from exc
    for app, (env, field_name) in SINGLE_ENV.items():
        if data[app]:
            continue
        value = os.environ.get(env, "").strip()
        if value:
            acc = {field_name: value}
            for extra_env, extra_field in SINGLE_EXTRA.get(app, {}).items():
                extra = os.environ.get(extra_env, "").strip()
                if extra:
                    acc[extra_field] = extra
            data[app] = [acc]

    for app in APPS:
        need = CREDENTIAL_FIELD[app]
        kept = []
        for acc in data[app]:
            value = str(acc.get(need, "")).strip()
            if not value:
                continue
            acc[need] = value
            register_secret(value)
            for key in ("machine_token", "machine_code", "machine_type", "machine_id",
                        "device_id", "cookie"):
                if acc.get(key):
                    register_secret(str(acc[key]))
            kept.append(acc)
        data[app] = kept
    return data


def account_name(acc: dict, index: int, app: str) -> str:
    return str(acc.get("name") or ("%s-%d" % (app, index + 1))).strip()


def enabled_apps() -> list[str]:
    """``SIGNIN_APPS`` 控制启用哪些平台，缺省全部（含 workbuddy）。"""
    raw = os.environ.get("SIGNIN_APPS", "").strip()
    allowed = ("workbuddy",) + APPS
    if not raw:
        return list(allowed)
    picked = [x.strip().lower() for x in raw.replace("|", ",").split(",") if x.strip()]
    return [x for x in picked if x in allowed]


def workbuddy_ready() -> bool:
    """WorkBuddy 是否有可用凭据（Secret 或仓库里续期后的 JSON）。"""
    if os.environ.get("WORKBUDDY_REFRESH_TOKEN", "").strip():
        return True
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "wb_refresh_tokens.json")
    try:
        return bool(json.load(open(path, encoding="utf-8")))
    except Exception:
        return False


# ---------------------------------------------------------------- 汇报

def render(results: list[Result]) -> str:
    """控制台 / 推送用的纯文本报告。"""
    lines = ["═══ 每日签到融合报告  %s ═══" % time.strftime("%Y-%m-%d %H:%M:%S")]
    for r in results:
        lines.append(r.line())
    ok = sum(1 for r in results if not r.needs_attention)
    bad = [r for r in results if r.needs_attention]
    lines.append("──────────────────────────────")
    lines.append("共 %d 项，正常 %d，需关注 %d" % (len(results), ok, len(bad)))
    if bad:
        lines.append("需关注：" + "、".join("%s/%s(%s)" % (r.app, r.account, r.status) for r in bad))
        lines.append("提示：AUTH_REJECTED / NO_AUTH 通常是客户端登录态过期，需重新导出 Secret。")
    return "\n".join(lines)


def write_step_summary(results: list[Result]) -> None:
    """写 GitHub Actions Job Summary；本地运行时静默跳过。"""
    path = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if not path:
        return
    lines = ["## 每日签到融合报告", "",
             "| 平台 | 账号 | 状态 | 收获 | 说明 |", "| --- | --- | --- | --- | --- |"]
    for r in results:
        icon = "✅" if not r.needs_attention else "⚠️"
        amount = "" if r.credits in (None, "") else str(r.credits)
        report = redact(r.report).replace("|", "\\|")
        lines.append("| %s | %s | %s %s | %s | %s |" % (
            APP_LABEL.get(r.app, r.app), r.account, icon, r.status, amount, report))
    bad = [r for r in results if r.needs_attention]
    lines += ["", "正常 %d / 共 %d 项。" % (len(results) - len(bad), len(results))]
    if bad:
        lines += ["", "> ⚠️ 需关注：%s" % "、".join(
            "%s/%s(%s)" % (r.app, r.account, r.status) for r in bad),
            "> 登录态类失败请在电脑上重新登录后更新 `SIGNIN_ACCOUNTS`。"]
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as exc:
        print("Step Summary 写入失败：%s" % exc, file=sys.stderr)


def pushplus(title: str, content: str) -> bool:
    """PushPlus 微信推送；与 WorkBuddy 主程序的通知口径一致，未配置则跳过。"""
    token = os.environ.get("PUSHPLUS_TOKEN", "").strip()
    if not token:
        return False
    payload = json.dumps({"token": token, "title": title,
                          "content": redact(content)[:18000], "template": "txt"},
                         ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request("https://www.pushplus.plus/send", data=payload,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        ok = data.get("code") == 200
        print("📢 推送%s" % ("成功" if ok else "失败：%s" % short(data.get("msg"))))
        return ok
    except Exception as exc:
        print("📢 推送异常：%s" % short(exc), file=sys.stderr)
        return False
