#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""🌱 每日签到融合入口：WorkBuddy 每日领取 + Qoder / Trae CN / 豆包 签到。

一次调用跑完四个平台，供 GitHub Actions 使用：::

    python run_all.py                     # 全流程（Secrets 里没配的平台自动跳过）
    python run_all.py --dry-run           # 只查状态不领取，首次配置后建议先跑一次
    python run_all.py --only qoder        # 只跑一个平台，排查用
    python run_all.py --strict            # 有需关注项时返回非 0（默认不阻断 token 持久化）

设计要点：
- **失败隔离**：一个平台 / 一个账号异常不影响其它平台；
- **幂等**：三个平台都是「先查状态，未签才领」，写操作不重试，重复运行不多领；
- **凭据只在环境变量**：Actions 上没有桌面客户端，本机 DPAPI/Keychain/CDP 链路全部移除；
- **默认退出 0**：保证 workflow 末尾的「持久化续期 Token」步骤不会因为某个平台
  失败被 ``if: success()`` 跳过；需要红灯时加 ``--strict``。
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from signin import RUNNERS, common

ROOT = Path(__file__).resolve().parent


def run_workbuddy(dry_run: bool = False) -> common.Result:
    """调度 signin/workbuddy.py（Token 续期 + 每日签到 + 成长任务 + 自动领奖）。

    workbuddy.py 是自带副作用的单文件脚本（import 会立刻读账号），所以用子进程；
    同时从子进程环境里摘掉 PUSHPLUS_TOKEN，改由本入口统一推送一次，避免重复通知。
    """
    app, name = "workbuddy", "每日领取"
    if not common.workbuddy_ready():
        return common.make(app, name, "SKIPPED",
                           "未配置 WORKBUDDY_REFRESH_TOKEN 且无续期文件，跳过")
    cmd = [sys.executable, str(ROOT / "signin" / "workbuddy.py"), "--no-desktop"]
    if dry_run:
        cmd.append("--query")
    env = os.environ.copy()
    env.pop("PUSHPLUS_TOKEN", None)
    env["WORKBUDDY_STATE_DIR"] = str(ROOT)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        proc = subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=1200)
    except subprocess.TimeoutExpired:
        return common.make(app, name, "ERROR", "workbuddy.py 运行超时（20 分钟）")
    except OSError as exc:
        return common.make(app, name, "ERROR", "workbuddy.py 启动失败：%s" % common.short(exc))

    output = (proc.stdout or "") + (proc.stderr or "")
    print(common.redact(output))
    lines = output.splitlines()
    signed = sum(1 for line in lines if "签到成功" in line)
    claimed = sum(1 for line in lines if "领奖[" in line)
    warnings = sum(1 for line in lines if "⚠️" in line or "失败" in line)
    report = "账号 %s｜签到成功 %d｜领奖 %d｜告警 %d" % (
        next((line.split(":")[-1].strip() for line in lines if "账号数:" in line), "?"),
        signed, claimed, warnings)
    if proc.returncode != 0:
        return common.make(app, name, "ERROR",
                           "%s；workbuddy.py 退出码 %s，末尾日志：%s" % (
                               report, proc.returncode, common.short(" / ".join(lines[-5:]), 160)))
    return common.make(app, name, "CLAIMED", report,
                       detail={"signed": signed, "claimed": claimed, "warnings": warnings})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="每日签到融合入口")
    parser.add_argument("--dry-run", action="store_true", help="只查状态/空跑，不发起领取")
    parser.add_argument("--strict", action="store_true", help="有需关注项时返回非 0")
    parser.add_argument("--only", default="", help="只跑指定平台，逗号分隔")
    parser.add_argument("--apps", default="", help="覆盖 SIGNIN_APPS，逗号分隔")
    args = parser.parse_args(argv)

    if args.apps:
        os.environ["SIGNIN_APPS"] = args.apps
    apps = common.enabled_apps()
    if args.only:
        only = {x.strip().lower() for x in args.only.replace("|", ",").split(",") if x.strip()}
        apps = [a for a in apps if a in only]

    try:
        config = common.load_config()
    except ValueError as exc:
        print("❌ 凭据配置错误：%s" % exc, file=sys.stderr)
        return 1

    results: list[common.Result] = []
    print("═" * 60)
    print("🌱 每日签到融合  %s  模式=%s  平台=%s" % (
        time.strftime("%Y-%m-%d %H:%M:%S"), "dry-run" if args.dry_run else "正式",
        ",".join(apps) or "无"))
    print("═" * 60)

    if "workbuddy" in apps:
        print("\n── WorkBuddy 每日领取 ──")
        try:
            results.append(run_workbuddy(dry_run=args.dry_run))
        except Exception as exc:
            results.append(common.make("workbuddy", "每日领取", "ERROR",
                                       "未捕获异常：%s" % common.short(exc)))

    for app in common.APPS:
        if app not in apps:
            continue
        accounts = config.get(app, [])
        if not accounts:
            results.append(common.make(app, "-", "SKIPPED",
                                       "未配置凭据（SIGNIN_ACCOUNTS.%s），跳过" % app))
            continue
        print("\n── %s（%d 个账号）──" % (common.APP_LABEL[app], len(accounts)))
        runner = RUNNERS[app]
        for index, acc in enumerate(accounts):
            name = common.account_name(acc, index, app)
            try:
                result = runner(acc, dry_run=args.dry_run)
            except Exception as exc:
                result = common.make(app, name, "ERROR", "未捕获异常：%s" % common.short(exc))
            result.account = name
            results.append(result)
            print("   " + result.line())

    text = common.render(results)
    print("\n" + text)
    common.write_step_summary(results)
    common.pushplus("🌱 每日签到融合报告", text)

    if args.strict and any(r.needs_attention for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
