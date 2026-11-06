#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""三个客户端平台的纯云端签到逻辑（凭据只从环境变量读）。

- ``common``：HTTP / 结果 / Secrets / 汇报（零第三方依赖）
- ``qoder``  ：Qoder CN / 国际版 campaigns 领取
- ``trae``   ：Trae CN status → claim → 复查
- ``doubao`` ：豆包签到 + 任务奖励清扫

``workbuddy.py`` 是 WorkBuddy 的单文件主程序（RT 自动续期、成长任务、每日领奖），
import 有副作用，因此不在此导入，由 ``run_all.py`` 用子进程调度。
"""
from . import common, doubao, qoder, trae

RUNNERS = {"qoder": qoder.run, "trae": trae.run, "doubao": doubao.run}
__all__ = ["common", "qoder", "trae", "doubao", "RUNNERS"]
