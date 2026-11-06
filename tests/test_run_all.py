#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""融合入口的离线端到端测试：三个平台一起跑，验证失败隔离与汇报。"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import run_all  # noqa: E402
from signin import common, doubao, qoder, trae  # noqa: E402

ACCOUNTS = {
    "qoder": [{"name": "Q主号", "token": "qoder-token-abcdef", "machine_token": "mt"}],
    "trae": [{"name": "T主号", "token": "trae-token-abcdef", "device_id": "1234567890123456"}],
    "doubao": [{"name": "D主号", "cookie": "sessionid=0123456789abcdef0123456789abcdef"}],
}


def fake_request(self, path, method="GET", body=None, *, headers=None, retry=True, query=""):
    table = {
        qoder.CAMPAIGNS_PATH: (200, {"campaigns": [{
            "campaignKey": "act-daily", "campaignId": "act-daily",
            "actionType": "CLAIM_BENEFIT", "claimStatus": "CLAIMABLE",
            "benefit": {"amount": 100}}]}),
        "/sash/api/v1/me/campaigns/act-daily/claim": (200, {"status": "CLAIMED"}),
        trae.STATUS_PATH: (200, {"code": 0, "checked_in": False}),
        trae.CLAIM_PATH: (200, {"code": 0, "checked_in": True, "credits": 100}),
        doubao.CHECKIN_PATH: (200, {"code": 0, "data": {
            "checked_in": True, "reward_amount": 200, "continuous_days": 5}}),
        doubao.DETAIL_PATH: (200, {"code": 0, "data": {"tasks": []}}),
    }
    if path not in table:
        raise AssertionError("未预期的请求：%s %s" % (method, path))
    code, payload = table[path]
    return code, payload, None


class RunAllTest(unittest.TestCase):
    def test_three_apps_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = str(Path(tmp) / "summary.md")
            env = {"SIGNIN_ACCOUNTS": json.dumps(ACCOUNTS),
                   "SIGNIN_APPS": "qoder,trae,doubao",
                   "GITHUB_STEP_SUMMARY": summary}
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(common.Http, "request", fake_request), \
                    mock.patch("builtins.print"):
                code = run_all.main([])
            self.assertEqual(code, 0)
            text = Path(summary).read_text(encoding="utf-8")
            self.assertIn("Qoder", text)
            self.assertIn("Trae CN", text)
            self.assertIn("豆包", text)
            self.assertIn("正常 3 / 共 3 项", text)
            # 凭据不能出现在报告里
            self.assertNotIn("qoder-token-abcdef", text)
            self.assertNotIn("0123456789abcdef0123456789abcdef", text)

    def test_one_app_failure_does_not_block_others(self):
        def flaky(self, path, method="GET", body=None, *, headers=None, retry=True, query=""):
            if path == qoder.CAMPAIGNS_PATH:
                return 401, {"msg": "unauthorized"}, None
            return fake_request(self, path, method, body, headers=headers,
                                retry=retry, query=query)

        with tempfile.TemporaryDirectory() as tmp:
            env = {"SIGNIN_ACCOUNTS": json.dumps(ACCOUNTS),
                   "SIGNIN_APPS": "qoder,trae,doubao",
                   "GITHUB_STEP_SUMMARY": str(Path(tmp) / "summary.md")}
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(common.Http, "request", flaky), \
                    mock.patch("builtins.print"):
                code = run_all.main([])
                strict_code = run_all.main(["--strict"])
            self.assertEqual(code, 0)
            self.assertEqual(strict_code, 1)
            text = (Path(tmp) / "summary.md").read_text(encoding="utf-8")
            self.assertIn("AUTH_REJECTED", text)
            self.assertIn("正常 2 / 共 3 项", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
