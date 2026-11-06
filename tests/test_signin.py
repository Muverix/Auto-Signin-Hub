#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""融合签到的离线契约测试：不发真实网络请求，全部用 mock 响应验证。

覆盖三个平台的关键行为：幂等分流、业务码映射、设备风控头、
限流退避、领后复查、任务奖励清扫、凭据脱敏与配置加载。

运行：``python -m unittest discover -s tests -v``
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from signin import common, doubao, qoder, trae  # noqa: E402


def patch_requests(mapping):
    """把 Http.request 换成按路径查表的假响应。

    mapping: {path: (http_code, body)}；值也可以是列表表示连续多次调用的返回。
    """
    queues = {k: (list(v) if isinstance(v, list) else [v]) for k, v in mapping.items()}
    calls = []

    def fake(self, path, method="GET", body=None, *, headers=None, retry=True, query=""):
        calls.append((path, method, body, headers, retry, query))
        queue = queues.get(path)
        if not queue:
            raise AssertionError("未预期的请求：%s %s" % (method, path))
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        code, payload = item
        return code, payload, None if code else "network down"

    return mock.patch.object(common.Http, "request", fake), calls


class CommonTest(unittest.TestCase):
    def test_dig_and_short(self):
        self.assertEqual(common.dig({"a": {"b": [1, 2]}}, "a.b.1"), 2)
        self.assertIsNone(common.dig({}, "a.b"))
        self.assertEqual(common.short("a  b\n c"), "a b c")

    def test_result_status_attention(self):
        self.assertFalse(common.make("qoder", "x", "ALREADY", "已领").needs_attention)
        self.assertTrue(common.make("qoder", "x", "NO_AUTH", "过期").needs_attention)
        self.assertTrue(common.make("qoder", "x", "PENDING", "待领").needs_attention)

    def test_redact_registered_secret(self):
        common.register_secret("SUPER_SECRET_TOKEN_VALUE")
        self.assertNotIn("SUPER_SECRET_TOKEN_VALUE", common.redact("token=SUPER_SECRET_TOKEN_VALUE"))
        self.assertIn("[REDACTED]", common.redact("token=SUPER_SECRET_TOKEN_VALUE"))

    def test_load_config_single_and_array(self):
        env = {"QODER_TOKEN": "qoder-token-abcdef", "TRAE_ACCOUNTS":
               '[{"name":"t1","token":"trae-token-abcdef","device_id":"1234567890123456"}]',
               "SIGNIN_APPS": "qoder,trae"}
        with mock.patch.dict(os.environ, env, clear=True):
            cfg = common.load_config()
            self.assertEqual(len(cfg["qoder"]), 1)
            self.assertEqual(cfg["qoder"][0]["token"], "qoder-token-abcdef")
            self.assertEqual(cfg["trae"][0]["name"], "t1")
            self.assertEqual(cfg["doubao"], [])
            self.assertEqual(common.enabled_apps(), ["qoder", "trae"])

    def test_load_config_filters_incomplete(self):
        with mock.patch.dict(os.environ,
                            {"SIGNIN_ACCOUNTS": '{"qoder":[{"name":"no-token"},'
                                               '{"token":"qoder-token-abcdef"}]}'}, clear=True):
            cfg = common.load_config()
            self.assertEqual(len(cfg["qoder"]), 1)

    def test_single_env_picks_up_trae_device_id(self):
        env = {"TRAE_TOKEN": "trae-token-abcdef",
               "TRAE_DEVICE_ID": "aha-5e09036c73b51abdf755a4ab60bb9ac2",
               "TRAE_APP_VERSION": "3.4.15"}
        with mock.patch.dict(os.environ, env, clear=True):
            acc = common.load_config()["trae"][0]
        self.assertEqual(acc["device_id"], "aha-5e09036c73b51abdf755a4ab60bb9ac2")
        self.assertEqual(acc["app_version"], "3.4.15")
        self.assertIsNone(trae.device_id_issue(acc))

    def test_single_env_without_device_id_is_flagged(self):
        with mock.patch.dict(os.environ, {"TRAE_TOKEN": "trae-token-abcdef"}, clear=True):
            acc = common.load_config()["trae"][0]
        self.assertIn("未配置", trae.device_id_issue(acc))

    def test_two_qoder_editions_in_one_secret(self):
        raw = json.dumps({"qoder": [
            {"name": "Qoder CN", "token": "cn-token-abcdef",
             "base_url": "https://openapi.qoder.com.cn"},
            {"name": "Qoder 国际版", "token": "intl-token-abcdef",
             "base_url": "https://openapi.qoder.sh"}]})
        with mock.patch.dict(os.environ, {"SIGNIN_ACCOUNTS": raw}, clear=True):
            accs = common.load_config()["qoder"]
        self.assertEqual(len(accs), 2)
        self.assertEqual({a["name"] for a in accs}, {"Qoder CN", "Qoder 国际版"})
        self.assertEqual({a["base_url"] for a in accs},
                         {"https://openapi.qoder.com.cn", "https://openapi.qoder.sh"})


class QoderTest(unittest.TestCase):
    ACC = {"name": "主号", "token": "qoder-token-abcdef", "machine_token": "mt",
           "machine_code": "mc", "machine_type": "mty"}

    def test_headers_include_risk_and_client_type(self):
        h = qoder.build_headers(self.ACC)
        self.assertEqual(h["Cosy-ClientType"], "10")
        self.assertEqual(h["Authorization"], "Bearer qoder-token-abcdef")
        self.assertEqual(h["Cosy-MachineToken"], "mt")

    def test_select_campaigns_window_and_status(self):
        now = 1000.0
        payload = {"campaigns": [
            {"campaignKey": "daily", "actionType": "CLAIM_BENEFIT",
             "claimStatus": "CLAIMABLE", "startAt": 900, "endAt": 2000},
            {"campaignKey": "old", "actionType": "CLAIM_BENEFIT",
             "claimStatus": "CLAIMABLE", "startAt": 100, "endAt": 200},
            {"campaignKey": "claimed", "actionType": "CLAIM_BENEFIT",
             "claimStatus": "CLAIMED", "startAt": 900, "endAt": 2000},
            {"campaignKey": "other", "actionType": "OTHER", "claimStatus": "CLAIMABLE"},
        ]}
        picked = qoder.select_campaigns(payload, now)
        self.assertEqual([c["campaignKey"] for c in picked["todo"]], ["daily"])
        self.assertEqual([c["campaignKey"] for c in picked["claimed"]], ["claimed"])
        self.assertEqual(len(picked["all"]), 3)

    def test_millisecond_timestamps(self):
        now = 1_700_000_000.0
        c = {"startAt": 1_700_000_000_000, "endAt": 1_700_086_400_000}
        self.assertTrue(qoder.is_active(c, now + 10))
        self.assertFalse(qoder.is_active(c, now - 10))

    def test_claim_writes_once_and_reports_claimed(self):
        listing = {"campaigns": [{"campaignKey": "act-20261102-287", "campaignId": "act-1",
                                  "actionType": "CLAIM_BENEFIT", "claimStatus": "CLAIMABLE",
                                  "benefit": {"amount": 100}}]}
        p, calls = patch_requests({
            qoder.CAMPAIGNS_PATH: (200, listing),
            "/sash/api/v1/me/campaigns/act-1/claim": (200, {"status": "CLAIMED",
                                                            "benefit": {"amount": 100}}),
        })
        with p:
            r = qoder.run(self.ACC)
        self.assertEqual(r.status, "CLAIMED")
        self.assertEqual(r.credits, 100)
        self.assertEqual(len([c for c in calls if c[1] == "POST"]), 1)
        self.assertFalse(calls[1][4])  # claim 不重试

    def test_already_does_not_post(self):
        listing = {"campaigns": [{"campaignKey": "act-1", "campaignId": "act-1",
                                  "actionType": "CLAIM_BENEFIT", "claimStatus": "CLAIMED",
                                  "benefit": {"amount": 100}}]}
        p, calls = patch_requests({qoder.CAMPAIGNS_PATH: (200, listing)})
        with p:
            r = qoder.run(self.ACC)
        self.assertEqual(r.status, "ALREADY")
        self.assertEqual(len(calls), 1)

    def test_inactive_without_risk_headers_explains_silent_filter(self):
        p, _ = patch_requests({qoder.CAMPAIGNS_PATH: (200, {"campaigns": []})})
        with p:
            r = qoder.run({"token": "qoder-token-abcdef"})
        self.assertEqual(r.status, "INACTIVE")
        self.assertIn("设备风控头", r.report)

    def test_401_maps_to_auth_rejected(self):
        p, _ = patch_requests({qoder.CAMPAIGNS_PATH: (401, {"msg": "unauthorized"})})
        with p:
            r = qoder.run(self.ACC)
        self.assertEqual(r.status, "AUTH_REJECTED")

    def test_dry_run_never_posts(self):
        listing = {"campaigns": [{"campaignKey": "act-1", "campaignId": "act-1",
                                  "actionType": "CLAIM_BENEFIT", "claimStatus": "CLAIMABLE"}]}
        p, calls = patch_requests({qoder.CAMPAIGNS_PATH: (200, listing)})
        with p:
            r = qoder.run(self.ACC, dry_run=True)
        self.assertEqual(r.status, "DRY_RUN")
        self.assertEqual(len(calls), 1)


class TraeTest(unittest.TestCase):
    ACC = {"name": "主号", "token": "trae-token-abcdef", "device_id": "1234567890123456",
           "app_version": "3.5.0"}

    def test_headers_device_id_and_ua(self):
        h = trae.build_headers(self.ACC)
        self.assertEqual(h["Authorization"], "Cloud-IDE-JWT trae-token-abcdef")
        self.assertEqual(h["x-device-id"], "1234567890123456")
        self.assertEqual(h["User-Agent"], "Trae/3.5.0")
        self.assertEqual(h["X-User-Region"], "cn")

    def test_already_checked_in(self):
        p, calls = patch_requests({trae.STATUS_PATH: (200, {"code": 0, "checked_in": True,
                                                            "credits": 100})})
        with p:
            r = trae.run(self.ACC)
        self.assertEqual(r.status, "ALREADY")
        self.assertEqual(len(calls), 1)

    def test_claim_echo_checked_in(self):
        p, calls = patch_requests({
            trae.STATUS_PATH: (200, {"code": 0, "checked_in": False}),
            trae.CLAIM_PATH: (200, {"code": 0, "checked_in": True, "credits": 100}),
        })
        with p:
            r = trae.run(self.ACC)
        self.assertEqual(r.status, "CLAIMED")
        self.assertEqual(r.credits, 100)
        self.assertEqual(len(calls), 2)

    def test_confirm_by_status(self):
        p, calls = patch_requests({
            trae.STATUS_PATH: [(200, {"code": 0, "checked_in": False}),
                               (200, {"code": 0, "checked_in": True, "credits": 100})],
            trae.CLAIM_PATH: (200, {"code": 0, "message": "accepted"}),
        })
        with p, mock.patch("signin.trae.time.sleep"):
            r = trae.run(self.ACC)
        self.assertEqual(r.status, "CLAIMED")
        self.assertEqual(r.credits, 100)

    def test_1001_is_auth_rejected(self):
        p, _ = patch_requests({trae.STATUS_PATH: (200, {"code": 1001})})
        with p:
            r = trae.run(self.ACC)
        self.assertEqual(r.status, "AUTH_REJECTED")

    def test_9004_points_to_device_id(self):
        p, _ = patch_requests({
            trae.STATUS_PATH: (200, {"code": 0, "checked_in": False}),
            trae.CLAIM_PATH: (200, {"code": 9004}),
        })
        with p:
            r = trae.run(self.ACC)
        self.assertIn("device_id", r.report)

    def test_9074_rate_limited_after_backoffs(self):
        p, _ = patch_requests({
            trae.STATUS_PATH: (200, {"code": 0, "checked_in": False}),
            trae.CLAIM_PATH: (200, {"code": 9074}),
        })
        with p, mock.patch("signin.trae.time.sleep"):
            r = trae.run(self.ACC)
        self.assertEqual(r.status, "RATE_LIMITED")

    def test_device_id_accepts_both_generations(self):
        self.assertIsNone(trae.device_id_issue({"device_id": "1234567890123456"}))
        self.assertIsNone(trae.device_id_issue(
            {"device_id": "aha-5e09036c73b51abdf755a4ab60bb9ac2"}))
        self.assertIn("未配置", trae.device_id_issue({}))
        self.assertIn("UUID", trae.device_id_issue(
            {"device_id": "123e4567-e89b-12d3-a456-426614174000"}))

    def test_uuid_device_id_blocks_claim(self):
        acc = dict(self.ACC, device_id="123e4567-e89b-12d3-a456-426614174000")
        p, calls = patch_requests({
            trae.STATUS_PATH: (200, {"code": 0, "checked_in": False}),
        })
        with p:
            r = trae.run(acc)
        self.assertEqual(r.status, "ERROR")
        self.assertIn("9074", r.report)
        self.assertEqual(len(calls), 1)  # 只发 status，不发 claim

    def test_missing_device_id_keeps_readonly_status(self):
        acc = dict(self.ACC)
        acc.pop("device_id")
        p, calls = patch_requests({
            trae.STATUS_PATH: (200, {"code": 0, "checked_in": True, "credits": 100}),
        })
        with p:
            r = trae.run(acc)
        self.assertEqual(r.status, "ALREADY")
        self.assertEqual(len(calls), 1)

    def test_dry_run_reports_device_id_issue(self):
        acc = dict(self.ACC, device_id="123e4567-e89b-12d3-a456-426614174000")
        p, _ = patch_requests({trae.STATUS_PATH: (200, {"code": 0, "checked_in": False})})
        with p:
            r = trae.run(acc, dry_run=True)
        self.assertEqual(r.status, "DRY_RUN")
        self.assertIn("9074", r.report)

    def test_unsafe_override_allows_claim(self):
        acc = dict(self.ACC, device_id="123e4567-e89b-12d3-a456-426614174000",
                   allow_unsafe_device_id=True)
        p, calls = patch_requests({
            trae.STATUS_PATH: (200, {"code": 0, "checked_in": False}),
            trae.CLAIM_PATH: (200, {"code": 0, "checked_in": True, "credits": 100}),
        })
        with p:
            r = trae.run(acc)
        self.assertEqual(r.status, "CLAIMED")
        self.assertEqual(len(calls), 2)


class DoubaoTest(unittest.TestCase):
    ACC = {"name": "主号", "cookie": "sessionid=0123456789abcdef0123456789abcdef"}

    def test_common_query_is_complete(self):
        for key in ("version_code", "aid", "real_aid", "pkg_type", "doubao_device_platform"):
            self.assertIn(key, doubao.COMMON_QUERY)

    def test_checkin_and_sweep(self):
        p, calls = patch_requests({
            doubao.CHECKIN_PATH: (200, {"code": 0, "data": {"checked_in": True,
                                                            "reward_amount": 400,
                                                            "continuous_days": 3}}),
            doubao.DETAIL_PATH: (200, {"code": 0, "data": {"tasks": [
                {"campaign_code": "task-1", "title": "体验任务", "task_status": 2,
                 "reward_summaries": [{"reward_amount": 100}]},
                {"campaign_code": "task-2", "title": "未完成任务", "task_status": 1},
            ]}}),
            doubao.CLAIM_PATH: (200, {"code": 0, "data": {}}),
        })
        with p:
            r = doubao.run(self.ACC)
        self.assertEqual(r.status, "CLAIMED")
        self.assertEqual(r.credits, 500)
        self.assertEqual(len(calls), 3)
        self.assertIn("aid=497858", calls[0][5])

    def test_idempotent_maps_to_already(self):
        p, _ = patch_requests({
            doubao.CHECKIN_PATH: (200, {"code": 0, "data": {"idempotent": True,
                                                            "reward_amount": 200,
                                                            "continuous_days": 2}}),
            doubao.DETAIL_PATH: (200, {"code": 0, "data": {"tasks": []}}),
        })
        with p:
            r = doubao.run(self.ACC)
        self.assertEqual(r.status, "ALREADY")

    def test_710012_is_no_auth(self):
        p, _ = patch_requests({doubao.CHECKIN_PATH: (200, {"code": 710012001})})
        with p:
            r = doubao.run(self.ACC)
        self.assertEqual(r.status, "NO_AUTH")

    def test_campaign_not_found_hint(self):
        p, _ = patch_requests({doubao.CHECKIN_PATH: (200, {"code": 2})})
        with p:
            r = doubao.run(self.ACC)
        self.assertIn("campaign_code", r.report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
