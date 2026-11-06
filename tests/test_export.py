#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本机凭据导出工具的离线测试：用构造的假加密文件验证解密链路。

不读取任何真实客户端数据；只在临时目录里造文件。需要 ``cryptography``，
缺失时整组跳过（它只是本机工具的可选依赖，不进 GitHub Actions）。
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location("wb_export", str(ROOT / "tools" / "export_secrets.py"))
export = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(export)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# 任何调用 main() 的用例都不得把假凭据写进工作区里的真实镜像文件。
_TMP_STATE = tempfile.TemporaryDirectory(prefix="wb-state-")
_ORIG_STATE_PATH = export.STATE_PATH


def setUpModule():
    export.STATE_PATH = Path(_TMP_STATE.name) / "accounts.local.json"


def tearDownModule():
    export.STATE_PATH = _ORIG_STATE_PATH
    _TMP_STATE.cleanup()


@unittest.skipUnless(HAS_CRYPTO, "需要本机 cryptography")
class TraeExportTest(unittest.TestCase):
    def test_ss_aes_envelope(self):
        master = os.urandom(32)
        salt = bytes(export._GLE[i] ^ export._ZLE[i] for i in range(64))
        digest = hashlib.sha512(hashlib.sha512(master).digest() + salt).digest()
        key, iv = digest[:16], digest[16:32]
        body = json.dumps({"token": "jwt-for-test", "expiredAt": "2027-01-01"}).encode()
        plain = hashlib.sha512(body).digest() + body
        pad = 16 - len(plain) % 16
        plain += bytes([pad]) * pad
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        raw = bytes([116, 99, 5, 16, 0, 0]) + master + (enc.update(plain) + enc.finalize())
        data = {
            "iCubeAuthInfo://icube.cloudide": base64.b64encode(raw).decode(),
            "iCubeAuthInfo://icube-dc:1234567890123456": {},
            "iCubeLastVersion": "3.5.0",
        }
        with tempfile.TemporaryDirectory() as tmp:
            storage = Path(tmp) / "Trae CN" / "User" / "globalStorage" / "storage.json"
            storage.parent.mkdir(parents=True)
            storage.write_text(json.dumps(data), encoding="utf-8")
            with mock.patch.dict(os.environ, {"APPDATA": tmp}):
                acct = export.export_trae()
        self.assertEqual(acct["token"], "jwt-for-test")
        self.assertEqual(acct["device_id"], "1234567890123456")
        self.assertEqual(acct["app_version"], "3.5.0")


@unittest.skipUnless(HAS_CRYPTO, "需要本机 cryptography")
class DoubaoExportTest(unittest.TestCase):
    def test_chromium_v10_cookie(self):
        key = os.urandom(32)
        aes = AESGCM(key)

        def encrypt(value: str) -> bytes:
            nonce = os.urandom(12)
            plain = b"X" * 32 + value.encode()  # 32 字节应用层前缀
            return b"v10" + nonce + aes.encrypt(nonce, plain, None)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Local State").write_text(json.dumps({"os_crypt": {
                "encrypted_key": base64.b64encode(b"DPAPI" + b"wrapped").decode()}}),
                encoding="utf-8")
            dbdir = root / "Default" / "Network"
            dbdir.mkdir(parents=True)
            conn = sqlite3.connect(str(dbdir / "Cookies"))
            conn.execute("create table cookies (host_key text, name text, encrypted_value blob)")
            for name, value in (("sessionid", "0123456789abcdef0123456789abcdef"),
                                ("sid_tt", "sid-value"), ("uid_tt", "uid-value")):
                conn.execute("insert into cookies values (?, ?, ?)",
                             (".doubao.com", name, encrypt(value)))
            conn.commit()
            conn.close()
            with mock.patch.dict(os.environ, {"DOUBAO_USER_DATA_DIR": str(root)}), \
                    mock.patch.object(export, "_dpapi_unprotect", return_value=key):
                acct = export.export_doubao()
        self.assertIn("sessionid=0123456789abcdef0123456789abcdef", acct["cookie"])
        self.assertIn("sid_tt=sid-value", acct["cookie"])
        self.assertEqual(acct["campaign_code"], "pc_incentive_task_mvp_v3")


@unittest.skipUnless(HAS_CRYPTO, "需要本机 cryptography")
class QoderSessionTest(unittest.TestCase):
    """Qoder 登录态解密已内联进导出脚本，不再依赖 tools/vendor/。"""

    def _auth_dir(self, root, token, name="com.qodercn.app.stable"):
        key, nonce = os.urandom(32), os.urandom(12)
        auth_dir = root / name
        auth_dir.mkdir()
        (auth_dir / "auth.v1.dat").write_bytes(
            b"v10" + nonce + AESGCM(key).encrypt(
                nonce, json.dumps({"token": token}).encode(), None))
        (auth_dir / "Local State").write_text(json.dumps({"os_crypt": {
            "encrypted_key": base64.b64encode(b"DPAPI" + b"wrapped").decode()}}),
            encoding="utf-8")
        return auth_dir, key

    def test_no_vendor_directory_or_module_is_used(self):
        self.assertFalse(hasattr(export, "QODER_VENDOR"))
        self.assertFalse((ROOT / "tools" / "vendor").exists())
        for name in ("_qoder_session", "_qoder_decrypt_gcm", "_qoder_umid_identity",
                     "_qoder_machine_id", "_qoder_risk_headers"):
            self.assertTrue(callable(getattr(export, name, None)), name)

    def test_session_is_decrypted_in_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_dir, key = self._auth_dir(Path(tmp), "qoder-token-for-test")
            with mock.patch.object(export, "_os_crypt_key", return_value=key):
                self.assertEqual(export._qoder_session(auth_dir)["token"],
                                 "qoder-token-for-test")

    def test_export_qoder_uses_inlined_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, key = self._auth_dir(root, "qoder-token-for-test")
            with mock.patch.dict(os.environ, {"APPDATA": str(root)}), \
                    mock.patch.object(export.sys, "platform", "win32"), \
                    mock.patch.object(export, "_os_crypt_key", return_value=key), \
                    mock.patch.object(export, "_qoder_umid_exe", return_value=None), \
                    mock.patch.object(export, "_qoder_risk_headers", return_value={}), \
                    mock.patch("sys.stderr", io.StringIO()):
                acct = export.export_qoder()
        self.assertEqual(acct["token"], "qoder-token-for-test")
        self.assertEqual(acct["base_url"], "https://openapi.qoder.com.cn")

    def test_risk_headers_map_umid_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            umid = root.joinpath("resources", "umid", "runtime-info.exe")
            umid.parent.mkdir(parents=True)
            umid.write_bytes(b"")
            (root / "resources" / "build-manifest.json").write_text(
                json.dumps({"productVersion": "1.2.3"}), encoding="utf-8")
            (root / "auth.machine-id").write_text("mid-123", encoding="utf-8")
            identity = {"machineToken": "mt", "machineCode": "mc",
                        "machineType": "mtype"}
            with mock.patch.object(export, "_qoder_umid_identity",
                                   return_value=identity), \
                    mock.patch.object(export.sys, "platform", "win32"), \
                    mock.patch.dict(os.environ, {"APPDATA": str(root)}):
                headers = export._qoder_risk_headers(root, umid, "com.qodercn.app*")
        self.assertEqual(headers["Cosy-MachineToken"], "mt")
        self.assertEqual(headers["Cosy-MachineCode"], "mc")
        self.assertEqual(headers["Cosy-MachineType"], "mtype")
        self.assertEqual(headers["Cosy-MachineId"], "mid-123")
        self.assertEqual(headers["Cosy-Version"], "1.2.3")
        self.assertTrue(headers["Cosy-MachineOS"].endswith("_windows"))


class TraeDeviceIdTest(unittest.TestCase):
    """设备号形态解析（不需要 cryptography）。"""

    AHA = "aha-5e09036c73b51abdf755a4ab60bb9ac2"

    def test_legacy_numeric_form(self):
        data = {"iCubeAuthInfo://icube-dc:1234567890123456": {}}
        self.assertEqual(export.aha_device_id(data)[0], "1234567890123456")

    def test_new_aha_hex_form(self):
        data = {"iCubeAuthInfo://icube-dc:" + self.AHA: {}}
        self.assertEqual(export.aha_device_id(data)[0], self.AHA)

    def test_new_form_wins_when_both_generations_exist(self):
        data = {"iCubeAuthInfo://icube-dc:1234567890123456": {},
                "iCubeAuthInfo://icube-dc:" + self.AHA: {}}
        self.assertEqual(export.aha_device_id(data)[0], self.AHA)

    def test_no_icube_dc_key(self):
        self.assertEqual(export.aha_device_id({"telemetry.devDeviceId": "x"})[0], "")

    def test_read_runtime_id_from_client_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "Trae CN" / "logs" / "20261106T000000"
            logs.mkdir(parents=True)
            (logs / "main.log").write_text(
                "[ICDRS] (init) did: 0, ldid: %s, rdid: 0\n"
                "[ICubeDeviceRegisterService] (init) resolve device_id: %s\n"
                % (self.AHA, self.AHA), encoding="utf-8")
            self.assertEqual(export.aha_device_id_from_logs(logs.parent), self.AHA)


@unittest.skipUnless(HAS_CRYPTO, "需要本机 cryptography")
class TraeUuidFallbackTest(unittest.TestCase):
    """端到端：找不到真实设备号时不得退化成 UUID（会触发 9074）。"""

    AHA = "aha-5e09036c73b51abdf755a4ab60bb9ac2"

    def _write_storage(self, tmp: str, extra: dict) -> None:
        master = os.urandom(32)
        salt = bytes(export._GLE[i] ^ export._ZLE[i] for i in range(64))
        digest = hashlib.sha512(hashlib.sha512(master).digest() + salt).digest()
        key, iv = digest[:16], digest[16:32]
        body = json.dumps({"token": "jwt-for-test"}).encode()
        plain = hashlib.sha512(body).digest() + body
        pad = 16 - len(plain) % 16
        plain += bytes([pad]) * pad
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        raw = bytes([116, 99, 5, 16, 0, 0]) + master + (enc.update(plain) + enc.finalize())
        data = dict(extra)
        data["iCubeAuthInfo://icube.cloudide"] = base64.b64encode(raw).decode()
        storage = Path(tmp) / "Trae CN" / "User" / "globalStorage" / "storage.json"
        storage.parent.mkdir(parents=True, exist_ok=True)
        storage.write_text(json.dumps(data), encoding="utf-8")

    def _export(self, extra: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            self._write_storage(tmp, extra)
            with mock.patch.dict(os.environ, {"APPDATA": tmp}):
                return export.export_trae()

    def test_new_aha_form_is_exported(self):
        acct = self._export({"iCubeAuthInfo://icube-dc:" + self.AHA: {}})
        self.assertEqual(acct["device_id"], self.AHA)

    def test_uuid_is_not_silently_used_as_fallback(self):
        acct = self._export({"telemetry.devDeviceId":
                             "123e4567-e89b-12d3-a456-426614174000"})
        self.assertEqual(acct["token"], "jwt-for-test")
        self.assertEqual(acct["device_id"], "")


class SecretFormatTest(unittest.TestCase):
    """导出结果 → GitHub Secret 可粘贴内容的格式转换。"""

    AHA = "aha-5e09036c73b51abdf755a4ab60bb9ac2"
    OUT = {
        "qoder": [{"name": "主号", "token": "qoder-token",
                   "base_url": "https://openapi.qoder.com.cn"}],
        "trae": [{"name": "主号", "token": "trae-token",
                  "device_id": AHA, "app_version": "3.4.15"}],
        "doubao": [{"name": "主号", "cookie": "sessionid=abc",
                    "campaign_code": "pc_incentive_task_mvp_v3"}],
    }

    def test_single_is_one_valid_json_secret(self):
        text, names = export.format_secrets(self.OUT, "single")
        self.assertEqual(names, "SIGNIN_ACCOUNTS")
        parsed = json.loads(text)
        self.assertEqual(set(parsed), {"qoder", "trae", "doubao"})
        self.assertIsInstance(parsed["trae"], list)
        self.assertEqual(parsed["trae"][0]["device_id"], self.AHA)

    def test_single_omits_unexported_platforms(self):
        text, _ = export.format_secrets({"trae": self.OUT["trae"]}, "single")
        self.assertEqual(set(json.loads(text)), {"trae"})

    def test_split_blocks_are_each_json_arrays(self):
        text, names = export.format_secrets(self.OUT, "split")
        self.assertIn("TRAE_ACCOUNTS", names)
        self.assertNotIn("#", text)
        for block in text.split("\n\n"):
            head, _, body = block.partition("\n")
            self.assertIn(head, set(export.SPLIT_SECRET_NAME.values()))
            self.assertIsInstance(json.loads(body), list)

    def test_env_includes_device_id_and_has_no_comments(self):
        text, _ = export.format_secrets(self.OUT, "env")
        self.assertIn("TRAE_TOKEN=trae-token", text)
        self.assertIn("TRAE_DEVICE_ID=" + self.AHA, text)
        self.assertNotIn("#", text)

    def test_choose_platforms_multi_select(self):
        with mock.patch("builtins.input", return_value="2,4"):
            self.assertEqual(export.choose_platforms(), ["qoder", "trae"])

    def test_choose_platforms_by_name_and_all(self):
        with mock.patch("builtins.input", return_value="workbuddy,qoder-intl"):
            self.assertEqual(export.choose_platforms(), ["workbuddy", "qoder_intl"])
        with mock.patch("builtins.input", return_value=""):
            self.assertEqual(export.choose_platforms(), list(export.SOURCES))

    def test_choose_platforms_cancel(self):
        with mock.patch("builtins.input", return_value="0"):
            self.assertEqual(export.choose_platforms(), [])

    def test_single_format_with_workbuddy_is_two_blocks(self):
        text, names = export.format_secrets(
            {"qoder": [{"token": "t"}]}, "single",
            {"WORKBUDDY_REFRESH_TOKEN": "13800138000:AT:RT"})
        self.assertIn("SIGNIN_ACCOUNTS", names)
        self.assertIn("WORKBUDDY_REFRESH_TOKEN", names)
        blocks = text.split("\n\n")
        self.assertEqual(len(blocks), 2)
        self.assertEqual(json.loads(blocks[0].split("\n", 1)[1]), {"qoder": [{"token": "t"}]})
        self.assertEqual(blocks[1].split("\n", 1)[1], "13800138000:AT:RT")

    def test_split_and_env_include_workbuddy(self):
        plain = {"WORKBUDDY_REFRESH_TOKEN": "13800138000:AT:RT"}
        split, _ = export.format_secrets({"trae": [{"token": "t"}]}, "split", plain)
        self.assertIn("\n\nWORKBUDDY_REFRESH_TOKEN\n13800138000:AT:RT", split)
        self.assertNotIn("#", split)
        env, _ = export.format_secrets({"trae": [{"token": "t"}]}, "env", plain)
        self.assertIn("WORKBUDDY_REFRESH_TOKEN=13800138000:AT:RT", env)

    def test_choose_format(self):
        with mock.patch("builtins.input", return_value="2"):
            self.assertEqual(export.choose_format(), "split")

    def test_clipboard_keeps_utf8_via_base64(self):
        done = mock.Mock(returncode=0)
        text = "含中文的 Secret 内容"
        with mock.patch.object(export.sys, "platform", "win32"), \
                mock.patch.object(export.subprocess, "run", return_value=done) as run:
            ok, how = export.copy_to_clipboard(text)
        self.assertTrue(ok)
        self.assertIn("Set-Clipboard", how)
        script = run.call_args[0][0][-1]
        payload = re.search(r"FromBase64String\('([^']+)'\)", script).group(1)
        self.assertEqual(base64.b64decode(payload).decode("utf-8"), text)


class MainFlowTest(unittest.TestCase):
    """入口：非交互导出 → 格式转换 → 剪贴板。"""

    def test_default_writes_only_clipboard_and_prints_nothing(self):
        fake = {"name": "主号", "token": "fake-token"}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(export.EXPORTERS, {"qoder": lambda: fake}), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch.object(export, "copy_to_clipboard",
                                  return_value=(True, "mock")) as clip:
            rc = export.main(["--only", "qoder", "--format", "single"])
        self.assertEqual(rc, 0)
        clip.assert_called_once()
        self.assertEqual(json.loads(clip.call_args[0][0])["qoder"][0]["token"], "fake-token")
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn("fake-token", err.getvalue())
        self.assertIn("SIGNIN_ACCOUNTS", err.getvalue())

    def test_no_clip_is_alias_of_print_and_skips_clipboard(self):
        fake = {"name": "主号", "token": "fake-token"}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(export.EXPORTERS, {"qoder": lambda: fake}), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch.object(export, "copy_to_clipboard") as clip:
            rc = export.main(["--only", "qoder", "--no-clip"])
        self.assertEqual(rc, 0)
        self.assertFalse(clip.called)
        self.assertIn("fake-token", out.getvalue())
        self.assertIn("--print", err.getvalue())

    def test_print_flag_is_the_only_way_to_emit_values(self):
        fake = {"name": "主号", "token": "fake-token"}
        out = io.StringIO()
        with mock.patch.dict(export.EXPORTERS, {"qoder": lambda: fake}), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", io.StringIO()), \
                mock.patch.object(export, "copy_to_clipboard") as clip:
            rc = export.main(["--only", "qoder", "--print"])
        self.assertEqual(rc, 0)
        self.assertFalse(clip.called)
        self.assertIn("fake-token", out.getvalue())

    def test_clipboard_failure_never_falls_back_to_printing(self):
        fake = {"name": "主号", "token": "fake-token"}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(export.EXPORTERS, {"qoder": lambda: fake}), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch.object(export, "copy_to_clipboard",
                                  return_value=(False, "no clipboard")):
            rc = export.main(["--only", "qoder"])
        self.assertEqual(rc, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn("fake-token", err.getvalue())
        self.assertIn("--print", err.getvalue())

    def test_user_cancel_does_not_export(self):
        with mock.patch("builtins.input", return_value="0"), \
                mock.patch.object(export.sys, "stdin", mock.Mock(isatty=lambda: True)), \
                mock.patch("sys.stderr", io.StringIO()), \
                mock.patch.object(export, "copy_to_clipboard") as clip:
            rc = export.main([])
        self.assertEqual(rc, 0)
        self.assertFalse(clip.called)


class WorkBuddyExportTest(unittest.TestCase):
    """WorkBuddy token 提取：明文直读 / 加密字段借客户端运行时解密。"""

    def _auth_file(self, root: Path, data: dict) -> None:
        path = root / export.WB_AUTH_REL
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")

    def test_plain_tokens_need_no_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._auth_file(root, {
                "auth": {"accessToken": "AT-value-123", "refreshToken": "RT-value-456"},
                "account": {"phoneNumber": "13800138000"}})
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(root)}), \
                    mock.patch.object(export, "_wb_decrypt") as dec:
                value = export.export_workbuddy()
        self.assertEqual(value, "13800138000:AT-value-123:RT-value-456")
        self.assertFalse(dec.called)

    def test_encrypted_fields_use_client_runtime(self):
        enc = {"$wbEncrypted": 1, "envelope": "dummy"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._auth_file(root, {"auth": {"accessToken": enc, "refreshToken": enc},
                                   "account": {"phoneNumber": enc}})
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(root)}), \
                    mock.patch.object(export, "_workbuddy_exe", return_value=Path("fake.exe")), \
                    mock.patch.object(export, "_wb_decrypt", return_value={
                        "accessToken": "AT-enc", "refreshToken": "RT-enc",
                        "phoneNumber": "13900139000"}) as dec:
                value = export.export_workbuddy()
        self.assertEqual(value, "13900139000:AT-enc:RT-enc")
        self.assertTrue(dec.called)

    def test_phone_falls_back_to_jwt_username(self):
        payload = base64.urlsafe_b64encode(
            json.dumps({"preferred_username": "13700137000"}).encode()).decode().rstrip("=")
        self.assertEqual(export._wb_jwt_user("hdr." + payload + ".sig"), "13700137000")

    def test_normalize_strips_json_string_wrapper(self):
        self.assertEqual(export._wb_normalize(json.dumps("AT-123")), "AT-123")
        self.assertEqual(export._wb_normalize("  AT-123  "), "AT-123")


class QoderEditionTest(unittest.TestCase):
    """CN / 国际版必须各自读自己的目录、域与 umid 组件。"""

    def test_edition_isolation_helpers_are_inlined(self):
        self.assertFalse(hasattr(export, "QODER_VENDOR"))
        self.assertFalse(hasattr(export, "_load_qoder_module"))
        for name in ("_qoder_auth_dir", "_qoder_umid_exe", "_qoder_session",
                     "_qoder_risk_headers"):
            self.assertTrue(callable(getattr(export, name, None)), name)

    def test_edition_config_is_disjoint(self):
        cn = export.QODER_EDITIONS["qoder"]
        intl = export.QODER_EDITIONS["qoder_intl"]
        self.assertNotEqual(cn["dir_glob"], intl["dir_glob"])
        self.assertNotEqual(cn["base_url"], intl["base_url"])
        import fnmatch
        self.assertTrue(fnmatch.fnmatch("com.qoder.app.stable", intl["dir_glob"]))
        self.assertFalse(fnmatch.fnmatch("com.qodercn.app.stable", intl["dir_glob"]))
        self.assertTrue(fnmatch.fnmatch("com.qodercn.app.stable", cn["dir_glob"]))
        self.assertFalse(fnmatch.fnmatch("com.qoder.app.stable", cn["dir_glob"]))

    def test_auth_dir_picker_uses_edition_glob(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("com.qodercn.app.stable", "com.qoder.app.stable"):
                d = root / name
                d.mkdir()
                (d / "auth.v1.dat").write_bytes(b"v10")
            with mock.patch.dict(os.environ, {"APPDATA": str(root)}):
                self.assertEqual(export._qoder_auth_dir(
                    export.QODER_EDITIONS["qoder"]["dir_glob"]).name,
                    "com.qodercn.app.stable")
                self.assertEqual(export._qoder_auth_dir(
                    export.QODER_EDITIONS["qoder_intl"]["dir_glob"]).name,
                    "com.qoder.app.stable")

    @unittest.skipUnless(HAS_CRYPTO, "需要本机 cryptography")
    def test_selected_edition_reads_only_its_own_login_state(self):
        key = os.urandom(32)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, token in (("com.qodercn.app.stable", "cn-token"),
                                ("com.qoder.app.stable", "intl-token")):
                d = root / name
                d.mkdir()
                nonce = os.urandom(12)
                (d / "auth.v1.dat").write_bytes(
                    b"v10" + nonce + AESGCM(key).encrypt(
                        nonce, json.dumps({"token": token}).encode(), None))
                (d / "Local State").write_text(json.dumps({"os_crypt": {
                    "encrypted_key": base64.b64encode(b"DPAPI" + b"x").decode()}}),
                    encoding="utf-8")
            with mock.patch.dict(os.environ, {"APPDATA": str(root)}), \
                    mock.patch.object(export.sys, "platform", "win32"), \
                    mock.patch.object(export, "_os_crypt_key", return_value=key), \
                    mock.patch.object(export, "_qoder_umid_exe", return_value=None), \
                    mock.patch.object(export, "_qoder_risk_headers", return_value={}), \
                    mock.patch("sys.stderr", io.StringIO()):
                intl = export.export_qoder("qoder_intl")
                cn = export.export_qoder("qoder")
        self.assertEqual(intl["base_url"], "https://openapi.qoder.sh")
        self.assertEqual(intl["name"], "Qoder 国际版")
        self.assertEqual(intl["token"], "intl-token")
        self.assertEqual(cn["base_url"], "https://openapi.qoder.com.cn")
        self.assertEqual(cn["name"], "Qoder CN")
        self.assertEqual(cn["token"], "cn-token")


class UnifiedFlowTest(unittest.TestCase):
    """一次导出：两个 Qoder 版本 + WorkBuddy → 两个 Secret。"""

    CN = {"name": "Qoder CN", "token": "cn-token", "machine_token": "mt",
          "base_url": "https://openapi.qoder.com.cn"}
    INTL = {"name": "Qoder 国际版", "token": "intl-token", "machine_token": "mt",
            "base_url": "https://openapi.qoder.sh"}
    WB = "13800138000:AT:RT"

    def _patch_sources(self):
        return (
            mock.patch.dict(export.EXPORTERS, {
                "qoder": lambda: self.CN, "qoder_intl": lambda: self.INTL}),
            mock.patch.dict(export.SECRET_EXPORTERS, {
                "workbuddy": ("WORKBUDDY_REFRESH_TOKEN", lambda: self.WB)}),
        )

    def test_full_export_print_mode_generates_both_secrets(self):
        p1, p2 = self._patch_sources()
        out, err = io.StringIO(), io.StringIO()
        with p1, p2, mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch.object(export, "copy_to_clipboard") as clip:
            rc = export.main(["--non-interactive", "--only",
                              "workbuddy,qoder,qoder_intl", "--print"])
        self.assertEqual(rc, 0)
        self.assertFalse(clip.called)
        text = out.getvalue().strip()
        self.assertNotIn("#", text)
        blocks = text.split("\n\n")
        self.assertTrue(blocks[0].startswith("SIGNIN_ACCOUNTS\n"))
        self.assertTrue(blocks[1].startswith("WORKBUDDY_REFRESH_TOKEN\n"))
        data = json.loads(blocks[0].split("\n", 1)[1])
        self.assertEqual(len(data["qoder"]), 2)
        self.assertEqual({a["base_url"] for a in data["qoder"]},
                         {"https://openapi.qoder.com.cn", "https://openapi.qoder.sh"})
        self.assertEqual(blocks[1].split("\n", 1)[1], self.WB)
        self.assertIn("Qoder 国际版 凭据已读取", err.getvalue())

    def test_step_mode_copies_name_then_value_for_each_secret(self):
        p1, p2 = self._patch_sources()
        out, err = io.StringIO(), io.StringIO()
        with p1, p2, mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch("builtins.input", return_value="") as enter, \
                mock.patch.object(export, "copy_to_clipboard",
                                  return_value=(True, "mock")) as clip:
            rc = export.main(["--non-interactive", "--only",
                              "workbuddy,qoder,qoder_intl", "--step"])
        self.assertEqual(rc, 0)
        # 两个 Secret → 字段名/数据 × 2 = 4 次写入；最后一次之后直接结束，不清理。
        writes = [call[0][0] for call in clip.call_args_list]
        self.assertEqual(len(writes), 4)
        self.assertEqual(writes[0], "SIGNIN_ACCOUNTS")
        self.assertEqual(len(json.loads(writes[1])["qoder"]), 2)
        self.assertEqual(writes[2], "WORKBUDDY_REFRESH_TOKEN")
        self.assertEqual(writes[3], self.WB)
        self.assertEqual(enter.call_count, 3)
        self.assertEqual(out.getvalue(), "")
        for secret in ("cn-token", "intl-token", self.WB):
            self.assertNotIn(secret, err.getvalue())
        self.assertIn("1/4", err.getvalue())
        self.assertIn("字段名", err.getvalue())
        self.assertIn("数据", err.getvalue())
        self.assertNotIn("剪贴板已清理", err.getvalue())
        self.assertNotIn("清理", err.getvalue())

    def test_no_clipboard_clearing_constant(self):
        self.assertFalse(hasattr(export, "CLIPBOARD_CLEAR_TEXT"))

    def test_secret_flag_skips_stepping_and_copies_pure_value(self):
        with mock.patch.dict(export.EXPORTERS, {
                "qoder": lambda: {"token": "cn-token"}}), \
                mock.patch("sys.stdout", io.StringIO()), \
                mock.patch("sys.stderr", io.StringIO()), \
                mock.patch("builtins.input", return_value="") as enter, \
                mock.patch.object(export, "copy_to_clipboard",
                                  return_value=(True, "mock")) as clip:
            rc = export.main(["--non-interactive", "--only", "qoder", "--step",
                              "--secret", "SIGNIN_ACCOUNTS"])
        self.assertEqual(rc, 0)
        clip.assert_called_once()
        self.assertEqual(json.loads(clip.call_args[0][0])["qoder"][0]["token"],
                         "cn-token")
        self.assertEqual(enter.call_count, 0)

    def test_non_interactive_only_puts_first_secret_in_clipboard(self):
        p1, p2 = self._patch_sources()
        out, err = io.StringIO(), io.StringIO()
        with p1, p2, mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch.object(export, "copy_to_clipboard",
                                  return_value=(True, "mock")) as clip:
            rc = export.main(["--non-interactive", "--only",
                              "workbuddy,qoder,qoder_intl"])
        self.assertEqual(rc, 0)
        clip.assert_called_once()
        self.assertIn("qoder", json.loads(clip.call_args[0][0]))
        self.assertIn("--secret", err.getvalue())
        self.assertEqual(out.getvalue(), "")

    def test_build_secret_items_split_and_env(self):
        accounts = {"qoder": [{"token": "t"}], "trae": [{"token": "u"}]}
        split = export.build_secret_items(accounts, "split",
                                          {"WORKBUDDY_REFRESH_TOKEN": self.WB})
        self.assertEqual([name for name, _ in split],
                         ["QODER_ACCOUNTS", "TRAE_ACCOUNTS", "WORKBUDDY_REFRESH_TOKEN"])
        self.assertIsInstance(json.loads(split[0][1]), list)
        env = export.build_secret_items(accounts, "env")
        self.assertIn(("QODER_TOKEN", "t"), env)
        self.assertTrue(all(not value.startswith("#") for _, value in env))
        self.assertEqual(export.build_secret_items({}, "single",
                                                   {"WORKBUDDY_REFRESH_TOKEN": self.WB}),
                         [("WORKBUDDY_REFRESH_TOKEN", self.WB)])

    def test_secret_flag_gives_pure_value(self):
        with mock.patch.dict(export.EXPORTERS, {
                "qoder": lambda: {"name": "Qoder CN", "token": "cn-token",
                                  "machine_token": "mt"}}), \
                mock.patch.dict(export.SECRET_EXPORTERS, {
                    "workbuddy": ("WORKBUDDY_REFRESH_TOKEN",
                                  lambda: "13800138000:AT:RT")}), \
                mock.patch("sys.stdout", io.StringIO()), \
                mock.patch("sys.stderr", io.StringIO()), \
                mock.patch.object(export, "copy_to_clipboard",
                                  return_value=(True, "mock")) as clip:
            rc = export.main(["--non-interactive", "--only", "workbuddy,qoder",
                              "--secret", "WORKBUDDY_REFRESH_TOKEN"])
        self.assertEqual(rc, 0)
        self.assertEqual(clip.call_args[0][0], "13800138000:AT:RT")
        with mock.patch.dict(export.EXPORTERS, {
                "qoder": lambda: {"name": "Qoder CN", "token": "cn-token",
                                  "machine_token": "mt"}}), \
                mock.patch("sys.stdout", io.StringIO()), \
                mock.patch("sys.stderr", io.StringIO()), \
                mock.patch.object(export, "copy_to_clipboard",
                                  return_value=(True, "mock")) as clip2:
            rc = export.main(["--non-interactive", "--only", "qoder",
                              "--secret", "SIGNIN_ACCOUNTS"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(clip2.call_args[0][0]),
                         {"qoder": [{"name": "Qoder CN", "token": "cn-token",
                                     "machine_token": "mt"}]})

    def test_single_secret_value_helper(self):
        accounts = {"qoder": [{"token": "t"}], "trae": [{"token": "u"}]}
        plain = {"WORKBUDDY_REFRESH_TOKEN": "13800138000:AT:RT"}
        self.assertEqual(export.single_secret_value(accounts, plain,
                                                    "WORKBUDDY_REFRESH_TOKEN"),
                         "13800138000:AT:RT")
        self.assertEqual(json.loads(export.single_secret_value(
            accounts, plain, "QODER_ACCOUNTS")), accounts["qoder"])
        self.assertEqual(export.single_secret_value(accounts, plain, "DOUBAO_ACCOUNTS"), "")

    def test_one_source_failure_does_not_block_others(self):
        def boom():
            raise RuntimeError("客户端没装")
        with mock.patch.dict(export.EXPORTERS, {"qoder": lambda: {"token": "t"}}), \
                mock.patch.dict(export.SECRET_EXPORTERS, {
                    "workbuddy": ("WORKBUDDY_REFRESH_TOKEN", boom)}), \
                mock.patch("sys.stdout", io.StringIO()), \
                mock.patch("sys.stderr", io.StringIO()) as err, \
                mock.patch.object(export, "copy_to_clipboard",
                                  return_value=(True, "mock")) as clip:
            rc = export.main(["--non-interactive", "--only", "workbuddy,qoder"])
        self.assertEqual(rc, 0)
        self.assertIn("导出失败", err.getvalue())
        self.assertEqual(json.loads(clip.call_args[0][0]), {"qoder": [{"token": "t"}]})


class MultiAccountTest(unittest.TestCase):
    """两种导出方式 + 一个 JSON 文件（本地镜像）承载多账号。"""

    WB = "13800138000:AT:RT"
    WB_OTHER = "13900139000:AT2:RT2"
    FAKE_EXPORTERS = {
        "qoder": lambda: {"name": "Qoder CN", "token": "cn-token", "machine_token": "mt"},
        "qoder_intl": lambda: {"name": "Qoder 国际版", "token": "intl-token",
                               "machine_token": "mt"},
        "trae": lambda: {"name": "Trae CN", "token": "trae-token",
                         "device_id": "aha-5e09036c73b51abdf755a4ab60bb9ac2"},
        "doubao": lambda: {"name": "豆包", "cookie": "sessionid=fake"},
    }
    FAKE_SECRET_EXPORTERS = {
        "workbuddy": ("WORKBUDDY_REFRESH_TOKEN", lambda: "13800138000:AT:RT"),
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "accounts.local.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        full = list(argv) + ["--state", str(self.state)]
        with mock.patch.dict(export.EXPORTERS, self.FAKE_EXPORTERS, clear=True), \
                mock.patch.dict(export.SECRET_EXPORTERS, self.FAKE_SECRET_EXPORTERS,
                                clear=True), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch("builtins.input", return_value=""), \
                mock.patch.object(export, "copy_to_clipboard",
                                  return_value=(True, "mock")) as clip:
            rc = export.main(full)
        return rc, out.getvalue(), err.getvalue(), clip

    def _seed(self, accounts, wb=""):
        self.state.write_text(json.dumps({
            "SIGNIN_ACCOUNTS": accounts,
            "WORKBUDDY_REFRESH_TOKEN": wb,
        }, ensure_ascii=False), encoding="utf-8")

    def test_all_mode_rebuilds_state_with_both_secrets(self):
        rc, out, err, clip = self._run(["--mode", "all", "--non-interactive",
                                        "--only", "workbuddy,qoder,trae"])
        self.assertEqual(rc, 0)
        state = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(set(state), {"SIGNIN_ACCOUNTS", "WORKBUDDY_REFRESH_TOKEN"})
        self.assertEqual(set(state["SIGNIN_ACCOUNTS"]), {"qoder", "trae"})
        self.assertEqual(state["WORKBUDDY_REFRESH_TOKEN"], self.WB)
        self.assertIn("本地镜像", err)
        self.assertEqual(out, "")

    def test_all_mode_with_no_state_does_not_write_file(self):
        rc, _, _, _ = self._run(["--mode", "all", "--non-interactive",
                                 "--only", "qoder", "--no-state"])
        self.assertEqual(rc, 0)
        self.assertFalse(self.state.exists())

    def test_single_mode_merges_and_delivers_only_one_secret(self):
        self._seed({"qoder": [{"name": "Qoder CN", "token": "OLD"}],
                    "trae": [{"name": "Trae CN", "token": "trae-token"}]},
                   self.WB_OTHER)
        rc, out, err, clip = self._run(["--mode", "single", "--source", "qoder"])
        self.assertEqual(rc, 0)
        clip.assert_called_once()  # 只交付 SIGNIN_ACCOUNTS，WorkBuddy 不用重粘
        data = json.loads(clip.call_args[0][0])
        self.assertEqual(set(data), {"qoder", "trae"})
        self.assertEqual(data["qoder"][0]["token"], "cn-token")  # 同名替换
        self.assertEqual(data["trae"][0]["token"], "trae-token")  # 其它账号保留
        self.assertEqual(out, "")
        state = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(state["WORKBUDDY_REFRESH_TOKEN"], self.WB_OTHER)

    def test_label_appends_second_account_instead_of_replacing(self):
        self._seed({"qoder": [{"name": "Qoder CN", "token": "OLD"}]})
        rc, _, _, clip = self._run(["--mode", "single", "--source", "qoder",
                                    "--label", "Qoder CN@办公室"])
        self.assertEqual(rc, 0)
        data = json.loads(clip.call_args[0][0])
        self.assertEqual([a["name"] for a in data["qoder"]],
                         ["Qoder CN", "Qoder CN@办公室"])
        self.assertEqual(data["qoder"][1]["token"], "cn-token")

    def test_single_workbuddy_merges_by_phone_and_only_delivers_its_own_secret(self):
        self._seed({"qoder": [{"name": "Qoder CN", "token": "keep"}]},
                   "13800138000:OLD_AT:OLD_RT\n" + self.WB_OTHER)
        rc, _, err, clip = self._run(["--mode", "single", "--source", "workbuddy"])
        self.assertEqual(rc, 0)
        clip.assert_called_once()
        value = clip.call_args[0][0]
        self.assertEqual(value, self.WB + "\n" + self.WB_OTHER)
        self.assertNotIn("--label", value)
        state = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(state["SIGNIN_ACCOUNTS"]["qoder"][0]["token"], "keep")

    def test_single_mode_without_state_refuses_to_overwrite(self):
        rc, out, err, clip = self._run(["--mode", "single", "--source", "qoder"])
        self.assertEqual(rc, 1)
        self.assertFalse(clip.called)
        self.assertEqual(out, "")
        self.assertIn("找不到本地镜像", err)

    def test_no_state_single_outputs_only_exported_account(self):
        rc, _, err, clip = self._run(["--mode", "single", "--source", "qoder",
                                      "--no-state"])
        self.assertEqual(rc, 0)
        self.assertEqual(set(json.loads(clip.call_args[0][0])), {"qoder"})
        self.assertIn("会覆盖", err)

    def test_single_mode_print_shows_only_affected_secret(self):
        self._seed({"qoder": [{"name": "Qoder CN", "token": "OLD"}],
                    "trae": [{"name": "Trae CN", "token": "trae-token"}]}, self.WB)
        rc, out, _, clip = self._run(["--mode", "single", "--source", "qoder",
                                      "--print"])
        self.assertEqual(rc, 0)
        self.assertFalse(clip.called)
        self.assertTrue(out.startswith("SIGNIN_ACCOUNTS\n"))
        self.assertNotIn("WORKBUDDY_REFRESH_TOKEN\n", out)
        self.assertIn('"trae"', out)

    def test_merge_helpers(self):
        base = {"qoder": [{"name": "A", "token": "1"}, {"name": "B", "token": "2"}]}
        merged = export.merge_accounts(base, {"qoder": [{"name": "B", "token": "9"}],
                                              "trae": [{"name": "T", "token": "t"}]})
        self.assertEqual([a["token"] for a in merged["qoder"]], ["1", "9"])
        self.assertEqual(merged["trae"][0]["name"], "T")
        self.assertEqual(export.merge_workbuddy(
            "138:OLD_AT:OLD_RT\n139:AT2:RT2", "138:AT:RT"),
            "138:AT:RT\n139:AT2:RT2")

    def test_choose_mode_and_one_source(self):
        with mock.patch("builtins.input", return_value="2"):
            self.assertEqual(export.choose_mode(), "single")
        with mock.patch("builtins.input", return_value="0"):
            self.assertEqual(export.choose_mode(), "")
        with mock.patch("builtins.input", return_value="3"):
            self.assertEqual(export.choose_one_source(), "qoder_intl")
        with mock.patch("builtins.input", return_value="trae"):
            self.assertEqual(export.choose_one_source(), "trae")
        with mock.patch("builtins.input", return_value="0"):
            self.assertEqual(export.choose_one_source(), "")

    def test_state_roundtrip(self):
        accounts = {"qoder": [{"name": "A", "token": "1"}]}
        self.assertTrue(export.save_state(accounts,
                                          {"WORKBUDDY_REFRESH_TOKEN": self.WB},
                                          self.state))
        state = export.load_state(self.state)
        self.assertEqual(export.state_accounts(state), accounts)
        self.assertEqual(export.state_workbuddy(state), self.WB)
        self.assertEqual(export.load_state(self.state.parent / "missing.json"), {})


class ExportConfirmTest(unittest.TestCase):
    """末尾只问「是否导出镜像文件」；选否也要照常复制粘贴值。"""

    FAKE = {"name": "Qoder CN", "token": "cn-token"}
    WB = "13800138000:AT:RT"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "accounts.local.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _sources(self):
        return (mock.patch.dict(export.EXPORTERS,
                                {"qoder": lambda: dict(self.FAKE)}, clear=True),
                mock.patch.dict(export.SECRET_EXPORTERS,
                                {"workbuddy": ("WORKBUDDY_REFRESH_TOKEN",
                                               lambda: self.WB)}, clear=True))

    def _run(self, argv, answers):
        err = io.StringIO()
        p1, p2 = self._sources()
        argv = list(argv) + ["--state", str(self.state)]
        with p1, p2, \
                mock.patch.object(export.sys, "stdin", mock.Mock(isatty=lambda: True)), \
                mock.patch("builtins.input", side_effect=answers), \
                mock.patch("sys.stdout", io.StringIO()), \
                mock.patch("sys.stderr", err), \
                mock.patch.object(export, "copy_to_clipboard",
                                  return_value=(True, "mock")) as clip:
            rc = export.main(argv)
        return rc, err.getvalue(), clip

    def test_state_lives_next_to_export_script(self):
        self.assertEqual(_ORIG_STATE_PATH, export.HERE / "accounts.local.json")
        self.assertEqual(export.HERE.name, "tools")
        self.assertIn("accounts.local.json",
                      (ROOT / ".gitignore").read_text(encoding="utf-8"))

    def test_display_path_is_never_absolute(self):
        self.assertEqual(export.short_path(_ORIG_STATE_PATH),
                         "tools/accounts.local.json")
        self.assertEqual(export.short_path(self.state), "accounts.local.json")
        self.assertNotIn(str(self.state.parent),
                         export.short_path(self.state))

    def test_describe_secret_never_echoes_value(self):
        value = json.dumps({"qoder": [self.FAKE]})
        desc = export.describe_secret("SIGNIN_ACCOUNTS", value)
        self.assertIn("qoder 1 个账号", desc)
        self.assertNotIn("cn-token", desc)
        self.assertIn("2 个账号", export.describe_secret(
            "WORKBUDDY_REFRESH_TOKEN", "138:AT:RT\n139:AT2:RT2"))
        self.assertEqual(export.describe_secret("QODER_TOKEN", "cn-token"), "单个纯值")

    def test_state_items_describe_both_secrets(self):
        items = export.state_items({"qoder": [self.FAKE]},
                                   {"WORKBUDDY_REFRESH_TOKEN": self.WB})
        self.assertEqual([name for name, _ in items],
                         ["SIGNIN_ACCOUNTS", "WORKBUDDY_REFRESH_TOKEN"])
        self.assertIn("qoder 1 个账号", export.describe_secret(*items[0]))
        self.assertIn("1 个账号", export.describe_secret(*items[1]))

    def test_confirm_file_export_choices(self):
        items = export.state_items({"qoder": [self.FAKE]},
                                   {"WORKBUDDY_REFRESH_TOKEN": self.WB})
        display = export.short_path(self.state)
        err = io.StringIO()
        with mock.patch("builtins.input", return_value=""), \
                mock.patch("sys.stderr", err):
            self.assertTrue(export.confirm_file_export(display, items))
        self.assertIn("是否导出本地镜像文件", err.getvalue())
        self.assertIn("选「否」只是不写这个文件", err.getvalue())
        self.assertIn("文件：accounts.local.json（导出脚本同目录）", err.getvalue())
        self.assertNotIn(str(self.state), err.getvalue())  # 不打印绝对地址
        for value in ("cn-token", "13800138000", self.WB):
            self.assertNotIn(value, err.getvalue())
        for answer in ("0", "n", "否", "不导出"):
            with mock.patch("builtins.input", return_value=answer), \
                    mock.patch("sys.stderr", io.StringIO()):
                self.assertFalse(export.confirm_file_export(display, items))

    def test_declining_file_still_delivers_all_values(self):
        # 末尾选「0 不导出文件」：4 次剪贴板照常走完，只是不写镜像。
        rc, err, clip = self._run([], ["1", "", "", "", "0"])
        self.assertEqual(rc, 0)
        self.assertEqual(clip.call_count, 4)
        self.assertFalse(self.state.exists())
        self.assertIn("是否导出本地镜像文件", err)
        self.assertIn("已跳过本地镜像文件", err)
        self.assertNotIn("已取消", err)
        for value in ("cn-token", self.WB):
            self.assertNotIn(value, err)

    def test_confirming_file_writes_it_after_delivery(self):
        rc, err, clip = self._run([], ["1", "", "", "", "1"])
        self.assertEqual(rc, 0)
        self.assertEqual(clip.call_count, 4)
        self.assertIn("是否导出本地镜像文件", err)
        state = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(set(state), {"SIGNIN_ACCOUNTS", "WORKBUDDY_REFRESH_TOKEN"})
        self.assertNotIn("cn-token", err)

    def test_yes_skips_question_and_writes_file(self):
        rc, err, clip = self._run(["--yes"], ["1", "", "", ""])
        self.assertEqual(rc, 0)
        self.assertNotIn("是否导出本地镜像文件", err)
        self.assertEqual(clip.call_count, 4)
        self.assertTrue(self.state.exists())

    def test_confirm_flag_forces_prompt_in_scripted_mode(self):
        rc, err, clip = self._run(
            ["--non-interactive", "--only", "qoder", "--confirm"], ["0"])
        self.assertEqual(rc, 0)
        self.assertIn("是否导出本地镜像文件", err)
        clip.assert_called_once()   # 选否不影响值照常进剪贴板
        self.assertFalse(self.state.exists())

    def test_no_state_skips_question_entirely(self):
        rc, err, clip = self._run(["--no-state"], [])
        self.assertEqual(rc, 0)
        clip.assert_called_once()   # 脚本化调用：只放第一个值，但仍照常交付
        self.assertNotIn("是否导出本地镜像文件", err)
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
