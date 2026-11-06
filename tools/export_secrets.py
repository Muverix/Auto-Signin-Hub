#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本机凭据导出工具：生成可粘贴的 GitHub Secret 值。

**只在自己的电脑上运行**，不要放进 GitHub Actions、不要提交输出内容。
工具只读本机客户端的登录态文件，不联网、不改写客户端状态。唯一会写入的文件是
多账号合并用的本地镜像 ``accounts.local.json``（按 ``__file__`` 所在目录定位，
即与导出脚本同目录；含明文、已 gitignore），可用 ``--no-state`` 完全禁用。
终端提示里只显示相对路径或文件名，不打印绝对地址。

两种导出方式：

- ``all``（默认，**全部导出**）：一台设备一个账号时用这个。导出本机所有已登录
  来源，重建本地镜像，产出两个 Secret。
- ``single``（**单个软件导出**）：只导出一个来源，按账号名合并进已有的本地镜像，
  只交付受影响的那一个 Secret。给第二台设备/第二个账号加 ``--label`` 区分。

用法::

    pip install cryptography          # Trae / 豆包解密需要（仅本机）
    python tools/export_secrets.py    # 交互：选方式 → 字段/数据逐个进剪贴板
    python tools/export_secrets.py --mode single --source qoder
    python tools/export_secrets.py --mode single --source qoder --label "Qoder CN@办公室"
    python tools/export_secrets.py --secret WORKBUDDY_REFRESH_TOKEN   # 只取一个纯值
    python tools/export_secrets.py --print                             # 脚本用：显式打印明文

**默认不在终端输出任何凭据内容**。按「字段名 → 数据」逐步复制：先复制 Secret
的 Name，粘到 GitHub 的 Name 框；按回车后再复制它的 Value，粘到 Value 框；
再按回车复制下一个 Secret 的 Name……最后一份数据粘完，剪贴板保留最后的内容、
不做清理。

**全部值交付完之后**才会单独问一句「是否导出本地镜像文件」：这一问只管写不写
``tools/accounts.local.json``，选「否」不写文件，但上面的复制粘贴照常完成、
结果不受影响。带 ``--no-state`` 时不问也不写；脚本化调用默认直接写文件，
可用 ``--confirm`` 强制在末尾询问、``--yes`` 跳过询问直接写。

本地镜像 ``tools/accounts.local.json`` 只用于本机合并多账号，**Actions 读不到**，
两个 Secret 的 Name / Value 仍要粘到 GitHub Actions 的 Secrets 里；多账号都在
同一份 JSON / 同一段值里，不用每个账号新建一个键值对。

带 ``--only`` / ``--format`` / ``--non-interactive`` 时跳过导出菜单，且剪贴板
只放第一个 Secret 的数据；其余用 ``--secret NAME`` 分别取，或加 ``--step``
强制逐步等回车。只有显式加 ``--print``（或旧的 ``--no-clip``）才会把值
打印到 stdout，供脚本/排障使用 —— 此时明文会显示在终端，请确认环境安全。

覆盖两个 Secret：
- ``SIGNIN_ACCOUNTS``：``qoder`` / ``trae`` / ``doubao`` 的账号数组 JSON；
  Qoder CN 与国际版各占数组里一项，各自带 ``base_url``。
- ``WORKBUDDY_REFRESH_TOKEN``：``手机号:AT:RT``，供 ``signin/workbuddy.py`` 自举续期。

原理与字段来源：
- WorkBuddy：``%LOCALAPPDATA%/CodeBuddyExtension/.../workbuddy-desktop.info``。
  ``$wbEncrypted`` 字段借客户端 Electron 运行时（``ELECTRON_RUN_AS_NODE=1``）
  取 ``atRestSecretKey`` 解 AES-256-GCM，与 README「凭据维护」链路一致。
- Qoder：本文件内的 ``_qoder_session`` / ``_qoder_risk_headers`` 解登录态 +
  umid 设备风控头（源自 88lin/workbuddy-auto-signin，MIT，见 LICENSE 末尾）。
  CN 与国际版分别按数据目录 ``com.qodercn.app*`` / ``com.qoder.app*`` 与各自
  安装目录的 umid 组件读取，API 域分别为 ``openapi.qoder.com.cn`` /
  ``openapi.qoder.sh``。缺风控头时服务端会静默不下发每日活动。
- Trae CN：``storage.json`` 里的 SS_AES 信封解 JWT，设备号取自
  ``iCubeAuthInfo://icube-dc:`` 键名（旧版 8-20 位纯数字；3.4.15+ 为
  ``aha-<32位hex>``）。**不用 ``telemetry.devDeviceId``（UUID）兜底**，实测会触发 9074 风控。
- 豆包：Chromium v10 Cookie（DPAPI 密钥 + AES-256-GCM + 32 字节前缀）。

导出的是**静态凭据**：客户端重新登录 / 令牌过期后需要重新导出并更新 Secret。
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent   # 导出脚本所在目录（tools/）
ROOT = HERE.parent                      # 仅用于把显示路径转成仓库相对路径

# ---------------------------------------------------------------- 通用

def short_path(path: Path) -> str:
    """显示用：优先相对仓库根，自定义路径只给文件名，不打印绝对地址。"""
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except (ValueError, OSError):
        return path.name

def _need_crypto():
    """返回 cryptography 的 AES 原语；缺库给出可行动提示。"""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("缺少 cryptography，请先在本机运行：pip install cryptography") from exc
    return Cipher, algorithms, modes, AESGCM


def _dpapi_unprotect(data: bytes) -> bytes:
    """Windows DPAPI(CryptUnprotectData)；仅当前登录用户可解。"""
    if sys.platform != "win32":
        raise RuntimeError("DPAPI 解密仅支持 Windows；macOS 请用对应客户端的 Keychain/CDP 链路")
    import ctypes
    import ctypes.wintypes as wt

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data)
    src = DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    dst = DataBlob()
    if not ctypes.WinDLL("crypt32", use_last_error=True).CryptUnprotectData(
            ctypes.byref(src), None, None, None, None, 0, ctypes.byref(dst)):
        raise RuntimeError("CryptUnprotectData 失败（必须以登录客户端的同一 Windows 用户运行）")
    try:
        return ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(dst.pbData)


def _os_crypt_key(local_state: Path) -> bytes:
    data = json.loads(local_state.read_text(encoding="utf-8"))
    wrapped = (data.get("os_crypt") or {}).get("encrypted_key")
    if not wrapped:
        raise RuntimeError("%s 缺少 os_crypt.encrypted_key" % local_state.name)
    raw = base64.b64decode(wrapped)
    if raw[:5] != b"DPAPI":
        raise RuntimeError("os_crypt.encrypted_key 前缀不是 DPAPI")
    return _dpapi_unprotect(raw[5:])


# ---------------------------------------------------------------- 通用：客户端定位

def _uninstall_roots(match) -> list[Path]:
    """从 Windows 卸载注册表项按 DisplayName 推客户端安装根目录。"""
    if sys.platform != "win32":
        return []
    import winreg

    roots: list[Path] = []
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for subpath in (r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"):
            try:
                key = winreg.OpenKey(hive, subpath)
            except OSError:
                continue
            try:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                        name = str(winreg.QueryValueEx(sub, "DisplayName")[0])
                    except OSError:
                        continue
                    if not match(name):
                        continue
                    for prop in ("InstallLocation", "DisplayIcon"):
                        try:
                            raw = str(winreg.QueryValueEx(sub, prop)[0])
                        except OSError:
                            continue
                        raw = re.sub(r",\s*-?\d+\s*$", "", raw).strip().strip('"')
                        if not raw:
                            continue
                        path = Path(raw)
                        roots.append(path.parent if path.suffix.lower() in (".exe", ".ico") else path)
            finally:
                winreg.CloseKey(key)
    seen, uniq = set(), []
    for root in roots:
        key = str(root).lower()
        if key not in seen:
            seen.add(key)
            uniq.append(root)
    return uniq


def _workbuddy_exe() -> Path | None:
    override = os.environ.get("WORKBUDDY_EXE", "").strip()
    if override:
        path = Path(override).expanduser()
        return path if path.is_file() else None
    candidates = [Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "WorkBuddy" / "WorkBuddy.exe",
                  Path(os.environ.get("LOCALAPPDATA", "")) / "WorkBuddy" / "WorkBuddy.exe"]
    candidates += [root / "WorkBuddy.exe" for root in
                   _uninstall_roots(lambda name: "workbuddy" in name.lower())]
    return next((p for p in candidates if p.is_file()), None)


# ---------------------------------------------------------------- Qoder
#
# 登录态解密与 umid 设备风控头：按 88lin/workbuddy-auto-signin 的实现（MIT，
# 授权声明见 LICENSE 末尾）裁成导出工具需要的本地读取部分，去掉了 CLI、联网
# 与领取流程。只保留 auth.v1.dat 解密（DPAPI + AES-256-GCM）、runtime-info.exe
# 产出的设备标识，以及 auth.machine-id / OS / hostname / 版本号。

# 两个版本各有独立的数据目录、API 域与 umid 组件。
QODER_EDITIONS = {
    "qoder": {"label": "Qoder CN", "dir_glob": "com.qodercn.app*",
              "base_url": "https://openapi.qoder.com.cn", "display_name": "Qoder CN"},
    "qoder_intl": {"label": "Qoder 国际版", "dir_glob": "com.qoder.app*",
                   "base_url": "https://openapi.qoder.sh", "display_name": "Qoder"},
}
QODER_UMID_REL = ("resources", "umid", "runtime-info.exe")
QODER_RISK_FIELDS = (
    ("Cosy-MachineToken", "machine_token"),
    ("Cosy-MachineCode", "machine_code"),
    ("Cosy-MachineType", "machine_type"),
    ("Cosy-MachineId", "machine_id"),
    ("Cosy-MachineOS", "machine_os"),
    ("Cosy-MachineHostname", "machine_hostname"),
    ("Cosy-Version", "version"),
)
QODER_UMID_FIELDS = (
    ("machineToken", "Cosy-MachineToken"),
    ("machineCode", "Cosy-MachineCode"),
    ("machineType", "Cosy-MachineType"),
)


def _qoder_auth_dir(dir_glob: str) -> Path | None:
    appdata = Path(os.environ.get("APPDATA", ""))
    dirs = [p for p in appdata.glob(dir_glob) if (p / "auth.v1.dat").is_file()]
    return max(dirs, key=lambda p: p.stat().st_mtime) if dirs else None


def _qoder_umid_exe(edition: str) -> Path | None:
    cfg = QODER_EDITIONS[edition]
    if cfg["display_name"] == "Qoder CN":
        match = lambda name: "qoder cn" in name.lower()
    else:
        match = lambda name: "qoder" in name.lower() and "qoder cn" not in name.lower()
    override = os.environ.get("QODER_UMID_EXE", "").strip()
    if override:
        path = Path(override).expanduser()
        return path if path.is_file() else None
    for root in _uninstall_roots(match):
        exe = root.joinpath(*QODER_UMID_REL)
        if exe.is_file():
            return exe
    return None


def _qoder_decrypt_gcm_cng(key: bytes, nonce: bytes, blob: bytes) -> bytes:
    """没装 cryptography 时改用 Windows 自带 CNG 解 AES-256-GCM。"""
    import ctypes
    import ctypes.wintypes as wt

    class AeadInfo(ctypes.Structure):  # BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        _fields_ = [
            ("cbSize", wt.ULONG), ("dwInfoVersion", wt.ULONG),
            ("pbNonce", ctypes.POINTER(ctypes.c_ubyte)), ("cbNonce", wt.ULONG),
            ("pbAuthData", ctypes.POINTER(ctypes.c_ubyte)), ("cbAuthData", wt.ULONG),
            ("pbTag", ctypes.POINTER(ctypes.c_ubyte)), ("cbTag", wt.ULONG),
            ("pbMacContext", ctypes.POINTER(ctypes.c_ubyte)), ("cbMacContext", wt.ULONG),
            ("cbAAD", wt.ULONG), ("cbData", ctypes.c_ulonglong), ("dwFlags", wt.ULONG),
        ]

    bcrypt = ctypes.WinDLL("bcrypt.dll")
    ct, tag = blob[:-16], blob[-16:]

    def chk(res, what):
        if res != 0:
            raise RuntimeError("CNG %s 失败 NTSTATUS=0x%08x" % (what, res & 0xFFFFFFFF))

    h_alg, h_key = ctypes.c_void_p(), ctypes.c_void_p()
    try:
        chk(bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(h_alg), "AES", None, 0), "OpenAlg")
        mode = "ChainingModeGCM"
        chk(bcrypt.BCryptSetProperty(h_alg, "ChainingMode", mode, (len(mode) + 1) * 2, 0),
            "SetProperty")
        kbuf = ctypes.create_string_buffer(key, len(key))
        chk(bcrypt.BCryptGenerateSymmetricKey(h_alg, ctypes.byref(h_key), None, 0,
                                              kbuf, len(key), 0), "GenKey")
        nbuf = (ctypes.c_ubyte * len(nonce)).from_buffer_copy(nonce)
        tbuf = (ctypes.c_ubyte * len(tag)).from_buffer_copy(tag)
        info = AeadInfo()
        info.cbSize = ctypes.sizeof(AeadInfo)
        info.dwInfoVersion = 1
        info.pbNonce = ctypes.cast(nbuf, ctypes.POINTER(ctypes.c_ubyte))
        info.cbNonce = len(nonce)
        info.pbTag = ctypes.cast(tbuf, ctypes.POINTER(ctypes.c_ubyte))
        info.cbTag = len(tag)
        ibuf = ctypes.create_string_buffer(ct, len(ct))
        obuf = ctypes.create_string_buffer(len(ct))
        done = ctypes.c_ulong()
        chk(bcrypt.BCryptDecrypt(h_key, ibuf, len(ct), ctypes.byref(info), None, 0,
                                 obuf, len(ct), ctypes.byref(done), 0), "Decrypt")
        return obuf.raw[:done.value]
    finally:
        if h_key:
            bcrypt.BCryptDestroyKey(h_key)
        if h_alg:
            bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)


def _qoder_decrypt_gcm(key: bytes, nonce: bytes, blob: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return _qoder_decrypt_gcm_cng(key, nonce, blob)
    return AESGCM(key).decrypt(nonce, blob, None)


def _qoder_session(auth_dir: Path) -> dict:
    """读 auth.v1.dat：v10 + 12 字节 nonce + AES-256-GCM，密钥由 DPAPI 保护。"""
    raw = (auth_dir / "auth.v1.dat").read_bytes()
    if not raw.startswith(b"v10") or len(raw) < 3 + 12 + 16 + 2:
        raise RuntimeError("auth.v1.dat 格式未知或正被客户端改写")
    key = _os_crypt_key(auth_dir / "Local State")
    plain = _qoder_decrypt_gcm(key, raw[3:15], raw[15:])
    sess = json.loads(plain.decode("utf-8"))
    token = sess.get("token") if isinstance(sess, dict) else None
    if not isinstance(token, str) or not token.strip():
        raise RuntimeError("解密成功但会话里没有 token")
    return sess


def _qoder_umid_identity(exe: Path) -> dict:
    """运行客户端自带的 umid 组件，取最后一行 JSON 作为设备身份。"""
    try:
        proc = subprocess.run(
            [str(exe), "--account-stdin"], input=b"", capture_output=True, timeout=15,
            cwd=str(exe.parent), creationflags=0x08000000 if sys.platform == "win32" else 0)
    except (OSError, subprocess.SubprocessError):
        return {}
    for line in reversed(proc.stdout.decode("utf-8", "replace").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        return data if isinstance(data, dict) else {}
    return {}


def _qoder_machine_id(auth_dir: Path | None, dir_glob: str) -> str:
    candidates = [auth_dir] if auth_dir else []
    appdata = Path(os.environ.get("APPDATA", ""))
    candidates += [p for p in appdata.glob(dir_glob) if p not in candidates]
    for root in candidates:
        try:
            value = (root / "auth.machine-id").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    return ""


def _qoder_risk_headers(auth_dir: Path | None, umid_exe: Path | None,
                        dir_glob: str) -> dict:
    """组装 Cosy-* 设备风控头；缺哪个就少给哪个，不编造设备标识。"""
    import platform
    import socket

    headers: dict = {}
    if sys.platform == "win32":
        arch = {"amd64": "x86_64", "x86_64": "x86_64",
                "aarch64": "aarch64", "arm64": "aarch64"}.get(
                    platform.machine().lower(), "x86_64")
        headers["Cosy-MachineOS"] = "%s_windows" % arch
        headers["Cosy-MachineHostname"] = socket.gethostname()
    if umid_exe and umid_exe.is_file():
        try:
            manifest = json.loads((umid_exe.parent.parent / "build-manifest.json")
                                  .read_text(encoding="utf-8"))
            if manifest.get("productVersion"):
                headers["Cosy-Version"] = str(manifest["productVersion"])
        except (OSError, ValueError):
            pass
        identity = _qoder_umid_identity(umid_exe)
        for src, dst in QODER_UMID_FIELDS:
            if identity.get(src):
                headers[dst] = str(identity[src])
    mid = _qoder_machine_id(auth_dir, dir_glob)
    if mid:
        headers["Cosy-MachineId"] = mid
    return headers


def export_qoder(edition: str = "qoder") -> dict:
    """导出一个 Qoder 版本；``edition`` 取值 ``qoder`` / ``qoder_intl``。"""
    if isinstance(edition, bool):  # 兼容旧的 --qoder-intl 布尔调用
        edition = "qoder_intl" if edition else "qoder"
    cfg = QODER_EDITIONS.get(edition, QODER_EDITIONS["qoder"])
    if sys.platform != "win32":
        raise RuntimeError("Qoder 登录态自动导出仅支持 Windows（DPAPI）；"
                           "其它系统请在 Secret 里手动填 token 与 Cosy-* 风控头")
    auth_dir = _qoder_auth_dir(cfg["dir_glob"])
    if not auth_dir:
        raise RuntimeError("没找到 %s 登录态（%%APPDATA%%\\%s）；请先安装并登录该版本"
                           % (cfg["label"], cfg["dir_glob"]))
    acct: dict = {"name": cfg["label"], "base_url": cfg["base_url"],
                  "token": _qoder_session(auth_dir)["token"]}
    umid = _qoder_umid_exe(edition)
    risk = _qoder_risk_headers(auth_dir, umid, cfg["dir_glob"])
    for header, field in QODER_RISK_FIELDS:
        if risk.get(header):
            acct[field] = str(risk[header])
    if not umid:
        print("⚠️ %s 未定位到该版本自带的 umid 组件，风控头可能来自另一版本安装"
              % cfg["label"], file=sys.stderr)
    if not acct.get("machine_token"):
        print("⚠️ %s 未取到 Cosy-MachineToken，服务端可能静默不下发每日活动"
              % cfg["label"], file=sys.stderr)
    return acct


# ---------------------------------------------------------------- Trae CN

# Trae CN 客户端 byteCrypto SS_AES 的固定盐表。
_GLE = bytes([82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
              124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233,
              203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250,
              195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109,
              139, 209, 37])
_ZLE = bytes([31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
              96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156,
              239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83,
              153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33,
              12, 125])

#: Aha 设备号有两种代际形态（2026-11-06 在 Trae CN 3.4.15 上复核）：
#: 旧版 = ``icube-dc:`` 键名后的 8-20 位纯数字；新版 = ``aha-<32位hex>``。
#: 客户端 ``_applyUgDeviceHeaders`` 把它原样放进 ``x-device-id``；
#: ``telemetry.devDeviceId`` 是 36 位 UUID，实测会触发 9074 风控，**不可兜底**。
AHA_KEY_PREFIX = "iCubeAuthInfo://icube-dc:"
AHA_ID_RE = re.compile(r"^aha-[0-9a-fA-F]{16,40}$")
LEGACY_ID_RE = re.compile(r"^\d{8,20}$")
LOG_ID_RE = re.compile(r"(?:resolve device_id:|ldid:)\s*(aha-[0-9a-fA-F]{16,40}|\d{8,20})")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")


def aha_device_id(storage: dict) -> tuple[str, str]:
    """从 storage.json 顶层键名解析 Aha 设备号，返回 ``(设备号, 来源)``。"""
    unknown: list[str] = []
    legacy = ""
    for key in storage:
        text = str(key)
        if not text.startswith(AHA_KEY_PREFIX):
            continue
        candidate = text[len(AHA_KEY_PREFIX):].strip()
        # 两种代际的键可能并存；新版客户端一律以 aha-<hex> 为准。
        if AHA_ID_RE.match(candidate):
            return candidate, "icube-dc 键名（新版 aha-<hex>）"
        if LEGACY_ID_RE.match(candidate) and not legacy:
            legacy = candidate
        elif candidate and not LEGACY_ID_RE.match(candidate):
            unknown.append(candidate[:40])
    if legacy:
        return legacy, "icube-dc 键名（旧版纯数字）"
    reason = "未识别的 icube-dc 形态：%s" % ",".join(unknown) if unknown \
        else "storage.json 里没有 icube-dc 设备键"
    return "", reason


def aha_device_id_from_logs(log_root: Path | None = None) -> str:
    """兜底：客户端日志里 ``resolve device_id`` / ``ldid`` 是运行时权威值。

    只读日志文本，按修改时间倒序取最近的一条；不做任何伪造。
    """
    root = log_root or (Path(os.environ.get("APPDATA", "")) / "Trae CN" / "logs")
    if not root.is_dir():
        return ""
    try:
        files = sorted(root.rglob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:40]
    except OSError:
        return ""
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        matches = list(LOG_ID_RE.finditer(text))
        if matches:
            return matches[-1].group(1)
    return ""


def export_trae() -> dict:
    Cipher, algorithms, modes, _ = _need_crypto()
    appdata = Path(os.environ.get("APPDATA", ""))
    storage_path = None
    for name in ("Trae CN", "Trae"):
        candidate = appdata / name / "User" / "globalStorage" / "storage.json"
        if candidate.is_file():
            storage_path = candidate
            break
    if storage_path is None:
        raise RuntimeError("没找到 Trae CN 的 storage.json；请先安装并登录桌面端")
    data = json.loads(storage_path.read_text(encoding="utf-8"))
    key_name = "iCubeAuthInfo://icube.cloudide" if "iCubeAuthInfo://icube.cloudide" in data else \
        next((k for k in data if k.startswith("iCubeAuthInfo://")), None)
    if not key_name:
        raise RuntimeError("storage.json 里没有 iCubeAuthInfo:// 登录态键")

    raw = base64.b64decode(data[key_name])
    if raw[:6] != bytes([116, 99, 5, 16, 0, 0]):
        raise RuntimeError("登录态信封头不属于 SS_AES 方案")
    master = raw[6:38]
    salt = bytes(_GLE[i] ^ _ZLE[i] for i in range(64))
    digest = hashlib.sha512(hashlib.sha512(master).digest() + salt).digest()
    aes_key, iv = digest[:16], digest[16:32]
    dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    plain = dec.update(raw[38:]) + dec.finalize()
    pad = plain[-1] if plain else 0
    if plain and 1 <= pad <= 16 and plain.endswith(bytes([pad]) * pad):
        plain = plain[:-pad]
    if plain[:64] != hashlib.sha512(plain[64:]).digest():
        raise RuntimeError("登录态校验和不匹配（文件可能正被客户端改写）")
    info = json.loads(plain[64:].decode("utf-8"))
    if not info.get("token"):
        raise RuntimeError("解密成功但登录态里没有 token")

    # 设备号 = 客户端 iCubeDeviceRegisterMainService.guaranteedDeviceId，
    # 即 icube-dc 键名后缀（旧版纯数字 / 3.4.15+ 的 aha-<hex>）。
    device_id, source = aha_device_id(data)
    if not device_id:
        device_id = aha_device_id_from_logs()
        if device_id:
            source = "客户端日志 resolve device_id / ldid"
    if not device_id:
        # 不做静默兜底：UUID 形态的设备号会触发 9074 风控。
        uuid_hint = str(data.get("telemetry.devDeviceId") or "").strip()
        print("⚠️ 未找到 Aha 设备号（%s）" % source, file=sys.stderr)
        if uuid_hint and UUID_RE.match(uuid_hint):
            print("⛔ 检测到 telemetry.devDeviceId 是 UUID 形态，已拒绝用它兜底："
                  "UUID 形态实测会触发 9074 风控，claim 必然失败。", file=sys.stderr)
        print("   请在下面 JSON 里把 trae[*].device_id 手动补成客户端真实设备号"
              "（形如 aha-<32位hex>，旧版为 8-20 位纯数字）后再写入 Secret；"
              "也可打开 Trae 客户端后在 %APPDATA%\\Trae CN\\logs 里搜 resolve device_id。",
              file=sys.stderr)
    else:
        masked = device_id[:7] + "…" + device_id[-4:] if len(device_id) > 14 else device_id
        print("🔑 Trae 设备号 %s（来源：%s）" % (masked, source), file=sys.stderr)
    acct = {"name": "主号", "token": info["token"], "device_id": device_id}
    if data.get("iCubeLastVersion"):
        acct["app_version"] = str(data["iCubeLastVersion"])
    return acct


# ---------------------------------------------------------------- 豆包

REQUIRED_COOKIES = ("sessionid", "sid_tt", "uid_tt")


def export_doubao() -> dict:
    _, _, _, AESGCM = _need_crypto()
    root = Path(os.environ.get("DOUBAO_USER_DATA_DIR") or
                (Path(os.environ.get("LOCALAPPDATA", "")) / "Doubao" / "User Data"))
    local_state = root / "Local State"
    if not local_state.is_file():
        raise RuntimeError("没找到豆包 Local State；请先安装并登录豆包电脑版")
    key = _os_crypt_key(local_state)
    dbs = [root / "Default" / "Network" / "Cookies"]
    dbs += sorted(root.glob("Profile */Network/Cookies"),
                  key=lambda p: p.stat().st_mtime, reverse=True)
    dbs = [p for p in dbs if p.is_file()]
    if not dbs:
        raise RuntimeError("没找到豆包 Cookie 库")

    merged: dict[str, str] = {}
    for db in dbs:
        tmp = Path(tempfile.gettempdir()) / ("wb-doubao-%s.db" % os.getpid())
        try:
            shutil.copyfile(db, tmp)
            conn = sqlite3.connect(str(tmp))
            try:
                rows = conn.execute(
                    "select host_key, name, encrypted_value from cookies "
                    "where host_key like '%doubao.com'").fetchall()
            finally:
                conn.close()
            for host, name, encrypted in rows:
                blob = bytes(encrypted)
                if not blob.startswith(b"v10"):
                    continue
                plain = AESGCM(key).decrypt(blob[3:15], blob[15:], None)
                value = plain[32:].decode("utf-8", "replace")  # 32B 应用层前缀
                if value and value.isprintable():
                    merged.setdefault(name, value)
        except Exception as exc:
            print("⚠️ 跳过 Cookie 库 %s：%s（客户端运行时可能独占，关掉后重试）"
                  % (db.parent.parent.name, type(exc).__name__), file=sys.stderr)
        finally:
            with contextlib.suppress(OSError):
                tmp.unlink()

    missing = [n for n in REQUIRED_COOKIES if n not in merged]
    if missing:
        raise RuntimeError("登录态不完整，缺 %s；请完全退出豆包客户端让 Cookie 落盘后重试"
                           % ",".join(missing))
    cookie = "; ".join("%s=%s" % (n, v) for n, v in sorted(merged.items()))
    return {"name": "主号", "cookie": cookie, "campaign_code": "pc_incentive_task_mvp_v3"}


# ---------------------------------------------------------------- WorkBuddy

WB_AUTH_REL = Path("CodeBuddyExtension") / "Data" / "Public" / "auth" / "workbuddy-desktop.info"
TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/-]+=*$")
PHONE_RE = re.compile(r"^\+?[0-9]{5,20}$")

#: 与 README「凭据维护」链路一致：借客户端 Electron 运行时取 atRestSecretKey，
#: 派生密钥后解 AES-256-GCM。明文字符串原样返回，不落盘、不联网。
WB_DECRYPT_JS = r"""
const crypto = require('crypto');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', s => input += s);
process.stdin.on('end', () => {
  let key;
  try {
    function decrypt(v) {
      if (typeof v === 'string') return v;
      if (!v || v.$wbEncrypted !== 1) throw Error('UNSUPPORTED_FORMAT');
      const e = JSON.parse(Buffer.from(v.envelope,'base64').toString('utf8'));
      if (e.suite !== 1) throw Error('UNSUPPORTED_SUITE');
      if (!key) {
        const p = JSON.parse(process._linkedBinding('electron_browser_workbuddy_storage').loggerGet());
        if (p.version !== 1 || typeof p.atRestSecretKey !== 'string') throw Error('RUNTIME_UNAVAILABLE');
        key = crypto.createHash('sha256').update(p.atRestSecretKey,'utf8').digest();
      }
      if (crypto.createHash('sha256').update(key).digest('hex').slice(0,16) !== e.keyId)
        throw Error('KEY_MISMATCH');
      function lp(s) { const b = Buffer.from(s,'utf8'), n = Buffer.alloc(4); n.writeUInt32BE(b.length); return Buffer.concat([n,b]); }
      const aad = Buffer.concat([
        Buffer.from('WB-AAD\0','ascii'), Buffer.from([1]),
        lp('WBEV1'), lp('sym-v1'), Buffer.from([0,0,0,1]),
        lp(e.keyId), Buffer.from([2,0,0])
      ]);
      const c = crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(e.nonce,'base64'),{authTagLength:16});
      c.setAAD(aad); c.setAuthTag(Buffer.from(e.authTag,'base64'));
      const plain = Buffer.concat([c.update(Buffer.from(e.ciphertext,'base64')),c.final()]);
      try { return plain.toString('utf8'); } finally { plain.fill(0); }
    }
    const result = {};
    for (const [k,v] of Object.entries(JSON.parse(input))) result[k] = decrypt(v);
    process.stdout.write(JSON.stringify({ok:true,result}));
  } catch (e) {
    const allowed = ['UNSUPPORTED_FORMAT','UNSUPPORTED_SUITE','RUNTIME_UNAVAILABLE','KEY_MISMATCH'];
    process.stdout.write(JSON.stringify({ok:false,error:allowed.includes(e.message) ? e.message : 'DECRYPT_FAILED'}));
  } finally { if (key) key.fill(0); }
});
"""


def _wb_normalize(value) -> str:
    """认证字段可能被 JSON 字符串再包一层，最多剥两层。"""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    for _ in range(2):
        try:
            decoded = json.loads(text)
        except (ValueError, TypeError):
            break
        if not isinstance(decoded, str):
            break
        text = decoded.strip()
    return text


def _wb_jwt_user(token: str) -> str:
    """AT 里通常带 preferred_username（手机号），作为账号键的兜底。"""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return str(json.loads(base64.urlsafe_b64decode(payload)).get("preferred_username") or "")
    except Exception:
        return ""


def _wb_decrypt(exe: Path, values: dict) -> dict:
    encoded = base64.b64encode(WB_DECRYPT_JS.encode("utf-8")).decode("ascii")
    args = [str(exe), "-e", "eval(Buffer.from('%s','base64').toString('utf8'))" % encoded]
    env = dict(os.environ, ELECTRON_RUN_AS_NODE="1")
    try:
        proc = subprocess.run(args, input=json.dumps(values).encode("utf-8"),
                              capture_output=True, timeout=30, env=env)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("调用 WorkBuddy 客户端运行时失败：%s" % type(exc).__name__) from exc
    try:
        reply = json.loads(proc.stdout.decode("utf-8", "replace"))
    except ValueError as exc:
        raise RuntimeError("客户端运行时返回内容无法解析") from exc
    if not reply.get("ok"):
        raise RuntimeError("认证字段解密失败：%s" % reply.get("error"))
    return reply["result"]


def export_workbuddy() -> str:
    """返回 ``手机号:AT:RT``，直接对应 ``WORKBUDDY_REFRESH_TOKEN``。"""
    auth_file = Path(os.environ.get("LOCALAPPDATA", "")) / WB_AUTH_REL
    if not auth_file.is_file():
        raise RuntimeError("没找到 WorkBuddy 认证文件；请先安装并登录 WorkBuddy 桌面端")
    data = json.loads(auth_file.read_text(encoding="utf-8"))
    auth = data.get("auth") or {}
    values: dict = {}
    for field in ("accessToken", "refreshToken"):
        top = data.get(field)
        values[field] = top if isinstance(top, str) and top else auth.get(field)
        if values[field] is None:
            raise RuntimeError("认证文件缺少 %s" % field)
    phone_raw = (data.get("account") or {}).get("phoneNumber")
    if phone_raw is not None:
        values["phoneNumber"] = phone_raw

    if any(not isinstance(v, str) for v in values.values()):
        exe = _workbuddy_exe()
        if exe is None:
            raise RuntimeError("认证字段已加密但找不到 WorkBuddy 客户端；"
                               "可设 WORKBUDDY_EXE 指向 WorkBuddy.exe")
        values = _wb_decrypt(exe, values)

    at = _wb_normalize(values["accessToken"])
    rt = _wb_normalize(values["refreshToken"])
    phone = _wb_normalize(values.get("phoneNumber", ""))
    for label, value in (("AT", at), ("RT", rt)):
        if not TOKEN_RE.match(value):
            raise RuntimeError("WorkBuddy %s 为空或格式异常" % label)
    if not PHONE_RE.match(phone):
        phone = _wb_jwt_user(at)
    if not PHONE_RE.match(phone):
        phone = "acct-1"
        print("⚠️ 未能自动识别手机号，用 acct-1 作账号键（不影响 WorkBuddy 主程序）",
              file=sys.stderr)
    return "%s:%s:%s" % (phone, at, rt)


# ---------------------------------------------------------------- 入口

EXPORTERS = {"qoder": lambda: export_qoder("qoder"),
             "qoder_intl": lambda: export_qoder("qoder_intl"),
             "trae": export_trae, "doubao": export_doubao}
APP_OF_SOURCE = {"qoder": "qoder", "qoder_intl": "qoder",
                 "trae": "trae", "doubao": "doubao"}
SECRET_EXPORTERS = {"workbuddy": ("WORKBUDDY_REFRESH_TOKEN", export_workbuddy)}
SOURCES = ("workbuddy", "qoder", "qoder_intl", "trae", "doubao")
SOURCE_LABEL = {
    "workbuddy": "WorkBuddy（每日领取 / 成长任务）",
    "qoder": "Qoder CN",
    "qoder_intl": "Qoder 国际版",
    "trae": "Trae CN",
    "doubao": "豆包（本机未安装可跳过）",
}
PLATFORMS = ("qoder", "trae", "doubao")
SPLIT_SECRET_NAME = {"qoder": "QODER_ACCOUNTS", "trae": "TRAE_ACCOUNTS",
                     "doubao": "DOUBAO_ACCOUNTS"}
ENV_SECRET_NAME = {"qoder": ("QODER_TOKEN", "token"), "trae": ("TRAE_TOKEN", "token"),
                   "doubao": ("DOUBAO_COOKIE", "cookie")}
FORMAT_LABEL = {
    "single": "SIGNIN_ACCOUNTS —— 一个 Secret 装下三个平台（推荐）",
    "split": "三个独立 Secret —— QODER_ACCOUNTS / TRAE_ACCOUNTS / DOUBAO_ACCOUNTS",
    "env": "单账号快捷变量 —— QODER_TOKEN / TRAE_TOKEN / DOUBAO_COOKIE",
}
SOURCE_ALIASES = {"qoder-cn": "qoder", "qodercn": "qoder", "intl": "qoder_intl",
                  "qoder-intl": "qoder_intl", "wb": "workbuddy"}
MODE_LABEL = {"all": "全部导出（本机所有已登录软件 → 两个 Secret）",
              "single": "单个软件导出（只导一个软件，合并进已有配置）"}

#: 多账号合并用的本地镜像：两个 Secret 的完整值，已在 .gitignore 里。
#: 只按「本脚本所在目录」定位，不写死任何绝对地址。
STATE_PATH = HERE / "accounts.local.json"


# ---------------------------------------------------------------- 本地镜像与合并

def load_state(path: Path | None = None) -> dict:
    """读本地镜像；不存在或不是合法 JSON 时返回空字典。"""
    p = path or STATE_PATH
    if not p.is_file():
        return {}
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return obj if isinstance(obj, dict) else {}


def save_state(accounts: dict, plain: dict, path: Path | None = None) -> bool:
    """把两个 Secret 的完整值写回本地镜像（原子替换）。

    这个文件含**明文凭据**，只在本机使用、已 gitignore；可用 ``--no-state`` 完全禁用。
    """
    p = path or STATE_PATH
    payload = {"SIGNIN_ACCOUNTS": accounts,
               "WORKBUDDY_REFRESH_TOKEN": str(plain.get("WORKBUDDY_REFRESH_TOKEN") or "")}
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")
        tmp.replace(p)
        return True
    except OSError as exc:
        print("⚠️ 本地镜像写入失败（%s），本次仍可继续，但不会记住多账号状态。"
              % type(exc).__name__, file=sys.stderr)
        return False


def state_accounts(state: dict) -> dict:
    obj = state.get("SIGNIN_ACCOUNTS")
    if not isinstance(obj, dict):
        return {}
    return {app: [dict(a) for a in obj.get(app, []) if isinstance(a, dict)]
            for app in PLATFORMS if isinstance(obj.get(app), list) and obj[app]}


def state_workbuddy(state: dict) -> str:
    value = state.get("WORKBUDDY_REFRESH_TOKEN")
    return value.strip() if isinstance(value, str) else ""


def merge_accounts(base: dict, new: dict) -> dict:
    """按 ``name`` 合并账号：同名替换、异名追加（用于第二台设备/第二个账号）。"""
    out: dict[str, list[dict]] = {
        app: [dict(a) for a in base.get(app, []) if isinstance(a, dict)]
        for app in PLATFORMS}
    for app, accs in new.items():
        if app not in out or not isinstance(accs, list):
            continue
        for acc in accs:
            if not isinstance(acc, dict):
                continue
            key = str(acc.get("name") or "").strip()
            pos = next((i for i, a in enumerate(out[app])
                        if str(a.get("name") or "").strip() == key), None)
            if pos is None:
                out[app].append(dict(acc))
            else:
                out[app][pos] = dict(acc)
    return {app: lst for app, lst in out.items() if lst}


def merge_workbuddy(base: str, new: str) -> str:
    """按手机号合并多行 ``手机号:AT:RT``：同号替换、异号追加。"""
    lines: dict[str, str] = {}
    for line in (base + "\n" + new).splitlines():
        line = line.strip()
        if line:
            lines[line.split(":", 1)[0]] = line
    return "\n".join(lines.values())


def format_items(items: list[tuple[str, str]]) -> str:
    """``--print`` 用：每段首行是字段名，其后是纯值。"""
    return "\n\n".join("%s\n%s" % (name, value) for name, value in items)


# ---------------------------------------------------------------- 交互选择

def choose_platforms() -> list[str]:
    """终端里选要导出的凭据来源；返回空列表表示取消。"""
    all_key = str(len(SOURCES) + 1)
    print("\n要导出哪些凭据？", file=sys.stderr)
    for i, src in enumerate(SOURCES, 1):
        print("  %d) %s" % (i, SOURCE_LABEL[src]), file=sys.stderr)
    print("  %s) 全部（默认）      0) 取消" % all_key, file=sys.stderr)
    for _ in range(3):
        try:
            answer = input("输入编号，逗号分隔（如 1,3），回车=全部：").strip()
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return []
        if not answer or answer.lower() in (all_key, "all", "a"):
            return list(SOURCES)
        if answer == "0":
            return []
        picked: list[str] = []
        for part in answer.replace("，", ",").split(","):
            part = part.strip().lower()
            if part.isdigit() and 1 <= int(part) <= len(SOURCES):
                picked.append(SOURCES[int(part) - 1])
            elif part in SOURCES:
                picked.append(part)
            elif part in SOURCE_ALIASES:
                picked.append(SOURCE_ALIASES[part])
            else:
                picked = []
                break
        if picked:
            return list(dict.fromkeys(picked))
        print("⚠️ 没看懂，请输入 1~%d、逗号组合或 %s：" % (len(SOURCES), all_key),
              file=sys.stderr)
    print("⚠️ 输入次数过多，按全部处理。", file=sys.stderr)
    return list(SOURCES)


def choose_format(default: str = "single") -> str:
    print("\n导出成哪种 GitHub Secret 格式？", file=sys.stderr)
    for i, key in enumerate(("single", "split", "env"), 1):
        print("  %d) %s" % (i, FORMAT_LABEL[key]), file=sys.stderr)
    try:
        answer = input("输入编号，回车=1：").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return default
    return {"1": "single", "2": "split", "3": "env",
            "single": "single", "split": "split", "env": "env"}.get(answer or "1", default)


def choose_mode(default: str = "all") -> str:
    """第一层菜单：全部导出 / 单个软件导出；返回空字符串表示取消。"""
    print("\n导出方式？", file=sys.stderr)
    print("  1) %s（推荐）" % MODE_LABEL["all"], file=sys.stderr)
    print("  2) %s" % MODE_LABEL["single"], file=sys.stderr)
    print("  0) 取消", file=sys.stderr)
    try:
        answer = input("输入编号，回车=1：").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return ""
    if answer == "0":
        return ""
    return {"1": "all", "2": "single", "all": "all", "single": "single"}.get(
        answer or "1", default)


def choose_one_source(default: str = "workbuddy") -> str:
    """单软件模式下选一个来源；返回空字符串表示取消。"""
    print("\n导出哪个软件的凭据？", file=sys.stderr)
    for i, src in enumerate(SOURCES, 1):
        print("  %d) %s" % (i, SOURCE_LABEL[src]), file=sys.stderr)
    print("  0) 取消", file=sys.stderr)
    for _ in range(3):
        try:
            answer = input("输入编号或名称，回车=1：").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return ""
        if answer == "0":
            return ""
        answer = answer or ("1" if default == "workbuddy"
                            else str(SOURCES.index(default) + 1))
        if answer.isdigit() and 1 <= int(answer) <= len(SOURCES):
            return SOURCES[int(answer) - 1]
        if answer in SOURCES:
            return answer
        if answer in SOURCE_ALIASES:
            return SOURCE_ALIASES[answer]
        print("⚠️ 没看懂，请输入 1~%d 或名称：" % len(SOURCES), file=sys.stderr)
    print("⚠️ 输入次数过多，已取消。", file=sys.stderr)
    return ""


def describe_secret(name: str, value: str) -> str:
    """确认页用：只描述账号数量，绝不回显任何凭据值。"""
    if name == "WORKBUDDY_REFRESH_TOKEN":
        count = len([line for line in value.splitlines() if line.strip()])
        return "%d 个账号（每行一个 手机号:AT:RT）" % count
    try:
        data = json.loads(value)
    except (ValueError, TypeError):
        return "单个纯值"
    if isinstance(data, dict):
        parts = ["%s %d 个账号" % (app, len(accs)) for app, accs in data.items()
                 if isinstance(accs, list) and accs]
        return "、".join(parts) if parts else "空配置"
    if isinstance(data, list):
        return "%d 个账号" % len(data)
    return "单个纯值"


def state_items(accounts: dict, plain: dict) -> list[tuple[str, str]]:
    """把本地镜像里会保存的两个 Secret 转成「名称 → 数量」用的描述数据。"""
    items = []
    if accounts:
        items.append(("SIGNIN_ACCOUNTS", json.dumps(accounts, ensure_ascii=False)))
    wb = str(plain.get("WORKBUDDY_REFRESH_TOKEN") or "")
    if wb:
        items.append(("WORKBUDDY_REFRESH_TOKEN", wb))
    return items


def confirm_file_export(display: str, items: list[tuple[str, str]]) -> bool:
    """最后一步单独问「要不要写本地镜像文件」；选否只跳过文件，不影响剪贴板。"""
    print("\n──────── 是否导出本地镜像文件？ ────────", file=sys.stderr)
    print("文件：%s（导出脚本同目录）" % display, file=sys.stderr)
    print("将保存 %d 个 Secret 的完整值（明文，不显示内容）：" % len(items), file=sys.stderr)
    for name, value in items:
        print("  · %-28s %s" % (name, describe_secret(name, value)), file=sys.stderr)
    print("用途：下次「单个软件导出」靠它合并其它账号，避免把已有账号覆盖掉；"
          "Actions 读不到这个文件，不用上传。", file=sys.stderr)
    print("选「否」只是不写这个文件，上面的剪贴板内容照常粘到 GitHub。", file=sys.stderr)
    print("  1) 导出文件（默认）", file=sys.stderr)
    print("  0) 不导出文件", file=sys.stderr)
    for _ in range(3):
        try:
            answer = input("输入编号，回车=1：").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return False
        if answer in ("", "1", "y", "yes", "是", "导出"):
            return True
        if answer in ("0", "n", "no", "否", "不导出"):
            return False
        print("⚠️ 请输入 1 导出或 0 不导出：", file=sys.stderr)
    print("⚠️ 输入次数过多，按不导出处理。", file=sys.stderr)
    return False


# ---------------------------------------------------------------- 格式转换

def format_secrets(out: dict, fmt: str,
                   plain_secrets: dict | None = None) -> tuple[str, str]:
    """``--print`` 用：每段首行是字段名，其后是纯值；不写任何注释。"""
    plain = plain_secrets or {}
    if fmt == "split":
        blocks, names = [], []
        for app in PLATFORMS:
            if app not in out:
                continue
            name = SPLIT_SECRET_NAME[app]
            names.append(name)
            blocks.append("%s\n%s" % (name, json.dumps(out[app], ensure_ascii=False, indent=2)))
        for name, value in plain.items():
            names.append(name)
            blocks.append("%s\n%s" % (name, value))
        return "\n\n".join(blocks), " / ".join(names)
    if fmt == "env":
        lines = []
        for app in PLATFORMS:
            if app not in out:
                continue
            acc = out[app][0]
            env_name, field = ENV_SECRET_NAME[app]
            lines.append("%s=%s" % (env_name, acc.get(field, "")))
            if app == "trae":
                if acc.get("device_id"):
                    lines.append("TRAE_DEVICE_ID=%s" % acc["device_id"])
                if acc.get("app_version"):
                    lines.append("TRAE_APP_VERSION=%s" % acc["app_version"])
            elif app == "qoder" and "qoder.sh" in str(acc.get("base_url") or ""):
                lines.append("QODER_BASE_URL=%s" % acc["base_url"])
            elif app == "doubao" and acc.get("campaign_code"):
                lines.append("DOUBAO_CAMPAIGN_CODE=%s" % acc["campaign_code"])
        for name, value in plain.items():
            lines.append("%s=%s" % (name, value))
        return "\n".join(lines), "等号左边是 Secret 名称"

    json_text = json.dumps(out, ensure_ascii=False, indent=2)
    if not plain:
        return json_text, "SIGNIN_ACCOUNTS"
    blocks = ["SIGNIN_ACCOUNTS\n" + json_text] if out else []
    names = ["SIGNIN_ACCOUNTS"] if out else []
    for name, value in plain.items():
        names.append(name)
        blocks.append("%s\n%s" % (name, value))
    return "\n\n".join(blocks), " / ".join(names)


def single_secret_value(accounts: dict, plain: dict, name: str) -> str:
    """取某一个 Secret 的纯 Value（不带分段标注），便于一次 Ctrl+V。"""
    if name == "SIGNIN_ACCOUNTS":
        return json.dumps(accounts, ensure_ascii=False, indent=2) if accounts else ""
    if name in plain:
        return plain[name]
    for app, secret_name in SPLIT_SECRET_NAME.items():
        if secret_name == name and app in accounts:
            return json.dumps(accounts[app], ensure_ascii=False, indent=2)
    return ""


def print_secret_guide(fmt: str, names: str, has_plain: bool = False) -> None:
    """``--print`` 模式的一行提醒；不含任何凭据值。"""
    print("\n⚠️ --print：下面会打印明文（%s），请勿截图/提交。" % names, file=sys.stderr)


def build_secret_items(out: dict, fmt: str,
                       plain_secrets: dict | None = None) -> list[tuple[str, str]]:
    """拆成 ``[(Secret 名称, 纯 Value), ...]``，每项单独进剪贴板。"""
    items: list[tuple[str, str]] = []
    if fmt == "split":
        for app, name in SPLIT_SECRET_NAME.items():
            if app in out:
                items.append((name, json.dumps(out[app], ensure_ascii=False, indent=2)))
    elif fmt == "env":
        text, _ = format_secrets(out, "env", {})
        for line in text.splitlines():
            name, _, value = line.partition("=")
            if name and value:
                items.append((name, value))
    elif out:  # single
        items.append(("SIGNIN_ACCOUNTS", json.dumps(out, ensure_ascii=False, indent=2)))
    for name, value in (plain_secrets or {}).items():
        items.append((name, value))
    return items


def copy_to_clipboard(text: str) -> tuple[bool, str]:
    """复制到系统剪贴板；零第三方依赖，按平台依次降级。"""
    if sys.platform == "win32":
        # base64 传参，避开 PowerShell 命令行/控制台代码页对中文的破坏。
        payload = base64.b64encode(text.encode("utf-8")).decode("ascii")
        script = ("$b=[Convert]::FromBase64String('%s');"
                  "$s=[Text.Encoding]::UTF8.GetString($b);Set-Clipboard -Value $s" % payload)
        if len(script) < 8000:
            try:
                done = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                                       "-Command", script], capture_output=True, timeout=15)
                if done.returncode == 0:
                    return True, "Windows 剪贴板（Set-Clipboard）"
            except (OSError, subprocess.SubprocessError):
                pass
        # 超长文本改走 stdin，并强制按 UTF-8 读取。
        script = ("[Console]::InputEncoding=[Text.Encoding]::UTF8;"
                  "$s=[Console]::In.ReadToEnd();Set-Clipboard -Value $s")
        try:
            done = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                                   "-Command", script], input=text.encode("utf-8"),
                                  capture_output=True, timeout=15)
            if done.returncode == 0:
                return True, "Windows 剪贴板（Set-Clipboard）"
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        for cmd in (["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"],
                    ["xsel", "--clipboard", "--input"]):
            try:
                done = subprocess.run(cmd, input=text.encode("utf-8"),
                                      capture_output=True, timeout=10)
                if done.returncode == 0:
                    return True, " ".join(cmd)
            except (OSError, subprocess.SubprocessError):
                continue
    try:
        import pyperclip
        pyperclip.copy(text)
        return True, "pyperclip"
    except Exception:
        pass
    try:
        import tkinter
        root = tkinter.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        root.destroy()
        return True, "tkinter"
    except Exception:
        pass
    return False, "没找到可用剪贴板"


def deliver_secrets(items: list[tuple[str, str]], *, wait_for_enter: bool) -> int:
    """依次复制「字段名 → 对应数据」，中间等回车；最后直接结束，不动剪贴板。"""
    if not items:
        print("没有可交付的 Secret。", file=sys.stderr)
        return 1
    if not wait_for_enter:
        ok, how = copy_to_clipboard(items[0][1])
        if not ok:
            print("❌ 剪贴板不可用（%s）；可加 --print 显式打印。" % how, file=sys.stderr)
            return 1
        if len(items) > 1:
            print("📋 %s 的数据已复制；其余用 --secret NAME 取，或加 --step 逐步复制。"
                  % items[0][0], file=sys.stderr)
        else:
            print("📋 %s 的数据已复制，直接 Ctrl+V 到 Value。" % items[0][0],
                  file=sys.stderr)
        return 0

    steps: list[tuple[str, str, str]] = []
    for name, value in items:
        steps.append((name, "字段名", name))
        steps.append((name, "数据", value))
    total = len(steps)
    print("\n共 %d 个 Secret：%s" % (len(items), "、".join(name for name, _ in items)),
          file=sys.stderr)
    print("GitHub → Settings → Secrets and variables → Actions，按提示粘 Name / Value。",
          file=sys.stderr)

    for idx, (name, kind, value) in enumerate(steps, 1):
        ok, how = copy_to_clipboard(value)
        if not ok:
            print("\n❌ 剪贴板不可用（%s）；为避免泄露明文已停止，可加 --print 显式打印。"
                  % how, file=sys.stderr)
            return 1
        target = "Name" if kind == "字段名" else "Value"
        print("📋 %d/%d  %s 的%s已复制 → 粘到 %s" % (idx, total, name, kind, target),
              file=sys.stderr)
        if idx == total:
            break
        print("   ⏎ 按回车复制下一个", file=sys.stderr, end="")
        try:
            input()
            print(file=sys.stderr)  # 管道 stdin 不回显回车，主动补一行保持提示整齐
        except (EOFError, KeyboardInterrupt):
            print("\n⚠️ 未检测到回车，已停止；剪贴板保留当前内容。", file=sys.stderr)
            return 1
    print("✅ 值已全部复制完，剪贴板保留最后一份数据。", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="导出平台凭据并生成 GitHub Secret 值")
    parser.add_argument("--mode", choices=("all", "single"), default="",
                        help="all=全部导出（默认）；single=只导一个软件并合并进已有配置")
    parser.add_argument("--source", default="",
                        help="single 模式的来源：%s" % ",".join(SOURCES))
    parser.add_argument("--label", default="",
                        help="single 模式的账号标签；同名替换、异名追加（多账号用）")
    parser.add_argument("--state", default="",
                        help="多账号本地镜像路径（默认：本脚本同目录的 accounts.local.json）")
    parser.add_argument("--no-state", action="store_true",
                        help="不读写本地镜像；single 模式只输出本次导出的账号")
    parser.add_argument("--only", default="",
                        help="只导出指定来源，逗号分隔：%s" % ",".join(SOURCES))
    parser.add_argument("--format", choices=("single", "split", "env"), default="",
                        help="Secret 格式；不填默认 single")
    parser.add_argument("--print", dest="print_values", action="store_true",
                        help="显式把 Secret 值打印到 stdout（明文可见，仅脚本/排障用）")
    parser.add_argument("--no-clip", action="store_true",
                        help="兼容旧用法：等价于 --print，明文会打印到终端")
    parser.add_argument("--step", action="store_true",
                        help="强制逐个字段等待回车（非 TTY / 脚本环境也生效）")
    parser.add_argument("--non-interactive", action="store_true", help="跳过导出菜单提问")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="跳过末尾「是否导出本地镜像文件」的询问，直接写文件（自动化用）")
    parser.add_argument("--confirm", action="store_true",
                        help="强制在末尾询问是否导出本地镜像文件（脚本环境需能提供 stdin）")
    parser.add_argument("--secret", default="",
                        choices=("SIGNIN_ACCOUNTS", "WORKBUDDY_REFRESH_TOKEN",
                                 "QODER_ACCOUNTS", "TRAE_ACCOUNTS", "DOUBAO_ACCOUNTS"),
                        help="只取指定 Secret 的纯 Value，便于一次 Ctrl+V")
    parser.add_argument("--qoder-intl", action="store_true",
                        help="兼容旧用法：把 --only qoder 换成国际版；全选时两个版本都导")
    args = parser.parse_args(argv)

    state_path = Path(args.state).expanduser() if args.state else STATE_PATH
    state_display = short_path(state_path)

    # 带明确参数的调用视为脚本化：不弹菜单、不等回车。
    # 单独给 --mode 仍允许继续交互（选软件、逐步复制）。
    scripted = bool(args.only or args.format or args.non_interactive or args.source
                    or args.print_values or args.no_clip or args.secret or args.step
                    or args.no_state)
    interactive = sys.stdin.isatty() and not scripted
    mode = args.mode or (choose_mode() if interactive else "all")
    if not mode:
        print("已取消，没有导出任何凭据。", file=sys.stderr)
        return 0

    if mode == "single":
        raw = args.source or (args.only.replace("，", ",").split(",")[0].strip()
                              if args.only else "")
        src = SOURCE_ALIASES.get(raw.lower(), raw.lower()) if raw else ""
        if not src and interactive:
            src = choose_one_source()
        if src not in SOURCES:
            print("⚠️ 单软件导出要指定来源：--source {%s}；或去掉 --mode single 走全部导出。"
                  % ",".join(SOURCES), file=sys.stderr)
            return 1
        selected = [src]
        fmt = "single"
        if args.label and src == "workbuddy":
            print("⚠️ WorkBuddy 多账号按手机号区分，--label 对它无效。", file=sys.stderr)
    else:
        if args.only:
            selected = [SOURCE_ALIASES.get(x.strip().lower(), x.strip().lower())
                        for x in args.only.replace("，", ",").split(",") if x.strip()]
        else:
            selected = list(SOURCES)  # 全部导出：默认本机所有来源，不再多问一轮
        fmt = args.format or "single"
    # 旧版 --qoder-intl：单独指定 qoder 时改导国际版；全选不动。
    if args.qoder_intl and "qoder" in selected and "qoder_intl" not in selected:
        selected = ["qoder_intl" if s == "qoder" else s for s in selected]
    if not selected:
        print("已取消，没有导出任何凭据。", file=sys.stderr)
        return 0

    accounts: dict = {}
    plain: dict = {}
    for src in selected:
        if src in SECRET_EXPORTERS:
            name, fn = SECRET_EXPORTERS[src]
            try:
                plain[name] = fn()
                print("✅ %s 凭据已读取" % SOURCE_LABEL[src], file=sys.stderr)
            except Exception as exc:
                print("⚠️ %s 导出失败：%s" % (SOURCE_LABEL[src], exc), file=sys.stderr)
            continue
        if src not in EXPORTERS:
            print("⚠️ 未知来源：%s（可选：%s）" % (src, ", ".join(SOURCES)), file=sys.stderr)
            continue
        try:
            acc = EXPORTERS[src]()
            app = APP_OF_SOURCE[src]
            accounts.setdefault(app, []).append(acc)
            if app == "trae" and not acc.get("device_id"):
                print("⚠️ Trae CN 凭据已读取，但设备号缺失：claim 会被跳过（不用 UUID 兜底）",
                      file=sys.stderr)
            elif app == "qoder" and not acc.get("machine_token"):
                print("⚠️ %s 缺少设备风控头，服务端可能静默不下发每日活动"
                      % SOURCE_LABEL[src], file=sys.stderr)
            else:
                print("✅ %s 凭据已读取" % SOURCE_LABEL[src], file=sys.stderr)
        except Exception as exc:
            print("⚠️ %s 导出失败：%s" % (SOURCE_LABEL.get(src, src), exc), file=sys.stderr)

    if not accounts and not plain:
        print("没有任何凭据导出成功，未生成 Secret 内容。", file=sys.stderr)
        return 1
    if mode == "single" and args.label:
        for accs in accounts.values():
            for acc in accs:
                acc["name"] = args.label

    final_accounts, final_plain = accounts, dict(plain)
    # 镜像写入推迟到全部值交付完、末尾单独确认之后：选「不导出」只是不落盘。
    pending_state: tuple[dict, dict] | None = None
    state_note = ""
    if mode == "all":
        # 全部导出 = 以本机为准重建镜像，供以后单软件增量导出合并。
        if not args.no_state:
            pending_state = (final_accounts, final_plain)
            state_note = ("💾 已保存本地镜像 %s（多账号合并用，含明文、已 gitignore）"
                          % state_display)
    else:
        if args.no_state:
            print("⚠️ --no-state：输出只含本次导出的账号，粘贴会覆盖 Secret 里其它账号。",
                  file=sys.stderr)
        else:
            state = load_state(state_path)
            if not state:
                print("❌ 找不到本地镜像 %s。" % state_display, file=sys.stderr)
                print("   先在这台机器跑一次「全部导出」，或把其它机器上的 "
                      "tools/accounts.local.json 拷过来；", file=sys.stderr)
                print("   确实只想用一个账号重建 Secret 时加 --no-state。", file=sys.stderr)
                return 1
            final_accounts = merge_accounts(state_accounts(state), accounts)
            merged_wb = merge_workbuddy(state_workbuddy(state),
                                        str(plain.get("WORKBUDDY_REFRESH_TOKEN") or ""))
            final_plain = ({"WORKBUDDY_REFRESH_TOKEN": merged_wb} if merged_wb else {})
            pending_state = (final_accounts, final_plain)
            state_note = "🔗 已按账号名合并进 %s（同名替换、异名追加）。" % state_display
        if selected[0] != "workbuddy":
            print("ℹ️ 同名账号会替换；想保留第二台设备/第二个账号，加 --label \"自定义名字\"。",
                  file=sys.stderr)

    if args.secret:
        value = single_secret_value(final_accounts, final_plain, args.secret)
        if not value:
            print("⚠️ 本次没有导出 %s 的内容（检查来源是否选对）" % args.secret,
                  file=sys.stderr)
            return 1
        items = [(args.secret, value)]
    elif mode == "single":
        # 只交付受影响的那一个 Secret，另外那个不用重新粘。
        if selected[0] == "workbuddy":
            items = [("WORKBUDDY_REFRESH_TOKEN",
                      final_plain.get("WORKBUDDY_REFRESH_TOKEN", ""))]
        else:
            items = [("SIGNIN_ACCOUNTS", json.dumps(final_accounts,
                                                    ensure_ascii=False, indent=2))]
    else:
        items = build_secret_items(final_accounts, fmt, final_plain)
    items = [(name, value) for name, value in items if value]
    if not items:
        print("没有可交付的 Secret 内容。", file=sys.stderr)
        return 1

    print_mode = bool(args.print_values or args.no_clip)
    if args.no_clip:
        print("⚠️ --no-clip 现等价于 --print：明文会打印到终端。", file=sys.stderr)
    if print_mode:
        # 只有显式要求时才输出明文；默认 stdout 保持空白。
        if args.secret or mode == "single":
            text, names = format_items(items), " / ".join(name for name, _ in items)
        else:
            text, names = format_secrets(final_accounts, fmt, final_plain)
        print_secret_guide(fmt, names, bool(final_plain))
        print(text)
        rc = 0
    else:
        # --secret 明确只要一个纯值，直接放进剪贴板，不走「字段名/数据」分步。
        rc = deliver_secrets(items, wait_for_enter=bool(args.step or interactive)
                             and not args.secret)

    # 最后一步：只问「要不要写本地镜像文件」，值已经全部交付完，选否不影响它们。
    if pending_state:
        need_confirm = not args.yes and (args.confirm or (
            sys.stdin.isatty() and not args.non_interactive))
        write_state = (confirm_file_export(state_display, state_items(*pending_state))
                       if need_confirm else True)
        if write_state:
            if save_state(pending_state[0], pending_state[1], state_path):
                print(state_note, file=sys.stderr)
        else:
            print("ℹ️ 已跳过本地镜像文件；剪贴板内容照常粘到 GitHub 即可。", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
