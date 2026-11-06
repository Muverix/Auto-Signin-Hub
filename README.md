# 🌱 每日签到融合 · Auto Signin Hub

> WorkBuddy 每日领取 + Qoder（CN / 国际版）+ Trae CN + 豆包签到，
> 统一跑在 GitHub Actions 上。配置一次，不用服务器，也不用一直开着电脑。

![Python](https://img.shields.io/badge/Python-3.11-blue)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Automation-2088FF)
![License](https://img.shields.io/badge/License-MIT-green)

| 平台 | 每天自动做什么 |
| --- | --- |
| WorkBuddy | 每日领取、成长任务、自动领奖，Refresh Token 自动续期 |
| Qoder CN / 国际版 | 每日 100 Credits，两个版本各自独立账号 |
| Trae CN | 每日签到积分 |
| 豆包 | 签到领额度 + 清扫任务奖励 |

默认北京时间 **07:00 / 10:05 / 12:00 / 23:30** 各跑一次，其中 10:05 对应 Qoder
每日活动 10:00 的刷新窗口。四个平台的领取接口都幂等，多跑不会多领；某个平台失败
不影响其它平台。可选 PushPlus 微信推送汇总结果。

> 前身是只覆盖 WorkBuddy 的 [gdemoni/workbuddy-Auto](https://github.com/gdemoni/workbuddy-Auto)，
> 融合四平台后更名为「每日签到融合 · Auto Signin Hub」（见 [致谢](#thanks)）。
> 只想跑 WorkBuddy 也完全可以：不填 `SIGNIN_ACCOUNTS`，另外三个平台会自动跳过。

**目录**：[快速上手](#quickstart) · [两个 Secret](#secrets) · [本机导出工具](#export) ·
[多账号](#multi) · [运行原理](#how) · [凭据维护](#refresh) · [仓库结构](#files) ·
[注意事项与 FAQ](#faq) · [许可证](#license) · [致谢](#thanks)

---

<a id="quickstart"></a>
## 🚀 快速上手

### 1. 建私有仓库 + 开写权限

`fork`，可见性必须选 `Private`。
再到 `Settings → Actions → General → Workflow permissions` 选
`Read and write permissions` 并保存 —— 工作流要把续期后的 Token 写回仓库。

### 2. 在本机导出凭据

Actions 是 Linux 容器，**没有桌面客户端**，登录态解密只能在本机完成：

```bash
pip install cryptography          # 仅本机解密需要，Actions 不用装
python tools/export_secrets.py
```

工具默认**不在终端显示任何凭据**，直接按「字段名 → 数据」逐段放进剪贴板，照屏幕
提示粘到 GitHub 即可。详见 [本机导出工具](#export)。

### 3. 填 Secret

`Settings → Secrets and variables → Actions → New repository secret`，最多 2 个：

| Name | Value | 什么时候需要 |
| --- | --- | --- |
| `SIGNIN_ACCOUNTS` | 完整 JSON（数组天然支持多账号） | 想跑 Qoder / Trae CN / 豆包 |
| `WORKBUDDY_REFRESH_TOKEN` | 每行一个 `手机号:AT:RT` | 想跑 WorkBuddy |

可选第三个 `PUSHPLUS_TOKEN`（微信通知）。格式要求见 [两个 Secret](#secrets)。

### 4. 跑一次

`Actions → Auto Signin Hub → Run workflow`。首次建议勾上 `dry_run`、`apps` 填
`qoder` 先空跑，看到绿色对勾就部署完成 🎉。之后按设定时间自动运行，不用保持开机。

本地等价命令：

```bash
python run_all.py --only qoder --dry-run     # 只查状态、不领取
python run_all.py --only qoder               # 真跑一个平台
python run_all.py                            # 全流程
python run_all.py --strict                   # 任一平台异常就返回非 0（默认总是 0）
```

结果会同时出现在日志、Job Summary 表格和 PushPlus 推送里。

---

<a id="secrets"></a>
## 🔑 两个 Secret

> ⚠️ **别把「有本地文件」理解成「不用填键值对了」**：`tools/accounts.local.json`
> 只是本机的合并缓存，云端 Actions 读不到它。两个 Secret 的 Name / Value **仍然
> 要粘到** GitHub。省掉的是「每加一个账号就新建一个 Secret」，不是 Secret 本身 ——
> 永远只有 2 个键。

### `SIGNIN_ACCOUNTS`

必须是**合法 JSON**（不能有注释、尾逗号或 JSONC），顶层是对象，键为 `qoder` /
`trae` / `doubao`，值是账号对象数组；字段名一律小写。GitHub Secret 支持多行文本，
直接粘贴，**不要给整个 JSON 再套一层引号**。模板见
[`signin/accounts.example.json`](signin/accounts.example.json)。

```json
{
  "qoder": [
    {"name": "Qoder CN", "token": "...", "base_url": "https://openapi.qoder.com.cn", "machine_token": "..."},
    {"name": "Qoder 国际版", "token": "...", "base_url": "https://openapi.qoder.sh", "machine_token": "..."}
  ],
  "trae": [{"name": "主号", "token": "...", "device_id": "aha-..."}],
  "doubao": [{"name": "主号", "cookie": "sessionid=...; sid_tt=..."}]
}
```

| 平台 | 必填 | 选填 | 凭据来源 |
| --- | --- | --- | --- |
| Qoder CN / 国际版 | `token`、`base_url` | `machine_token/code/type/id/os/hostname/version` | 各自 `auth.v1.dat` 解密（CN `com.qodercn.app*` / 国际版 `com.qoder.app*`） |
| Trae CN | `token`、`device_id` | `app_version`、`device_brand/type`、`os_version` | `storage.json` 的 SS_AES 信封 + `icube-dc:` 键名里的设备号 |
| 豆包 | `cookie` | `campaign_code` | Chromium Cookie 库（`sessionid` / `sid_tt` / `uid_tt`） |

没导出的平台不写进 JSON 就行，运行时自动跳过。`qoder` 数组里可以放多个账号，
CN 和国际版各自用自己的 `base_url`，互不串号。

> **Trae 设备号有两种形态**：旧版 `iCubeAuthInfo://icube-dc:<8-20 位纯数字>`，
> 新版 `iCubeAuthInfo://icube-dc:aha-<32位hex>`。`telemetry.devDeviceId` 是 36 位
> UUID，实测会触发 9074 风控，**导出工具不会拿它兜底**：找不到真实设备号就输出空
> `device_id` 并提示，运行侧跳过 claim（status 只读查询照常）。确实要强行发送，
> 可在该账号里加 `"allow_unsafe_device_id": true`。

### `WORKBUDDY_REFRESH_TOKEN`

一行 `手机号:AT:RT`，多个账号换行分隔：

```text
13800138000:AT1:RT1
13900138000:AT2:RT2
```

首次运行后 `signin/workbuddy.py` 会自动续期并把状态存进私有仓库，之后不必反复更新
（见 [凭据维护](#refresh)）。

### 其它格式（排障用）

`--format split` 生成 `QODER_ACCOUNTS` / `TRAE_ACCOUNTS` / `DOUBAO_ACCOUNTS`
三段（各是一个 JSON 数组，需分别新建 Secret）；`--format env` 生成
`QODER_TOKEN` / `TRAE_TOKEN` / `DOUBAO_COOKIE`（含 `TRAE_DEVICE_ID` 等补充）。
日常只用默认的「一个 JSON」即可，运行侧 `common.load_config()` 本来就按数组遍历。

---

<a id="export"></a>
## 🖥️ 本机导出工具

`tools/export_secrets.py` 只读本机客户端的登录态文件，不联网、不改写客户端状态。
五个来源：`WorkBuddy` / `Qoder CN` / `Qoder 国际版` / `Trae CN` / `豆包`；
没装或没登录的自动跳过，不影响其它来源。

工具只问**两件事**：

| 时机 | 问什么 |
| --- | --- |
| 开头 | 导出方式：`1` 全部导出（推荐，一台设备一个账号）/ `2` 单个软件导出 / `0` 取消整个流程 |
| 全部值交付完之后 | 是否把本地镜像文件写到磁盘：`1` 导出（默认）/ `0` 不导出 |

**末尾那一问的 `0` 只表示「不导出文件」，不是取消流程** —— 剪贴板的值照常复制
粘贴完，两个 Secret 照常粘到 GitHub，结果完全一样。

### 剪贴板流程

不打印任何凭据内容，按「字段名 → 数据 → 下一个 Secret」逐段复制；粘完一段按
**回车**复制下一段（全部导出 4 步 / 3 次回车，单个软件导出只涉及一个 Secret，
就是 2 步 / 1 次回车）：

```text
📋 1/4  SIGNIN_ACCOUNTS 的字段名已复制 → 粘到 Name
   ⏎ 按回车复制下一个
📋 2/4  SIGNIN_ACCOUNTS 的数据已复制 → 粘到 Value
   ⏎ 按回车复制下一个
📋 3/4  WORKBUDDY_REFRESH_TOKEN 的字段名已复制 → 粘到 Name
   ⏎ 按回车复制下一个
📋 4/4  WORKBUDDY_REFRESH_TOKEN 的数据已复制 → 粘到 Value
✅ 值已全部复制完，剪贴板保留最后一份数据。
```

结束时**不会自动清理剪贴板**（想覆盖随手复制点别的内容即可）。后端走 Windows
`Set-Clipboard` / macOS `pbcopy` / Linux `xclip` / `wl-copy`；剪贴板不可用时
**不会退化成打印明文**，会报错并提示改用 `--print`。

### 末尾的文件询问

```text
──────── 是否导出本地镜像文件？ ────────
文件：tools/accounts.local.json（导出脚本同目录）
将保存 2 个 Secret 的完整值（明文，不显示内容）：
  · SIGNIN_ACCOUNTS            qoder 2 个账号、trae 1 个账号
  · WORKBUDDY_REFRESH_TOKEN    1 个账号（每行一个 手机号:AT:RT）
选「否」只是不写这个文件，上面的剪贴板内容照常粘到 GitHub。
  1) 导出文件（默认）
  0) 不导出文件
```

文件按**导出脚本自己的所在目录**（`Path(__file__).resolve().parent`）定位，
不写死绝对地址，提示里也只显示相对路径或文件名。它含明文、已 gitignore，
纯粹是本机多账号合并用的缓存；单账号或不想在磁盘留痕时可以不要它。
`--state` 可改路径，`--no-state` 完全不读写也不问。

### 常用参数

```bash
# 全部导出：跳过菜单，仍逐步等回车
python tools/export_secrets.py --mode all --only workbuddy,qoder,qoder_intl,trae --step
# 单个软件导出：换一个软件的 token，其它账号原样保留
python tools/export_secrets.py --mode single --source qoder
# 给第二台设备/第二个账号加一份（换标签 = 追加，不覆盖原账号）
python tools/export_secrets.py --mode single --source qoder --label "Qoder CN@办公室"
python tools/export_secrets.py --secret WORKBUDDY_REFRESH_TOKEN   # 剪贴板只放这一个纯值
python tools/export_secrets.py --print                            # 排障：显式打印明文到 stdout
python tools/export_secrets.py --mode all --step --yes            # 跳过末尾询问，直接写镜像
python tools/export_secrets.py --mode all --no-state              # 不写镜像，值照常复制粘贴
```

带参数时不弹菜单；脚本化调用默认直接写镜像、不弹末尾询问，`--confirm` 可强制问、
`--yes` 可明确跳过（`--yes` 优先）。非终端环境下剪贴板一次只能放一个值，只放第一个，
其余用 `--secret NAME` 分别取或加 `--step`。只有显式 `--print`（旧写法
`--no-clip`）才会把明文打印到终端 —— 请确认无人旁观、不要截图。

### 来源与限制

- **WorkBuddy**：读 `%LOCALAPPDATA%\CodeBuddyExtension\...\workbuddy-desktop.info`，
  遇到 `$wbEncrypted` 借客户端 Electron 运行时解出 AT / RT / 手机号。
- **Qoder**：`auth.v1.dat`（DPAPI → AES-256-GCM）+ 各版本自带的
  `umid/runtime-info.exe` 设备风控头。解密依赖 Windows DPAPI，所以这一项
  自动读取**仅支持 Windows**；其它系统请按模板手动填 `token` 与 `machine_*`
  （运行侧不限制平台）。需要时可用 `QODER_UMID_EXE` 指定某版本的组件路径。
- **Trae CN / 豆包**：`storage.json` 的 SS_AES 信封、Chromium v10 Cookie。

导出的是**静态凭据**：客户端重新登录或令牌过期后要重新导出并覆盖 Secret。

---

<a id="multi"></a>
## 👥 多账号

**推荐：一个 JSON / 一个 Secret 装全部账号（数组），不用「每个账号一个 Secret」。**

- GitHub Secret **只能覆盖、不能查看**。拆成 `QODER_TOKEN_1`、`QODER_TOKEN_2`…
  之后既看不到旧值，又要在 workflow 里预先枚举所有名字，加账号就得改工作流，
  删账号还会留下没人知道的残留。
- 运行侧本来就是按数组遍历的，`run_all.py` 会打印「N 个账号」逐个执行，
  **不用改任何运行代码**。
- 一份 JSON 可以整体备份、整体替换，也容易核对少了哪个账号。

本地镜像 `tools/accounts.local.json` 用来在多次导出之间合并账号：

| 操作 | 镜像行为 | 交付到剪贴板 |
| --- | --- | --- |
| **全部导出** | 以这台机器为准**重建** | 两个 Secret 都重新粘 |
| **单个软件导出** | 读旧镜像 → 按 `name` 合并（同名替换、异名追加）→ 写回 | 只粘受影响的**那一个** Secret |
| 末尾选「不导出文件」/ `--no-state` | 不写镜像（single 仍会读旧镜像来合并） | 与上面完全相同 |

- `WORKBUDDY_REFRESH_TOKEN` 按手机号合并：同号替换、异号追加。
- 给第二台设备加账号用 `--label` 换个名字就会追加；不加 `--label` 则替换同名账号
  （适合 token 过期后重新导出）。把 `tools/accounts.local.json` 拷到那台机器即可
  继续增量维护。
- 单软件导出**找不到本地镜像会直接报错停止**，避免把「只含一个账号」的 JSON
  粘上去冲掉其它账号。先跑一次「全部导出」，或把镜像拷过来。
- 镜像含明文，不要提交、不要同步到公开网盘。

---

<a id="how"></a>
## 🧩 运行原理

Qoder / Trae CN / 豆包 的签到逻辑已抽成纯 HTTP 模块，去掉本机客户端依赖，与
WorkBuddy 一起由根目录的 `run_all.py` 统一调度。

| 平台 | 服务端接口 | 幂等策略 |
| --- | --- | --- |
| WorkBuddy | 见 `signin/workbuddy.py` | 先查状态，未签才领；RT 自动续期 |
| Qoder | `GET /sash/api/v1/me/campaigns` → `POST .../{id}/claim` | 只领 `claimStatus=CLAIMABLE` |
| Trae CN | `POST /trae/api/v2/ug/checkin_credits/status` → `/claim` | 已签跳过；领后复查 status |
| 豆包 | `POST /alice/ug/campaign/landing/checkin/` → `/v3/detail/` → `/item/reward/claim/` | 服务端 `idempotent` 判定 |

抽取时保留的关键契约：Qoder 的 `Cosy-ClientType: 10` 与设备风控头、Trae 的
`x-device-id` 与 9074 限流退避、豆包的七个 AGW 公共参数与 32 字节 Cookie 值前缀、
写操作不重试、全程脱敏。公共重试 / 预算 / 结果模型 / 汇报都在 `signin/common.py`。

- **失败隔离**：一个平台挂了不影响其它平台；默认退出 0，保证末尾的
  「持久化续期 Token」步骤不被跳过，需要红灯时加 `--strict`。
- **dry-run**：只查状态不领奖，本地 `--dry-run` 或 Actions 的 `dry_run` 输入。
- **报告**：日志 + Job Summary 表格 + 可选 PushPlus 推送（只发一次）。

---

<a id="refresh"></a>
## 🔄 凭据维护

**WorkBuddy 不用天天换**。首次运行从 `WORKBUDDY_REFRESH_TOKEN` 读取账号 →
自动刷新 → 生成 `wb_refresh_tokens.json` → 保存最新 Token → 下次继续使用。
首次成功后工作流优先读私有仓库里的这个文件并持续更新，正常情况下 Secret
只需配置一次；只有认证彻底失效时才需要重新导出。

`wb_refresh_tokens.json` 必须是**标准 JSON**（不能有 `//` / `#` 注释）：

```json
{
  "手机号1": {"refresh_token": "RT1", "access_token": "AT1"},
  "手机号2": {"refresh_token": "RT2", "access_token": "AT2"}
}
```

多个账号写在**同一个最外层对象**里，除最后一个节点外每个 `}` 后都要加英文逗号，
不要把两个带外层 `{}` 的 JSON 首尾拼接。带注释的模板见
[`signin/wb_refresh_tokens.example.jsonc`](signin/wb_refresh_tokens.example.jsonc)。

**另外三个平台会过期**：Trae JWT 约 20 天、豆包 Cookie 会话更短、Qoder 风控头
是静态快照。报 `AUTH_REJECTED` / `NO_AUTH` 时，在电脑上重新登录客户端并重跑导出
工具，覆盖 `SIGNIN_ACCOUNTS` 即可。

---

<a id="files"></a>
## 📁 仓库结构

```text
.github/workflows/daily.yml         GitHub Actions 工作流（一天四次触发）
run_all.py                         唯一入口：四平台调度、失败隔离、汇总、推送
signin/
  ├─ common.py                    零依赖 HTTP / 结果 / Secrets / 汇报
  ├─ qoder.py / trae.py / doubao.py   三个平台的纯云端签到
  ├─ workbuddy.py                WorkBuddy 主程序（续期 / 任务 / 领奖）
  ├─ accounts.example.json       SIGNIN_ACCOUNTS 字段模板
  └─ wb_refresh_tokens.example.jsonc   WorkBuddy 多账号状态示例
tools/
  ├─ export_secrets.py           本机一次性凭据导出（不参与 Actions）
  └─ accounts.local.json         本机多账号镜像（gitignored，不提交）
tests/                            离线契约测试：python -m unittest discover -s tests
requirements.txt / LICENSE
```

仓库不依赖任何桌面客户端源码目录，也没有 `vendor/` 第三方文件：导出工具需要的
Qoder 登录态解密与 umid 风控头已裁成几个函数写进 `tools/export_secrets.py`
（源自 [88lin/workbuddy-auto-signin](https://github.com/88lin/workbuddy-auto-signin)，
MIT 授权声明见 `LICENSE` 末尾）。

---

<a id="faq"></a>
## ⚠️ 注意事项与 FAQ

- 运行仓库**必须保持 `Private`**；不要公开手机号、AT、RT 或 `wb_refresh_tokens.json`，
  不要把真实 Token 写进 README、脚本或工作流文件。
- 不要让多个仓库同时跑同一个账号，否则续期 Token 会互相覆盖；换仓库前先停用旧的
  Actions。
- **Qoder 风控头是静态快照**：`machine_token/code/type` 由本机 umid 组件生成，
  云端无法生成；服务端对缺头请求**静默不下发**每日活动（不报错）。脚本检测到缺头
  会标 ⚠️，客户端升级后可能需要重新导出。
- **接口是逆向得来的**，服务端改版可能失效。端点与字段集中在
  `signin/qoder.py` / `signin/trae.py` / `signin/doubao.py` 顶部，改一处即可，
  公共重试 / 脱敏逻辑不用动。

<details>
<summary><strong>为什么有些桌面任务没有执行？</strong></summary>

GitHub Actions 使用 Linux 容器，只能在 Windows 桌面端完成的任务会自动跳过，
云端任务仍正常运行。

</details>

<details>
<summary><strong>导出工具提示找不到认证文件？</strong></summary>

先打开对应桌面客户端并登录、进入主界面，再重跑 `python tools/export_secrets.py`。
导出工具跑不通时，也可以按 `signin/accounts.example.json` 手动填字段。

</details>

<details>
<summary><strong>以后还需要重新添加 Token 吗？</strong></summary>

WorkBuddy 通常不需要（RT 自动续期）；Qoder / Trae CN / 豆包的凭据过期后
重新导出并覆盖 `SIGNIN_ACCOUNTS` 即可。

</details>

---

<a id="license"></a>
## 📄 许可证

本项目采用 [MIT License](LICENSE)。`tools/export_secrets.py` 中的 Qoder 登录态解密
部分改编自 [88lin/workbuddy-auto-signin](https://github.com/88lin/workbuddy-auto-signin)
（MIT），完整第三方授权声明见 `LICENSE` 末尾。

<a id="thanks"></a>
## 🙏 致谢

本仓库是在原项目基础上融合扩展而来的，感谢原作者与各位上游作者：

| 项目 | 作者 | 本仓库用到的部分 |
| --- | --- | --- |
| [`gdemoni/workbuddy-Auto`](https://github.com/gdemoni/workbuddy-Auto)（原仓库） | [@gdemoni](https://github.com/gdemoni)；版权所有者 [@L0NE-6](https://github.com/L0NE-6)（另见 [`L0NE-6/WorkBuddy-Daily`](https://github.com/L0NE-6/WorkBuddy-Daily)） | WorkBuddy 每日领取、成长任务、Token 自动续期与 Actions 模板 —— 即本仓库的前身 |
| [`88lin/workbuddy-auto-signin`](https://github.com/88lin/workbuddy-auto-signin) | [@88lin](https://github.com/88lin) | Qoder 登录态解密（`auth.v1.dat` / DPAPI / AES-GCM）与 umid 设备风控头 |
| `auto-signin-kit` | auto-signin-kit contributors | Trae CN / 豆包 的接口契约与逆向取证资料 |

原项目的 MIT 版权声明保留在 `LICENSE` 中；Qoder 部分的第三方授权声明见 `LICENSE` 末尾。

如果这个项目帮你省下了一点时间，欢迎点个 ⭐。
