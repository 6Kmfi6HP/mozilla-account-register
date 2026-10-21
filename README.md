# Mozilla 账号注册机

针对 **Mozilla 账号（Mozilla Accounts / 原 Firefox Accounts）** 的批量自动注册 CLI。

提供**两个注册后端**：

- **API 后端（默认）**：纯 HTTP onepw 协议。客户端派生 `authPW` → `POST /account/create` → 从临时邮箱自动取验证码 → `POST /recovery_email/verify_code` 完成验证，并可为每个验证成功账号写出 fxpool 凭据包。
- **浏览器后端（`--backend browser`）**：cloakbrowser 走真实注册页，绕过生产 WAF；它还能从 `localStorage` 采集 FxA 会话。两个后端都可把验证后的会话桥接给 [fxpool-proxy](https://github.com/6Kmfi6HP/firefox-ip-protection-pool-go)，浏览器后端还可选完成一次性开通。

## 特性

- ✅ 接入 **Cloud Mail 临时邮箱 API**（无需预创建邮箱，随机生成 `用户名@域名`）
- ✅ **自动获取验证码并自动验证**，全程无需人工介入
- ✅ 批量注册：文本邮箱列表 或 自动生成邮箱 + 随机密码
- ✅ 多线程并发 + 错峰启动，输出逐行 fsync 落盘不丢
- ✅ `authPW` 派生与 Mozilla 官方 onepw v1 协议字节级一致（已用官方测试向量验证）
- ✅ **浏览器后端**按当前线上流程注册：邮箱 → 设置密码 → `Create account` → 6 位验证码 → `/settings`；密码框被 `input-label` 覆盖，自动使用 `force=True` 填充
- ✅ 账号在服务端创建后**立即落盘** `email----password`，验证码迟到/失败也不会丢账号
- ✅ 登录已有账号（`--signin`）时先快照邮箱，只接受新到达的验证码，避免旧注册码误用
- ✅ 支持 `/signin_unblock` 的 8 位字母数字授权码（风控拦截场景）
- ✅ 从 `localStorage["__fxa_storage.accounts"]` 采集 FxA 会话（不依赖 cookies / Firefox profile）
- ✅ 可选一次性开通（`--enroll`），并写出 fxpool-proxy 可直接消费的凭据包 / `renewal_credentials.json`

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置（把 config.example.json 复制为 config.json 并填邮箱服务信息）
cp config.example.json config.json

# 3. 干跑：校验配置 + 测试 authPW 派生，不发网络请求
python register.py --dry-run

# 4. 注册 3 个账号（API 后端，自动生成临时邮箱 + 随机密码）
python register.py --count 3

# 5. 从文件批量注册
python register.py --emails emails.txt --threads 2

# 6. API 后端批量注册并为每个账号写入 fxpool 凭据包
python register.py --emails emails.txt --threads 2 --bundle-dir fxpool-bundles

# 7. 浏览器后端（绕过生产 WAF；需先装 cloakbrowser）
pip install cloakbrowser
python register.py --backend browser --count 1

# 8. 浏览器后端 + 开通 + 为 fxpool-proxy 写凭据包
python register.py --backend browser --count 1 --enroll --bundle-dir fxpool-bundles

# 9. 注册机与代理同机：直接写 <root>/tokens/renewal_credentials.json
python register.py --backend browser --count 1 --enroll --fxpool-root ~/.fxpool

# 10. 已有账号：只登录生成会话/凭据，不创建新账号
python register.py --backend browser --signin --emails accounts_20261021_120000.txt \
  --enroll --fxpool-root ~/.fxpool

# 11. 用 emailnator 临时 Gmail 收码（config.json 里 email_provider=emailnator）
python register.py --backend browser --count 3
```

## 配置

复制 `config.example.json` 为 `config.json`。核心字段：

| 字段 | 必填 | 说明 |
|------|------|------|
| `email_provider` | 是 | `cloudmail`（默认）或 `emailnator`（临时 Gmail） |
| `cloudmail_api_base` | 是 | Cloud Mail 服务地址（`cloudmail` 时必填） |
| `cloudmail_public_token` | 是 | Cloud Mail 公共 Token（`cloudmail` 时必填） |
| `cloudmail_domains` | 是 | 收件域名，逗号分隔（随机轮换生成邮箱） |
| `cloudmail_path_messages` | 否 | 邮件列表接口路径，默认 `/api/public/emailList` |
| `emailnator_script` | 否 | emailnator CLI 路径，默认 `~/.claude/skills/emailnator/emailnator.py` |
| `emailnator_proxy` | 否 | emailnator 专用代理（优先级高于 `proxy` / `$EMAILNATOR_PROXY`；该后端强制走代理） |
| `emailnator_state_dir` | 否 | 每个邮箱一个状态文件（旧邮件基线 + 已用验证码）的目录，默认 `~/.emailnator/states`。**不要改成共享文件**：并发注册会丢基线 |
| `emailnator_code_pattern` | 否 | `wait-code` 的严格提取正则（含捕获组），默认只匹配 `Use 123456 to confirm your account` / `confirmation code: 123456`；空串退回 CLI 通用规则（营销邮件会被误判） |
| `auth_base` | 否 | Mozilla Auth Server，默认 `https://api.accounts.firefox.com/v1` |
| `proxy` | 否 | HTTP 代理（批量高频时建议用代理池） |
| `browser_proxy` | 否 | 浏览器后端专用代理（优先级：`browser_proxy` > `proxy` > `$BROWSER_PROXY`）。**批量注册必填**——FxA 按出口 IP 限速 |
| `register_backend` | 否 | `api`（默认）或 `browser` |
| `register_count` | 否 | 自动生成邮箱时注册数量 |
| `register_threads` | 否 | 并发线程数 |
| `register_max_attempts` | 否 | 单个账号被限速时的最大重试次数（每次重试换邮箱 + 换出口 IP），默认 10 |
| `mail_timeout` | 否 | 等待验证码超时（秒） |
| `mail_poll_interval` | 否 | 邮箱轮询间隔（秒） |
| `mail_retry_count` | 否 | emailnator CLI 传输层失败（SSL 断连/超时）的重试次数，默认 3 |
| `account_hard_timeout` | 否 | 单个账号的总时长上限（秒），默认 900；限速重试受它约束 |
| `emails_file` | 否 | 邮箱列表文件路径（也支持 `--emails` CLI 参数） |
| `fxpool_enroll` | 否 | 注册/登录后执行一次性开通（仅浏览器后端；等价 `--enroll`） |
| `fxpool_root` | 否 | 写入 `<PATH>/tokens/renewal_credentials.json`（仅浏览器后端；等价 `--fxpool-root`；也可用环境变量 `FXPOOL_ROOT`） |
| `bundle_dir` | 否 | 为每个验证成功的账号写 `<DIR>/<uid>.json` 凭据包（API 和浏览器后端；等价 `--bundle-dir`，空=关闭） |

`fxpool_enroll` / `fxpool_root` 只在浏览器后端生效。`bundle_dir` 在两个后端都生效；
`--no-bridge` 可在任一后端关闭凭据发布。API 后端会忽略 `fxpool_root`，但
`fxpool_enroll=true` 与 `register_backend=api` 同时出现会直接报配置错误。

## 命令行

```
python register.py [选项]
  --config PATH        配置文件路径（默认 config.json）
  --count N            注册数量（覆盖配置）
  --emails FILE        邮箱列表文件（--signin 时每行 email----password）
  --threads N          并发线程数（覆盖配置）
  --out FILE           账号输出文件（默认 accounts_<时间戳>.txt）
  --backend X          api | browser（默认 api；browser 需安装 cloakbrowser）
  --enroll             注册/登录后执行一次开通（每账号仅一次，不重试）
  --fxpool-root PATH   写入 <PATH>/tokens/renewal_credentials.json
  --bundle-dir DIR     为每个账号写 <DIR>/<uid>.json 凭据包
  --no-bridge          不写凭据包与 renewal_credentials.json
  --signin             只登录已有账号生成会话，不创建账号
  --dry-run            只校验配置与 authPW 派生，不发网络请求
```

> 提示：若生产 API 被 WAF 拦截（HTTP 406），请改用 `--backend browser`。
`--enroll`、`--fxpool-root`、`--signin` 只能与 `--backend browser` 一起使用；
`--bundle-dir` 与 `--no-bridge` 两个后端都支持。

### 登录已有账号（`--signin`）

`--signin` 读取的每行格式为 `email----password`（按第一个 `----` 分割，密码
本身可以再包含 `----`）。本工具写出的 `accounts_<时间戳>.txt` 每行末尾还有
第三个字段（`browser-verified`、`created-unverified` 或 API 后端的 32 位 uid），
该字段会被自动识别并忽略，因此生成的文件可以直接回喂给 `--signin`。

登录时会在提交密码前快照邮箱里已有的邮件 id，只接受之后到达的新验证码；
如果 FxA 把登录路由到 `/signin_unblock`，则按 8 位字母数字授权码解析。

## 输出

- **账号**：`accounts_<YYYYMMDD_HHMMSS>.txt`，格式 `邮箱----密码----extra`
  - 浏览器后端在点击 `Create account` 后立即写 `created-unverified`，整个浏览器
    流程成功返回后原地更新为 `browser-verified`；
  - API 后端 extra 为账号 uid。
- **邮箱凭证**：`mail_credentials.txt`，格式 `邮箱\t凭证`（可回读）。
- **凭据包**（可选，API/浏览器后端）：`<bundle_dir>/<uid>.json`，键恰好为
  `schema/email/uid/session_token`，权限 0600。
- **fxpool 凭据**（可选）：`<fxpool_root>/tokens/renewal_credentials.json`，
  紧凑 JSON、`schema` 为数字 1、权限 0600，目录 0700。

## 模块结构

```
mozilla-account-register/
├── register.py           # CLI 入口：批量编排、并发、参数解析、后端分派
├── register_mozilla.py   # API 后端单账号注册（派生→创建→取码→验证）
├── register_browser.py   # 浏览器后端（注册/登录、会话采集、一次性开通）
├── fxpool_bridge.py      # 凭据包 + renewal_credentials.json 发布（纯标准库）
├── mozilla_api.py        # Auth Server v1 客户端（/account/create、verify_code）
├── mozilla_crypto.py     # onepw v1 派生（PBKDF2 1000 轮 + HKDF）
├── mail_service.py       # cloudmail 邮箱 API + 验证码提取
├── account_outputs.py    # 账号/邮箱凭证输出
├── app_config.py         # 配置加载/校验
├── app_paths.py          # 可移植路径
├── docs/api-flow.md      # Mozilla 注册 API 流程与参数文档
└── tests/                # 单元测试（含官方 onepw 测试向量）
```

## 工作原理

### API 后端

```
[邮箱生成] cloudmail 随机生成 email@domain
   │
   ▼
[authPW 派生] PBKDF2-SHA256(password, "identity.mozilla.com/picl/v1/quickStretch:{email}", 1000轮)
   │                 HKDF-SHA256(quickStretched, salt=空, info=".../authPW")
   ▼
[创建账号]  POST https://api.accounts.firefox.com/v1/account/create  {email, authPW, service}
   │                 → { uid, sessionToken }，同时发 6 位验证码邮件
   ▼
[取验证码]  cloudmail 轮询收件箱 → extract_verification_code() 提取 6 位数字
   │
   ▼
[验证邮箱]  POST /recovery_email/verify_code  {uid, code}  → 账号 verified
   │
   ▼
[输出]      accounts_<时间戳>.txt: email----password----uid
```

### 浏览器后端（无 Firefox）

```
[启动] cloakbrowser 反检测浏览器（绕过 Fastly Client Challenge）
   │
   ▼
[注册页] /signup 填邮箱 → 提交
   │
   ▼
[密码页] input[name=newPassword]（force fill）→ 点 "Create account"
   │         账号在服务端创建，同时发送 6 位验证码邮件
   │         立即写入 accounts_<时间戳>.txt: email----password----created-unverified
   ▼
[验证码] cloudmail 取码 → input[name=code]（force fill）→ Confirm
   │         成功后落到 /settings（唯一成功信号），账号行更新为 browser-verified
   ▼
[采集会话] localStorage["__fxa_storage.accounts"]
   │         → uid（32 hex）+ sessionToken（64 hex）
   ▼
[可选开通] 一次 GET https://vpn.mozilla.org/api/v1/fpn/auth
   │         自动 302 到 /oauth/success，正文为权益 JSON
   │         （每账号只尝试一次；429 不重试）
   ▼
[可选桥接] fxpool_bridge → <bundle_dir>/<uid>.json
   │                     和/或 <fxpool_root>/tokens/renewal_credentials.json
   ▼
[输出]    accounts_<时间戳>.txt: email----password----browser-verified
```

> 验证码输入框与密码框一样可能被 `input-label` 覆盖，两处都使用
> `force=True`。登录路径会先快照邮箱中的旧邮件，避免把上一次注册的验证码
> 当成新的登录码提交。

### 出口 IP 限速（批量注册必读）

FxA 对注册接口按**出口 IP** 限速：同一 IP 反复注册会看到
`You've tried too many times. Please try again in a day.`。
这不是账号问题，换 IP 就能继续。

处理方式：

- `browser_proxy`（或 `proxy` / `$BROWSER_PROXY`）给浏览器指定代理。
  SOCKS5 代理每条新连接换一个出口 IP，所以**每次重试都会自动换 IP**。
- 命中限速文案时抛 `SignupRateLimited`；注册页出现 `Unexpected error` 被弹回
  首页时抛 `SignupNotCreated`。两者都发生在"账号在服务端建好"之前，
  `register.py` 捕获后**换一个临时邮箱**重试（服务端没有为上一个邮箱建号），
  最多 `register_max_attempts` 次，且总时长受 `account_hard_timeout` 约束。
- 账号只有在落到 `/settings`（验证码通过）后才会被标成 `browser-verified`。
  限速/校验失败发生在到达验证码页之前，账号不存在，也不会写进结果文件。
- emailnator CLI 偶发 `curl: (35) SSL_ERROR_SYSCALL`（代理出口抖动），
  这类传输层失败会按 `mail_retry_count` 自动重试；业务失败（如邮箱已存在）不重试。

> 直连（不走代理）时，同一出口 IP 连续注册第 2 个账号起就会被限速，
> 10 个账号全部失败。走代理后 10/10 成功。

### 与 fxpool-proxy 对接

- 注册机生成凭据包后，在代理机执行：
  `fxpool-proxy import-credentials <uid>.json --delete-source`
  （也支持从 stdin 读取：`fxpool-proxy import-credentials - --no-verify`）
- 批量导入整个凭据包目录用 `import_bundles.py`：
  ```bash
  python import_bundles.py --bundle-dir fxpool-bundles \
      --fxpool-root /path/to/fxpool-root
  ```
  默认离线导入（传 `--no-verify`），并给 `fxpool-proxy` 传 `--delete-source`
  让它在导入成功后删掉凭据包；`--keep` 不传该参数、`--verify` 联网校验、
  `--dry-run` 只列清单。导入失败时凭据包保留以便重试。
  **多账号导入必须加 `--account-mode rr`**（或设置环境变量 `ACCOUNT_MODE=rr`）：
  否则第二个账号起会覆盖 `tokens/renewal_credentials.json`，而不是写进
  `<root>/data/fxpool.db` 的账号池。`--account-mode` 会原样透传给
  `fxpool-proxy import-credentials`。
- 同机运行时直接用 `--fxpool-root <fxpool 运行目录>`，fxpool-proxy 的
  `token-status` / `token-refresh --force` / `usage` / `run` 会读取
  `<root>/tokens/renewal_credentials.json`。
- 凭据文件等同登录会话，**不要分享**；`fxpool-bundles/`、
  `renewal_credentials*.json`、`enrollment_attempts.txt` 已在 `.gitignore` 中。

## 验证与测试

```bash
python -m unittest discover -s tests -q
```

测试覆盖：
- `authPW`/`unwrapBKey` 派生 vs **官方权威向量**（PyFxA + fxa-auth-client 交叉验证）
- 验证码提取（contextual / 裸数字 / HTML 清洗 / 追踪段排除 / 8 位授权码）
- 凭据包的键顺序、字节格式、0600/0700 权限、同 uid 覆盖与不同 uid 拒绝
- `select_account_entry` 的 uid/email/currentAccountUid/lastLogin 选择规则
- `accounts_*.txt` 解析与开通台账的一次性语义
- 限速文案识别（`SignupRateLimited`）与"限速换邮箱重试"的次数/边界
- 浏览器代理优先级（`browser_proxy` > `proxy` > `$BROWSER_PROXY`）与透传给 `launch()`
- emailnator 传输层失败重试、业务失败不重试
- 配置加载与校验、路径与输出格式

## 免责声明

本工具仅用于学习 Mozilla Accounts API 协议与自动化研究。请勿用于恶意批量注册、规避平台风控或违反 Mozilla 服务条款的活动。批量注册可能触发 fxa-customs-server 速率限制（errno 114/125），请控制频率与规模，遵守目标服务的使用条款。

## License

MPL-2.0
