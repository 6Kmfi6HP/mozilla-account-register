# Mozilla 账号注册机

针对 **Mozilla 账号（Mozilla Accounts / 原 Firefox Accounts）** 的批量自动注册 CLI。

Mozilla 账号注册是**纯 HTTP API 流程**，无需浏览器自动化：客户端派生 `authPW` → `POST /account/create` → 从临时邮箱自动取验证码 → `POST /recovery_email/verify_code` 完成验证。

## 特性

- ✅ 接入 **Cloud Mail 临时邮箱 API**（无需预创建邮箱，随机生成 `用户名@域名`）
- ✅ **自动获取验证码并自动验证**，全程无需人工介入
- ✅ 批量注册：文本邮箱列表 或 自动生成邮箱 + 随机密码
- ✅ 多线程并发 + 错峰启动，输出逐行 fsync 落盘不丢
- ✅ `authPW` 派生与 Mozilla 官方 onepw v1 协议字节级一致（已用官方测试向量验证）

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置（把 config.example.json 复制为 config.json 并填邮箱服务信息）
cp config.example.json config.json

# 3. 干跑：校验配置 + 测试 authPW 派生，不发网络请求
python register.py --dry-run

# 4. 注册 3 个账号（自动生成临时邮箱 + 随机密码）
python register.py --count 3

# 5. 从文件批量注册
python register.py --emails emails.txt --threads 2
```

## 配置

复制 `config.example.json` 为 `config.json`。核心字段：

| 字段 | 必填 | 说明 |
|------|------|------|
| `email_provider` | 是 | `cloudmail`（当前支持） |
| `cloudmail_api_base` | 是 | Cloud Mail 服务地址 |
| `cloudmail_public_token` | 是 | Cloud Mail 公共 Token |
| `cloudmail_domains` | 是 | 收件域名，逗号分隔（随机轮换生成邮箱） |
| `cloudmail_path_messages` | 否 | 邮件列表接口路径，默认 `/api/public/emailList` |
| `auth_base` | 否 | Mozilla Auth Server，默认 `https://api.accounts.firefox.com/v1` |
| `proxy` | 否 | HTTP 代理（批量高频时建议用代理池） |
| `register_count` | 否 | 自动生成邮箱时注册数量 |
| `register_threads` | 否 | 并发线程数 |
| `mail_timeout` | 否 | 等待验证码超时（秒） |
| `emails_file` | 否 | 邮箱列表文件路径（也支持 `--emails` CLI 参数） |

## 命令行

```
python register.py [选项]
  --config PATH    配置文件路径（默认 config.json）
  --count N        注册数量（覆盖配置）
  --emails FILE    邮箱列表文件，每行一个邮箱
  --threads N      并发线程数（覆盖配置）
  --out FILE       账号输出文件（默认 accounts_<时间戳>.txt）
  --dry-run        只校验配置与 authPW 派生，不发网络请求
```

## 输出

- **账号**：`accounts_<YYYYMMDD_HHMMSS>.txt`，格式 `邮箱----密码----uid`（逐行 fsync 实时追加）
- **邮箱凭证**：`mail_credentials.txt`，格式 `邮箱\t凭证`（可回读）

## 模块结构

```
mozilla-account-register/
├── register.py           # CLI 入口：批量编排、并发、参数解析
├── register_mozilla.py   # 单账号注册流程（派生→创建→取码→验证）
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

## 验证与测试

```bash
python -m unittest discover -s tests -q
```

测试覆盖：
- `authPW`/`unwrapBKey` 派生 vs **官方权威向量**（PyFxA + fxa-auth-client 交叉验证）
- 验证码提取（contextual / 裸数字 / HTML 清洗 / 追踪段排除）
- 配置加载与校验
- 路径与输出格式

## 免责声明

本工具仅用于学习 Mozilla Accounts API 协议与自动化研究。请勿用于恶意批量注册、规避平台风控或违反 Mozilla 服务条款的活动。批量注册可能触发 fxa-customs-server 速率限制（errno 114/125），请控制频率与规模，遵守目标服务的使用条款。

## License

MPL-2.0
