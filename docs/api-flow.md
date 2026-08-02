# Mozilla 账号注册 API 流程

基于官方文档整理（https://mozilla.github.io/ecosystem-platform/api 与
https://mozilla.github.io/ecosystem-platform/explanation/onepw-protocol），
Mozilla 账号（原 Firefox Accounts / FxA）注册是纯 HTTP API 流程，无需浏览器自动化。

## 环境

| 项 | 值 |
|----|----|
| Auth Server 基址 | `https://api.accounts.firefox.com/v1` |
| Content Server | `https://accounts.firefox.com` |

## 第 1 步：派生 authPW（onepw 协议 v1）

密码明文绝不直接传输，客户端先做 PBKDF2 + HKDF 拉伸（参考
`mozilla/fxa` 仓库 `fxa-auth-client/lib/crypto.ts` 与 `salt.ts`）：

```
salt            = "identity.mozilla.com/picl/v1/quickStretch:{email}"
quickStretched  = PBKDF2-SHA256(password, salt, iterations=1000, dkLen=32)
authPW          = HKDF-SHA256(quickStretched, salt=空, info="identity.mozilla.com/picl/v1/authPW", L=32)
```

- 邮箱用小写（作为 PBKDF2 的盐，大小写敏感）。
- `authPW` 与 `unwrapBKey` 使用同一 `quickStretched`，仅 HKDF info 不同
  （`.../authPW` 与 `.../unwrapBkey`）。注册只用到 `authPW`。
- 服务器端另有 scrypt 拉伸存储 verifyHash，但那是服务端职责，客户端不需要。

## 第 2 步：创建账号

```
POST {base}/account/create
Content-Type: application/json
Body: { "email": "<邮箱>", "authPW": "<64位hex>", "service": "sync" }
```

- 必填：`email`（≤255 字符）、`authPW`（^[a-fA-F0-9]{2}+$）。
- 可选 `service`（≤16 字符，`^[a-zA-Z0-9-]*$`，会嵌入验证邮件链接）。
- 成功返回 `200`：
  ```json
  { "uid": "...", "sessionToken": "...", "authAt": 1234 }
  ```
  并立即向邮箱发送 **6 位数字验证码** 邮件。
- 邮件正文结构（当前生产）：主题含 "Confirm your email address" 之类，
  正文含 6 位数字确认码。

## 第 3 步：邮箱验证

```
POST {base}/recovery_email/verify_code
Content-Type: application/json
Body: { "uid": "<uid>", "code": "<6位码>" }
```

成功返回 `200 {}`，账号转为 verified。

## 可能遇到的错误（auth-server errno）

| errno | 含义 | 处理 |
|-------|------|------|
| 102 | 未知账号 | 重试/忽略 |
| 106 | 请求体无效 | 检查参数 |
| 114 | 触发限速 | 等待 retryAfter |
| 120 | 邮箱大小写不一致 | 用服务器返回的规范邮箱重试 |
| 125 | WAF 拦截 | 换 User-Agent/加 Cookie，降低频率 |
| 138 | 验证码已过期/已用 | 重新创建或忽略 |

## 防自动化注意

- 生产环境前有 **Fastly WAF**：对 /account/create、/account/login 等路径
  要求携带 Cookie（官方 auth-client 对 https 环境设置
  `credentials = 'include'`）。用 `requests.Session` 自动维持 Cookie。
- **fxa-customs-server** 对注册有速率限制（IP + 邮箱域维度），高频批量
  会触发 errno 114/125。批量时需要代理池或显著降低并发。
- 当前生产验证邮件是 6 位纯数字码（support.mozilla.org 确认），
  可直接用 `extract_verification_code` 式正则提取。

## 参考实现

- 官方 TS 客户端：`packages/fxa-auth-client/lib/client.ts`（signUp 流程）
- 官方加密模块：`packages/fxa-auth-client/lib/crypto.ts`、`lib/salt.ts`
- onepw 协议文档：https://mozilla.github.io/ecosystem-platform/explanation/onepw-protocol
