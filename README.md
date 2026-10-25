# centsmtp

SMTP 桥:本地 SMTP 前端(`centsmtp_client`)→ 加密隧道 → AWS SES 中转(`centsmtp_server`)。

业务程序照常连本机的 SMTP 端口发信。`client` 把邮件通过加密隧道转交给 `server`,`server` 完成收件人检查后交给 SES 发送,并把每封邮件存档。SES 的退信、投诉事件通过 SNS → SQS 回流,`server` 主动拉取,**不需要开放任何入站端口来接收 SNS**。

```
业务程序 --SMTP--> centsmtp_client --加密隧道(TCP 7025)--> centsmtp_server --SMTP(587)--> AWS SES
                                                               ^
                                       SES --> SNS --> SQS ----+ (server 出站长轮询)
```

## 功能

**server**
- 收件人检查,每个收件人都会得到明确的结果:
  1. 地址语法检查
  2. 地址黑名单:曾经永久退信或投诉的地址,直接拒发
  3. 一次性邮箱域名黑名单:自动下载并定期更新开源列表
  4. 常见域名拼写纠错:例如 `hotmail.con` 会提示 `did you mean hotmail.com?`
  5. 域名有效性检查:域名必须有 MX 记录(或 A/AAAA 记录)。白名单域名(如 gmail.com)免检
- 通过 SES SMTP 接口发送。
- 每封邮件(包括被拒绝的)存成独立的 `.eml` 文件,按 client 名称和日期分目录存放。
- 通过 SQS 接收 SES 的 Bounce / Complaint / Delivery / Reject 事件。永久退信和投诉的地址自动加入黑名单,事件写入 `events.jsonl`。
- 黑白名单为 JSON 文件,运行时只读内存,有变更才写盘。`whitelist.json` 手动修改后自动重新加载。

**client**
- 暴露标准 SMTP 服务(默认 `127.0.0.1:25`),接受任意 AUTH 凭据,方便强制要求认证的邮件库使用。
- 可以运行多个实例,每个实例有不同的名称和端口。
- 以日志记录每个收件地址的发送结果,只记录目标地址和 server 的回复,不记录邮件内容。
- 向业务程序返回标准 SMTP 状态码:`250` 成功,`451` 可稍后重试,`550` 永久失败,`552` 邮件过大。

**加密隧道**:预共享密钥(PSK)+ HKDF-SHA256 派生每个连接、每个方向独立的 ChaCha20-Poly1305 密钥,双向握手验证。

## 构建

需要 Rust 工具链。

```powershell
cargo build --release
```

产物在 `target\release\`:`centsmtp_server.exe` 和 `centsmtp_client.exe`。

## 使用

### 1. 生成共享密钥

```powershell
.\centsmtp_server.exe --gen-key
```

server 和所有 client 必须使用同一个密钥。

### 2. 配置并启动 server

在 server 的工作目录创建 `centsmtp.conf`(`KEY=VALUE` 格式,`#` 开头为注释)。真实的环境变量优先于文件内容,文件路径可用 `CENTSMTP_CONFIG` 指定。该文件含密钥,不要提交到 git(已在 `.gitignore` 中)。

```ini
# 隧道
CENTSMTP_KEY=<上一步生成的密钥>
CENTSMTP_LISTEN=0.0.0.0:7025

# SES SMTP 凭据(SES 控制台 -> SMTP settings 生成)
CENTSMTP_SMTP_HOST=email-smtp.us-east-1.amazonaws.com
CENTSMTP_SMTP_PORT=587
CENTSMTP_SMTP_USER=<SES SMTP 用户名>
CENTSMTP_SMTP_PASS=<SES SMTP 密码>

# SES 事件回流(SNS -> SQS)
CENTSMTP_SQS_URL=https://sqs.us-east-1.amazonaws.com/<账号ID>/<队列名>
AWS_ACCESS_KEY_ID=<IAM 访问密钥 ID>
AWS_SECRET_ACCESS_KEY=<IAM 访问密钥>
```

启动:

```powershell
.\centsmtp_server.exe
```

防火墙只需要允许 client 访问 `CENTSMTP_LISTEN` 的端口(默认 7025)。

所有配置项(命令行参数名 / 环境变量或配置文件键):

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `--listen` / `CENTSMTP_LISTEN` | `0.0.0.0:7025` | client 连接的监听地址 |
| `--key` / `CENTSMTP_KEY` | 必填 | 预共享密钥 |
| `--smtp-host` / `CENTSMTP_SMTP_HOST` | `email-smtp.us-east-1.amazonaws.com` | SES SMTP 地址 |
| `--smtp-port` / `CENTSMTP_SMTP_PORT` | `587` | 587 为 STARTTLS,465 为隐式 TLS |
| `--smtp-user` / `CENTSMTP_SMTP_USER` | 必填 | SES SMTP 用户名 |
| `--smtp-pass` / `CENTSMTP_SMTP_PASS` | 必填 | SES SMTP 密码 |
| `--archive-dir` / `CENTSMTP_ARCHIVE_DIR` | `archive` | 邮件存档目录 |
| `--data-dir` / `CENTSMTP_DATA_DIR` | `data` | 黑白名单、事件日志所在目录 |
| `--sqs-url` / `CENTSMTP_SQS_URL` | 无 | SQS 队列地址;不设置则不拉取事件 |
| `--aws-access-key-id` / `AWS_ACCESS_KEY_ID` | 无 | 访问 SQS 的 IAM 密钥(使用 SQS 时必填) |
| `--aws-secret-access-key` / `AWS_SECRET_ACCESS_KEY` | 无 | 同上 |
| `--aws-session-token` / `AWS_SESSION_TOKEN` | 无 | 仅临时凭据需要 |
| `--sns-topic-arn` / `CENTSMTP_SNS_TOPIC_ARN` | 无 | 只接受该 topic 的消息(可选) |
| `--blocklist-url` / `CENTSMTP_BLOCKLIST_URL` | disposable-email-domains 项目的列表 | 一次性邮箱域名列表地址,填 `off` 关闭 |
| `--blocklist-interval-hours` / `CENTSMTP_BLOCKLIST_INTERVAL_HOURS` | `24` | 列表更新间隔 |
| `--max-connections` | `64` | client 最大并发连接数 |
| `--sns-token` / `CENTSMTP_SNS_TOKEN` | 无 | 可选:启用 HTTP 接收 SNS(`POST /sns/<token>`)。默认关闭,不需要 |

### 3. 启动 client

```powershell
$env:CENTSMTP_KEY    = "<与 server 相同的密钥>"
$env:CENTSMTP_SERVER = "server.example.com:7025"
$env:CENTSMTP_NAME   = "web1"
.\centsmtp_client.exe
```

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `--name` / `CENTSMTP_NAME` | 必填 | 实例名称(`A-Za-z0-9._-`)。用于结果日志文件名和 server 端存档目录 |
| `--server` / `CENTSMTP_SERVER` | 必填 | server 地址 `host:port` |
| `--key` / `CENTSMTP_KEY` | 必填 | 预共享密钥 |
| `--listen` / `CENTSMTP_LISTEN` | `127.0.0.1:25` | 本地 SMTP 监听地址 |
| `--log-dir` / `CENTSMTP_LOG_DIR` | `logs` | 结果日志目录,文件为 `<name>.log` |

在同一台机器上运行多个实例时,使用不同的名称和端口:

```powershell
.\centsmtp_client.exe --name site-a --listen 127.0.0.1:2525 --server server.example.com:7025 --key <密钥>
.\centsmtp_client.exe --name site-b --listen 127.0.0.1:2526 --server server.example.com:7025 --key <密钥>
```

### 4. 业务程序发信

把 SMTP 服务器指向 client 即可,不需要加密,用户名和密码任意填写。以 PHPMailer 为例:

```php
$mail->isSMTP();
$mail->Host       = '127.0.0.1';
$mail->Port       = 25;
$mail->SMTPAuth   = false;   // 开启也可以,任意凭据都会被接受
$mail->SMTPSecure = false;
$mail->SMTPAutoTLS = false;
$mail->setFrom('admin@example.com');   // 发件地址必须是 SES 已验证的身份
```

## AWS 侧准备

1. **SES**:验证发件域名或地址,并生成 SMTP 凭据。新账号默认处于沙盒,只能发给已验证的地址,需要申请移出沙盒。建议在 SES 的 Suppression list 里开启对 Bounces 和 Complaints 的抑制。
2. **SNS + SQS**:创建 SNS topic 和 SQS 队列,让队列订阅该 topic。队列的访问策略要允许该 topic 执行 `sqs:SendMessage`。
3. **SES 事件**:在 SES 身份的 Notifications 里,把 Bounce、Complaint、Delivery 的通知目标设为该 topic。
4. **IAM**:为 server 创建一个只读队列的用户,生成访问密钥,策略如下:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
    "Resource": "arn:aws:sqs:us-east-1:<账号ID>:<队列名>"
  }]
}
```

## 返回状态

client 在日志和 SMTP 回复里使用这些状态:

| 状态 | 含义 | SMTP 码 |
|---|---|---|
| `SENT` | 已被 SES 接受 | 250 |
| `INVALID_ADDRESS` | 地址格式无效 | 550 |
| `INVALID_DOMAIN` | 域名不存在、无邮件服务器,或疑似拼写错误 | 550 |
| `BLACKLISTED` | 地址在黑名单,或域名在一次性邮箱列表中 | 550 |
| `RELAY_REJECTED` | SES 永久拒绝 | 550 |
| `TOO_LARGE` | 邮件超过 30 MB | 552 |
| `DOMAIN_CHECK_FAILED` | DNS 暂时查询失败,可重试 | 451 |
| `RELAY_TEMPORARY` | SES 暂时失败,可重试 | 451 |
| `RELAY_UNAVAILABLE` | client 连不上 server,可重试 | 451 |
| `INTERNAL_ERROR` | server 内部错误,可重试 | 451 |

一封邮件有多个收件人时,只要有一个被 SES 接受就算成功,其余失败的收件人会在回复和日志里逐个列出。

## 文件和目录

**server 端**

| 路径 | 内容 |
|---|---|
| `archive/<client名>/<日期>/<时间>_<id>_<sent\|failed\|rejected>.eml` | 邮件存档 |
| `data/whitelist.json` | 免 DNS 检查的域名列表。首次运行时自动生成,可以手动编辑,30 秒内自动重新加载 |
| `data/blacklist.json` | 黑名单地址及原因,由退信事件自动写入。需要解封时删除对应条目并重启 server |
| `data/events.jsonl` | 收到的每个 SES 事件,每行一条 JSON |
| `data/disposable_domains.txt` | 一次性邮箱域名列表的本地缓存 |

**client 端**:`logs/<名称>.log`,每行格式为 `时间 收件地址 状态 说明`。

### 白名单的作用

白名单中的域名会跳过一次性邮箱检查、拼写检查和 DNS 检查。

- 常用邮箱域名已经预置(gmail.com、outlook.com、qq.com、163.com 等)。
- 如果收件域名被误判为拼写错误或一次性邮箱,把它加入 `whitelist.json` 即可放行:
  ```json
  { "domains": ["gmail.com", "mycompany.com"] }
  ```
- 长度不少于 9 的白名单域名还会被用作拼写纠错的参考,所以把自己公司的域名加进去,也会得到拼写保护。

## 注意事项

- `centsmtp.conf` 包含 SES 和 AWS 密钥,不要提交或分享。
- client 的 SMTP 监听器不验证凭据,默认只监听 `127.0.0.1`。不要把它改成监听公网地址。
- 隧道使用预共享密钥,泄露后需要同时更换 server 和所有 client 的密钥。
- 配置文件在启动时读取,修改后需要重启 server(白名单除外)。
