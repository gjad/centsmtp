# 快速部署

## 服务器(2 个文件)

把 `centsmtp_server.exe` 和 `centsmtp.conf` 放在同一个目录,在该目录下运行:

```powershell
.\centsmtp_server.exe
```

`data\` 和 `archive\` 目录会自动创建。

`centsmtp.conf` 示例(密钥可用 `.\centsmtp_server.exe --gen-key` 生成):

```ini
CENTSMTP_KEY=<密钥>
CENTSMTP_LISTEN=0.0.0.0:7025
CENTSMTP_SMTP_USER=<SES SMTP 用户名>
CENTSMTP_SMTP_PASS=<SES SMTP 密码>
CENTSMTP_SQS_URL=https://sqs.us-east-1.amazonaws.com/<账号ID>/<队列名>
AWS_ACCESS_KEY_ID=<IAM 访问密钥 ID>
AWS_SECRET_ACCESS_KEY=<IAM 访问密钥>
```

网络要求:
- 入站:允许客户端访问 7025 端口。
- 出站:SES SMTP(587)、SQS、GitHub(下载一次性邮箱列表)。

## 客户端(1 个文件)

只需要 `centsmtp_client.exe`,一条命令:

```powershell
.\centsmtp_client.exe --name site-a --listen 127.0.0.1:2525 --server server.example.com:7025 --key <密钥>
```

`logs\` 目录会自动创建。业务程序的 SMTP 地址填 `127.0.0.1:2525`,不加密,用户名密码任意。

## 提示

- 密钥必须和服务器的 `CENTSMTP_KEY` 一致。
- `--key` 会出现在进程列表里,介意的话改用环境变量 `CENTSMTP_KEY`。
- 同一台机器上运行多个客户端,用不同的 `--name` 和 `--listen`。
- 目标机器若报缺少 `vcruntime140.dll`,安装 Microsoft Visual C++ Redistributable。
- `centsmtp.conf` 含密钥,不要提交或分享。
