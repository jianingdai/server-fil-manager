# 内网文件管理系统

一个面向公司内网的网页文件管理器。服务端使用 Go，网页静态资源嵌入程序，数据存入 SQLite。目标服务器无需安装数据库、Docker 或 Go，也无需 sudo；按麒麟 Linux V10 SP1 ARM64 构建后，将单个二进制文件传到服务器运行。

## 功能

- 管理员通过网页创建、停用普通用户、重置密码并配置逐目录权限；网页不能提升管理员角色。
- 管理员可以登记当前运行账号可访问的服务器目录。共享目录不能重叠，也不能包含应用数据目录。
- 普通用户只能访问已授权目录。浏览、下载、上传、新建目录、重命名、删除、复制、移动和搜索分别授权。
- 文件操作支持上传、下载、目录浏览、新建目录、重命名、跨目录复制/移动、按文件名搜索和可恢复删除。
- 删除文件放入回收站，首版不会自动清理；管理员可永久清理。数据文件保留在 SQLite 之外。
- 普通文件 API 使用共享目录 ID 与目录内相对路径。路径穿越和符号链接访问会被拒绝；不支持复制、删除设备节点、FIFO 或套接字。

## 数据表初稿与权限规则

数据库在应用数据目录中的 `manager.sqlite3`。首版包含以下表：

| 表 | 保存内容 |
| --- | --- |
| `users` | 唯一用户名、bcrypt 密码哈希、`admin`/`user` 角色、启用状态和时间戳 |
| `storage_roots` | 管理员登记的目录名称、规范绝对路径、启用状态和创建者 |
| `user_root_permissions` | 普通用户到共享目录的授权关系，分别记录浏览、下载、上传、新建目录、重命名、删除、复制、移动和搜索权限 |
| `sessions` | 用户、会话令牌哈希、CSRF 令牌和创建/过期时间 |
| `trash_entries` | 原目录和相对路径、回收站内容位置、删除人/时间及恢复/清理状态 |
| `audit_logs` | 操作者、操作类型、目录、相对路径、时间和结果；不记录文件内容 |
| `schema_migrations` | 已应用的数据库结构版本 |

管理员对所有启用目录拥有完整权限。普通用户每个请求都会在服务端按共享目录检查相应权限；停用账号会立即撤销其会话，权限变更会在后续请求立即生效。跨目录复制要求源目录有“复制”且目标目录有“上传”；跨目录移动要求源目录有“移动”且目标目录有“上传”。恢复回收站条目要求该用户仍有目标目录的“上传”权限；权限被撤销后，普通用户也不会再看到该目录下的回收站元数据。首版不自动清理回收站。

## 开发与检查

在仓库根目录运行：

```sh
go mod download
go test ./...
```

构建机需要 Go 1.26 或更新版本及模块下载网络。依赖版本由 `go.mod` 和 `go.sum` 固定。

## 构建麒麟 ARM64 离线程序

在有 Go 和网络的构建机、仓库根目录执行：

```sh
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o dist/server-file-manager ./cmd/server-file-manager
sha256sum dist/server-file-manager
```

输出文件是 `dist/server-file-manager`。通过公司批准的文件传输方式将程序复制到服务器，并在复制后对比 SHA-256。目标机无需连接互联网。

## 服务器首次部署

以有权访问预期共享文件夹的普通 Linux 账号登录服务器，不要以 root 运行。以下示例将数据库、会话和回收站放在用户目录：

```sh
mkdir -p "$HOME/bin" "$HOME/.local/share/server-file-manager"
chmod 700 "$HOME/.local/share/server-file-manager"
# 将已校验的二进制文件放入 "$HOME/bin/server-file-manager"
chmod 700 "$HOME/bin/server-file-manager"
"$HOME/bin/server-file-manager" init-admin --data-dir "$HOME/.local/share/server-file-manager"
"$HOME/bin/server-file-manager" serve --listen :8080 --data-dir "$HOME/.local/share/server-file-manager"
```

`init-admin` 会交互式隐藏密码输入，不提供默认账号密码。密码至少 12 个字符，bcrypt 限制最多 72 个 UTF-8 字节。服务前台运行，退出终端或按 Ctrl-C 会停止；首版不配置开机自启。浏览器访问 `http://<服务器内网地址>:8080/`。服务器防火墙必须允许该高位端口；调整防火墙可能需要系统管理员协助。

登录后，管理员先在“共享目录”中输入显示名称和服务器上的绝对路径，再到“用户与权限”给普通用户分配权限。应用只能访问其 Linux 运行账号原本可访问的目录；请勿登记包含凭据、应用数据或不应共享内容的目录。共享路径必须是已存在目录，且不能和其他已登记目录重叠。

可使用 `--max-upload-bytes N` 限制单个上传请求大小；默认 `0` 表示不设应用层大小上限。请结合磁盘容量和用户信任级别决定是否设置上限。搜索只匹配文件名，不读取文件内容。

## 账号管理命令

管理员可在网页创建和管理普通账号。初始管理员之后的角色授予只通过服务器命令行完成：

```sh
"$HOME/bin/server-file-manager" user set-role --data-dir "$HOME/.local/share/server-file-manager" USERNAME admin
```

把管理员降为普通用户时，命令会阻止降级最后一个启用的管理员。角色变更会使目标用户现有会话失效。

## HTTPS

首版默认 HTTP。HTTP 会明文传输登录凭据和文件内容，只适合在已受控的公司内网中使用。若已有公司反向代理，可让代理提供 HTTPS 并转发到本服务；启用 `--secure-cookie` 并确保代理保留浏览器访问时的 `Host`。也可由本服务读取证书：

```sh
"$HOME/bin/server-file-manager" serve --listen :8080 \
  --data-dir "$HOME/.local/share/server-file-manager" \
  --tls-cert /path/to/server.crt --tls-key /path/to/server.key
```

反向代理终止 TLS 的启动示例：

```sh
"$HOME/bin/server-file-manager" serve --listen :8080 \
  --data-dir "$HOME/.local/share/server-file-manager" --secure-cookie
```

证书和私钥不要提交到 Git 仓库。启用 TLS 后会设置 Secure 会话 Cookie。

## 数据与备份

默认数据目录为 `$XDG_DATA_HOME/server-file-manager`；未设置 `XDG_DATA_HOME` 时使用 `$HOME/.local/share/server-file-manager`。可用 `--data-dir` 指定其他路径。数据库为 `manager.sqlite3`，回收站内容位于数据目录下的 `trash/`。数据目录权限设置为仅运行账号可访问。

备份时先停止服务，再复制整个数据目录；共享目录中的原始文件仍需按公司的文件备份策略单独备份。恢复备份前也应停止服务。

## 安全边界

- 用户权限由服务端逐请求校验，网页隐藏按钮不构成权限边界。
- 管理员能登记运行账号可访问的任意目录；此权限应只授予受信任管理员。
- 服务拒绝路径穿越、符号链接及非普通文件操作，并拒绝覆盖已有目标名。
- 运行账号的 Linux 文件权限仍然生效。不要将程序以 root 身份启动。
- `.gitignore` 会排除本地环境配置、密钥、数据库、用户文件、日志及构建产物。提交公开仓库前仍应检查 Git 暂存内容，避免加入真实服务器路径、账号、证书或运行数据。

## 目标机验收

在匹配的麒麟 ARM64 服务器上完成二进制启动、无网络登录、管理员与普通用户权限隔离、跨目录操作授权、回收站恢复和从另一台内网设备浏览器访问的实机检查。开发机上的 Go 测试不能代替目标机和服务器防火墙验证。
