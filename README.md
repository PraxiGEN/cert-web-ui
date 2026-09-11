# cert-web-ui

自建 CA 的证书管理平台：Go 进程内直接签发证书，单容器、零外部依赖。

内网设备（NAS、路由、Home Assistant、软路由面板等）需要 HTTPS 时，通常得自建 CA、手动 openssl 签发、自己管到期——这个项目把整条流程做成一个网页：签发、续签、吊销、换根，点点按钮完成。

## 功能

- **证书签发**：自动生成私钥与 SAN 证书（EC P-256 / P-384 / P-521、RSA 2048 / 4096），SAN 支持多域名多行填写
- **自动续签**：后台定时扫描，剩余有效期低于阈值（默认 30 天）自动用当前根重签，私钥保持不变
- **吊销与 CRL**：吊销证书并自动重建 CRL，供 Nginx / Traefik 等校验
- **根证书管理**：一键轮换（旧根自动归档、叶子证书全量重签）、回滚到任意历史根，全程双重确认防误触
- **导入归档**：外部证书可导入统一展示、下载，但不可续签
- **访问门禁**：可选 `UI_PASSWORD` 密码保护，常量时间比对
- **界面**：明暗主题、Dock 四向停靠、应用内弹窗反馈，移动端自适应

## 快速开始

```bash
docker run -d --name cert-web-ui \
  -p 9280:9280 \
  -v cert-ca-data:/data \
  -e CA_NAME="Home Root CA" \
  --restart unless-stopped \
  ghcr.io/<owner>/cert-web-ui:latest
```

打开 `http://<主机>:9280`，首页下载根证书并信任到客户端，即可开始签发。

或使用 compose：

```bash
docker compose up -d
```

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `PORT` | `9280` | 监听端口 |
| `CA_NAME` | `Cert Web UI Root CA` | 根证书 CN |
| `CA_ROOT_KEY_TYPE` | `ec-p256` | 根密钥算法（ec-p256/384/521、rsa-2048/4096） |
| `CA_ROOT_VALIDITY` | `87600h` | 根证书有效期（默认 10 年） |
| `CA_LEAF_VALIDITY` | `8760h` | 叶子证书默认有效期（默认 1 年） |
| `RENEW_INTERVAL` | `24h` | 自动续签扫描周期 |
| `RENEW_BEFORE` | `720h` | 临期阈值（剩余 < 30 天触发续签） |
| `UI_PASSWORD` | 空（不校验） | 访问门禁密码，**生产环境建议设置** |
| `APP_VERSION` | 编译时注入 | 版本号，镜像随 git tag 自动注入 |

数据目录 `/data`（建议挂卷持久化）：根证书与私钥、吊销记录、CRL、历史根归档、每张证书一个文件夹（证书 + 私钥 + 元数据）。

## 发版机制

项目自带 GitHub Actions（`.github/workflows/release.yml`），发布到 GHCR 的三种方式：

1. **改版本即发布**：修改 `config/config.go` 中 `APP_VERSION` 默认值并 push 到 main，版本有变自动打 tag 发布
2. **手动触发**：Actions 页面 Run workflow，可指定版本号
3. **直接打 tag**：push `v*` tag

镜像构建多架构（amd64 + arm64），tag 形如 `ghcr.io/<owner>/cert-web-ui:v1.2.3` 与 `:latest`，版本号自动注入运行时。仓库无需配置任何 secret。

## 技术说明

- Go 1.27，**零第三方依赖**（net/http + crypto/x509），进程内完成全部 PKI 操作
- 路径操作经 `os.Root` 沙箱隔离，写请求带 Origin 校验防 CSRF，口令常量时间比对
- 全部文件原子写入；日志走 `log/slog` 结构化输出
- 前端为单文件 `web/index.html`（原生 JS，无框架无构建）

## License

MIT
