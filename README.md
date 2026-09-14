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
  ghcr.io/praxigen/cert-web-ui:latest
```

打开 `http://<主机>:9280`，首页下载根证书并信任到客户端，即可开始签发。

或使用 compose：仓库根目录提供了开箱即用的 `docker-compose.yml`，已预置全部环境变量（含中文注释）、数据绑定挂载到本地 `./data` 目录，克隆后直接启动：

```bash
git clone https://github.com/PraxiGEN/cert-web-ui.git
cd cert-web-ui
docker compose up -d
```

`CA_NAME`、有效期、续签周期等参数直接在 `docker-compose.yml` 的 `environment` 中修改；如需访问门禁，取消 `UI_PASSWORD` 行的注释并设置密码即可。

### iKuai 应用市场（ipkg 离线安装）

iKuai v4 路由用户可从 [Releases](https://github.com/PraxiGEN/cert-web-ui/releases) 下载 `.ipkg` 离线安装包（内嵌 amd64 镜像，无需拉取 Docker 镜像）：**高级应用 → 应用市场 → 本地安装** 导入即可，安装后在应用列表点击图标直接打开管理页。

## 信任根证书

首次启动会在 `/data` 自动生成根证书 `root_ca.crt`（首页「下载根证书」可取），把它导入每一台会访问内网站点的设备后，签发的证书都被视为可信：

| 系统 | 操作 |
|---|---|
| Windows | 管理员命令：`certutil -addstore -f root root_ca.crt` |
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root_ca.crt` |
| Debian / Ubuntu / 树莓派 OS | 拷入 `/usr/local/share/ca-certificates/xxx.crt`（须 `.crt` 后缀）→ `sudo update-ca-certificates` |
| RHEL / CentOS / Fedora | 拷入 `/etc/pki/ca-trust/source/anchors/` → `sudo update-ca-trust extract` |
| Android | 设置 → 安全 → 安装证书 → CA 证书（浏览器信任；部分 App 内嵌页面不认用户证书） |
| iOS / iPadOS | Safari 下载并安装描述文件后，**必须**再到 设置 → 通用 → 关于本机 → 证书信任设置 打开开关 |
| Firefox | 全平台独立证书库：设置 → 隐私与安全 → 证书 → 证书颁发机构 → 导入并勾选「信任标识网站」 |

> 每台客户端都要导入，没装的设备访问时照样告警。导入后仍提示不受信任的，先重启浏览器或清一次会话。

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

数据目录 `/data`（建议挂卷持久化）：根证书与私钥、吊销记录、CRL、历史根归档、每张证书一个文件夹（证书 + 私钥 + 元数据）。

## 技术说明

- Go 1.27，**零第三方依赖**（net/http + crypto/x509），进程内完成全部 PKI 操作
- 路径操作经 `os.Root` 沙箱隔离，写请求带 Origin 校验防 CSRF，口令常量时间比对
- 全部文件原子写入；日志走 `log/slog` 结构化输出
- 前端为单文件 `web/index.html`（原生 JS，无框架无构建）

## 自行构建

构建定义位于 `docker/Dockerfile`，构建上下文为仓库根目录：

```bash
docker build -f docker/Dockerfile -t cert-web-ui:local .
```

## License

MIT
