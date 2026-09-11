# cert-web-ui 项目长期记忆

## 项目定位
**自建 Go 内置 CA** 的证书管理平台（crypto/x509 进程内签发），单容器、零外部依赖。早期「step-ca 外壳」时代的代码已全部清除。

## 架构
- 模块 `cert-web-ui`，Go **1.27**，**零第三方依赖**（net/http + crypto/x509）。日志走 `log/slog`，服务器带 `ReadHeaderTimeout`/优雅关停，写盘走 `store.WriteFileAtomic`，换根/签发并发由 `swapMu` + 调度器互斥保护，写请求经 `http.CrossOriginProtection` 防 CSRF。**`CA_ROOT_CERT` 已删除**（根路径由 CA_HOME 推导）。
- 包：`config/` env 配置、`store/` metadata 与目录扫描、`ca/` PKI 核心、`api/` 路由+handler+访问日志、`scheduler/` 自动续签、`web/index.html` 单文件前端（运行时由 Go 读取）。
- 数据布局：`CA_HOME/`（`root_ca.crt`、`root_ca.key` 0600、`revoked.json`、`crl.pem`、`archive/root-<ts>/` 历次被替换下去的根）+ `CERT_OUTPUT_BASE/`（每张证书一个目录：`<cn>.crt`、`<cn>.key` 0600、`metadata.json`）。
- 证书 `origin`：`issued`（本系统签发，可续签/吊销）、`imported`（导入归档，仅查看/下载/删除，续签被拒）。

### 根证书高危操作 = 轮换 + 回滚（`ca/rotate.go`）
共用一条流程 `activateRoot()`（归档当前根 → 写入新根 → 换 `rootCache`）+ `rebuildCRL()` + 可选 `reissueIssued()`，返回统一 `RootSwapResult`（带 `mode: rotate|rollback`）。
- 轮换 `RotateRoot()` ← `POST /api/backend/root/rotate`：内存先生成新根 → 再归档 → 最后落盘，任一步失败 `rollbackMoves()` 搬回。
- 回滚 `RollbackRoot()` ← `POST /api/backend/root/rollback`：把 `archive/root-<ts>/` 里某份**历史根**恢复为当前根。语义是「换一份根材料」而非一次性撤销 —— 当前根会被再归档，**回滚本身也能再回滚**，无单向门。
- 归档枚举 `ListRootArchives()` ← `GET /api/backend/root/archives`。`has_key=false`（缺私钥/不配对）与 `is_current=true`（**指纹**等于当前根，重复归档的同一张也识别得出）不可回滚，前端置灰。
- **`resolveArchiveDir()` 必须做路径穿越收敛**：`filepath.Base()` → 前缀须为 `root-` → `filepath.Abs` 校验落在 `CA_HOME/archive/` 内；前端传绝对路径也安全。
- `RootCA.Key` 是 `crypto.Signer`（EC P-256/384/521、RSA 2048/4096）。重签复用 `ca.Renew()`（原私钥 + 当前根重签，**私钥字节不变**）；`origin=imported` 计入 `untouched`，证书文件一字节不动。**`revoked.json` 不归档**（序列号与新根不冲突），旧 CRL 归档后必须用新根重建。
- `rotate` 与 `rollback` 服务端都有 `confirm` 硬校验（须逐字等于**当前**根 CN），前端另有一道逐字输入门槛。

### 前端
- 单文件 `web/index.html`（原生 JS + CSS 变量主题）。三页：首页 / 证书管理（签发·导入·证书列表三个分页）/ 后端管理。
- 布局：上 `header.app-header`（logo/简介/CA 就绪点/版本/作者/设置）、中 `main.content`、下 `nav.dock`；整页居中 `max-width:1280`、`body{min-width:960}`。
- **`nav.dock` 必须紧跟 `<header>` 之后**（`top` 停靠模式用 `sticky`，放 DOM 末尾则其自然流位置在页底，永远滚不出来）。Dock 四向由 `:root[data-dock=...]` 驱动，持久化 `cert-ui-dock`；`top` = 顶栏下方靠左状态栏（`--header-h` 由 JS 量取）；≤760px 一律回落底部胶囊。
- 首页：4 张统计卡 + `.grid-2` 双列（根证书 `#rootOverview`/`#rootDays`、运行信息 `#runtimeInfo`）+「即将到期」`#expiringList`。**没有「后端连接状态」**——step-ca 时代残留，与后端管理的 CA 状态完全重复（同一 `renderBackend()` + 同一接口）。
- **交互反馈已全部应用内化**（原生 `alert`/`confirm` 残留为 0）：`toast(msg,type)` 轻提示（`ok|err|warn|info`，右下角自动消失；窄屏移 Dock 之上撑满，`data-dock=right` 时右移避让）、`appConfirm({title,message,confirmText,danger})` 返回 `Promise<boolean>`、`downloadPem(url,filename)` 先 fetch 探测再落盘。**下载 CRL/根证书不再 `location.href` 跳页**，404 直接把后端文案显示为 toast。
- 设置面板 `#settingsOverlay`：主题三卡 `#themeOpts` + Dock 四向 `#dockOpts`，持久化 `cert-ui-theme` / `cert-ui-dock`。
- **危险操作一律收进二级入口**：根证书卡片头部只有 `下载 CRL / 下载根证书 / 管理`，点「管理」`#manageBtn` 开 `#manageOverlay`（`.manage-item` 列表）→ 再进 `#rotateOverlay` 或 `#rollbackOverlay`。页面上**不再有常驻的红色 danger-zone**（`.danger-zone` 已删）。两个面板共用 `.swap-confirm`/`.swap-submit` 与 `resetSwapPanel()`/`closeSwap()`/`showSwapResult(kind,r)`。

## 关键约定与坑
- **同一条消息内不可对同一文件发多个 Edit** —— 会写覆盖，只生效一部分（已两次踩坑）。必须一条消息一个 Edit 并 grep 复核；跨多处替换统一写临时 Python 补丁脚本（每步 `assert s.count(old)==1`），跑完删脚本。
- **安全三层防线（Go 1.27 验证过）**：① ServeMux 的 `{name}` 通配自带拒绝 `.`/`..` 段；② `store.ValidLeafName` 是名字进路径前的最后一道硬门槛；③ `os.Root` 沙箱让符号链接与 `..` 无法逃逸，`Root.RemoveAll(".")` 会被直接拒。**不要**再写「Abs 后比字符串前缀」的守卫——目标等于根目录本身时前缀比对形同虚设。
- **文件名/文件夹名一律白名单清洗**（`SanitizeFolder` / `certFileName`：字母数字 `-_.`）：`encodeURIComponent` **不转义 `' ( ) ! * ~`**，任何把含 `'` 的字符串拼进 `onclick="…('…')"` 属性的写法都是存储型 XSS。路径/URL 类参数**永不进 HTML 属性**——改为传 name/kind，函数内部取值（`copyFile(name, kind, btn)` 即此模式）。
- 前端隐藏面板一律用 `.hidden` **类**，禁用原生 `hidden` 属性。
- **`opacity:0` + `transition` 不可作为元素基础态**：动画时钟不推进的环境（无头/降级合成）下元素会永久隐形。基础态应直接可见，入场动画用 `@keyframes` 叠加，并配 `@media (prefers-reduced-motion: reduce)` 关闭。
- `appConfirm` 的 Esc 须 **capture + stopPropagation** 拦截，否则会穿到面板自身的 Esc 收起逻辑把底层一起关掉。
- 图标按钮用 `<div role="button" tabindex="0">`（`<button>` 内嵌 `<svg>` 在预览渲染器里异常），且**必须自己绑 `onkeydown`**（Enter/空格）才有键盘可达性。
- `.settings-panel` 自带 `max-height:calc(100vh - 40px)` + `overflow:auto`，面板再长也能滚；层级 overlay 100 > dock 40 > header 30。
- `config.Load()` 默认：`CA_HOME=/data`、`CA_ROOT_VALIDITY=87600h`、`CA_LEAF_VALIDITY=8760h`、`RENEW_INTERVAL=24h`、`RENEW_BEFORE=720h`、`CA_ROOT_KEY_TYPE=ec-p256`。**版本号唯一权威来源 = env `APP_VERSION`**（config.go，默认 v1.0.0）；前端 `APP_VERSION` 常量仅首帧兜底，`loadBackendStatus()` 拿到 `st.version` 后覆盖顶栏。**作者名/链接硬编码在 `config/config.go` 包级变量 `authorName`/`authorURL`**（不走环境变量，改了重新构建），经 `/api/backend/status` 的 `author_name`/`author_url` 下发，前端 `sideAuthor` 由接口驱动。
- `InitRoot` 只在根证书文件**不存在**时生成；已存在但加载失败会报错而非覆盖（避免误轮换根让全体客户端失效）。
- **Go 零值时间**（`0001-01-01T00:00:00Z`）在 JS 里是 truthy，`fmtTime` 必须按 `getFullYear() < 2000` 收敛为 `—`。
- 调度器首次扫描默认延迟半个周期（12h），期间计数恒为 0 → 启动时 `refreshCounts()` 只统计不续签，免得首页统计卡自相矛盾。
- 390px 手机：表格会把徽标压成竖排多行 → 窄屏走 `isPhone()` 分支的卡片/紧凑列表；断点切换时**同时**重渲染所有按断点分支的列表。
- 环境无本地 Go，只能靠 Docker 多阶段构建验证。宿主机有 `openssl`，运行时镜像**没有** → 验证书要 `docker cp` 出来（目标路径须 `cygpath -w`）。
- devshot 的 `measure()` 会**覆盖 `document.title`**，`?eval=` 断言别写进 title，改写进某元素 `textContent` 再 grep；切页/切状态**必须走 devshot**（`?tab=` 由注入段驱动，直连应用端口不生效）。
- 运行时：镜像 `cert-web-ui:local`，容器 `cert-web-ui`（`-p 16850:8080 -v cert-ca-data:/data -e CA_NAME=... --restart unless-stopped`），http://127.0.0.1:16850 。
- **CI 发布**：`.github/workflows/release.yml` 单文件三触发——① push main 时解析 config.go 的 `APP_VERSION` 默认值，版本有变自动打 tag 发布（**发版 = 改版本号 + push main**）；② `workflow_dispatch` 手动触发（可指定版本）；③ push `v*` tag 直接发布。多架构（amd64+arm64）发 `ghcr.io/<owner>/<repo>:vX.Y.Z` + `:latest`。**坑：GITHUB_TOKEN 打的 tag 不触发新 run**（防递归），resolve/docker 两 job 必须同 workflow 串联，docker 的 if 须兼容 resolve 被 skip。镜像 tag 带 v 前缀。**容器内外端口统一 9280**（8080→16850→9280，避开 9000 系常用服务 Portainer/MinIO/Prometheus/ES 等，`PORT` env 可覆盖）。

## 用户偏好
- 只写向前代码，拒绝数据迁移/向后兼容。
- 先讨论方案、收窄边界，再分步实施；架构问题「不写代码先聊聊」。
- 倾向精简实现、统一抽象、零依赖；要直接果断的结论，先抛底线判断。
