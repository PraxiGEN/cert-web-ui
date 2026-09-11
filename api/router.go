package api

import (
	"log/slog"
	"net/http"
	"os"

	"cert-web-ui/config"
)

// NewRouter 构建全部路由：API、下载、前端页面与健康检查。
// 认证中间件统一包裹需要保护的接口。
func NewRouter(cfg config.Config) *http.ServeMux {
	mux := http.NewServeMux()

	// 前端页面在启动时读入内存，随二进制一起服务。
	indexHTML, err := os.ReadFile(cfg.IndexPath)
	if err != nil {
		slog.Warn("无法读取前端页面，首页将返回 404", "path", cfg.IndexPath, "err", err)
	}

	// "GET /{$}" 只匹配根路径本身（Go 1.22+ 的 {$} 通配符），
	// 未知路径因此直接得到 404，而不再被 SPA 兜底悄悄吞成 200 的 HTML。
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if len(indexHTML) == 0 {
			http.Error(w, "前端页面未找到", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})

	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// 证书 / 私钥下载（路径沙箱在 handler 内部用 os.Root 兜底）
	mux.HandleFunc("GET /download", withAuth(cfg, downloadHandler(cfg)))

	// 无需鉴权：前端靠它判断是否展示登录页，因此只暴露一个布尔值。
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"auth_required": cfg.UIPassword != ""})
	})

	// 登录页密码校验：正确返回 ok，错误由 withAuth 统一 401。
	// 只读接口，跨站无风险，不需要 CSRF 保护。
	mux.HandleFunc("GET /api/auth/check", withAuth(cfg, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"ok": true})
	}))

	mux.HandleFunc("GET /api/certs", withAuth(cfg, listHandler(cfg)))
	mux.HandleFunc("GET /api/certs/{name}", withAuth(cfg, detailHandler(cfg)))
	mux.HandleFunc("POST /api/issue", withAuth(cfg, issueHandler(cfg)))
	mux.HandleFunc("POST /api/certs/{name}/renew", withAuth(cfg, renewHandler(cfg)))
	mux.HandleFunc("POST /api/certs/{name}/revoke", withAuth(cfg, revokeHandler(cfg)))
	mux.HandleFunc("DELETE /api/certs/{name}", withAuth(cfg, deleteHandler(cfg)))
	mux.HandleFunc("POST /api/certs/import", withAuth(cfg, importHandler(cfg)))

	// 后端管理：CA 就绪探测 + 根证书下载/详情 + CRL 下载
	mux.HandleFunc("GET /api/backend/status", withAuth(cfg, backendStatusHandler(cfg)))
	mux.HandleFunc("GET /api/backend/root", withAuth(cfg, backendRootHandler(cfg)))
	mux.HandleFunc("GET /api/backend/rootinfo", withAuth(cfg, backendRootInfoHandler(cfg)))
	mux.HandleFunc("GET /api/backend/crl", withAuth(cfg, backendCRLHandler(cfg)))
	// 危险操作：轮换 / 回滚根证书（服务端均以 confirm 字段二次校验，前端另有强提示）
	mux.HandleFunc("POST /api/backend/root/rotate", withAuth(cfg, backendRootRotateHandler(cfg)))
	mux.HandleFunc("GET /api/backend/root/archives", withAuth(cfg, backendRootArchivesHandler(cfg)))
	mux.HandleFunc("POST /api/backend/root/rollback", withAuth(cfg, backendRootRollbackHandler(cfg)))

	// 自动续签：状态查询 + 手动触发一次扫描
	mux.HandleFunc("GET /api/renew/status", withAuth(cfg, renewStatusHandler()))
	mux.HandleFunc("POST /api/renew/scan", withAuth(cfg, renewScanHandler(cfg)))

	return mux
}
