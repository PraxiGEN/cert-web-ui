package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cert-web-ui/ca"
	"cert-web-ui/config"
	"cert-web-ui/scheduler"
	"cert-web-ui/store"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONStatus 以指定状态码输出 JSON。
func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, msg string) {
	writeJSON(w, map[string]any{"success": false, "error": msg})
}

// withAuth 门禁中间件：校验 X-UI-Password 头或 ui_password 参数，连续失败按 IP 限流
func withAuth(cfg config.Config, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.UIPassword == "" {
			h(w, r)
			return
		}
		ip := clientIP(r)
		if blocked, remain := authLimit.blocked(ip); blocked {
			w.Header().Set("Retry-After", fmt.Sprint(remain))
			slog.Warn("访问密码尝试过于频繁，已临时锁定", "remote", ip)
			writeJSONStatus(w, http.StatusTooManyRequests,
				map[string]any{"success": false, "error": fmt.Sprintf("尝试次数过多，请 %d 秒后再试", remain)})
			return
		}
		if !passwordOK(r, cfg.UIPassword) {
			authLimit.recordFail(ip)
			slog.Warn("访问密码校验失败",
				"remote", r.RemoteAddr, "method", r.Method, "path", r.URL.Path)
			writeJSONStatus(w, http.StatusUnauthorized,
				map[string]any{"success": false, "error": "访问密码错误"})
			return
		}
		authLimit.recordOK(ip)
		h(w, r)
	}
}

// passwordOK 常量时间比较：先取 SHA-256 再比，避免长度不等时提前返回泄漏长度
func passwordOK(r *http.Request, want string) bool {
	got := r.Header.Get("X-UI-Password")
	if got == "" {
		got = r.URL.Query().Get("ui_password")
	}
	gotSum := sha256.Sum256([]byte(got))
	wantSum := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotSum[:], wantSum[:]) == 1
}

// relInRoot 把绝对路径收敛成「相对于 rootDir 的相对路径」，越界即报错。
func relInRoot(rootDir, target string) (string, error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return "", err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absRoot, absTarget)
	if err != nil {
		return "", err
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("路径越界")
	}
	return rel, nil
}

// downloadHandler 证书/私钥下载：os.Root 沙箱打开，符号链接与 ".." 无法逃逸输出目录
func downloadHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filePath := strings.TrimSpace(r.URL.Query().Get("file"))
		if filePath == "" {
			http.Error(w, "缺少 file 参数", http.StatusBadRequest)
			return
		}
		root, err := os.OpenRoot(cfg.OutputBase)
		if err != nil {
			slog.Error("打开证书输出目录失败", "dir", cfg.OutputBase, "err", err)
			http.Error(w, "服务器错误", http.StatusInternalServerError)
			return
		}
		defer root.Close()

		rel, err := relInRoot(cfg.OutputBase, filePath)
		if err != nil {
			slog.Warn("下载请求路径越界", "file", filePath)
			http.Error(w, "非法路径", http.StatusBadRequest)
			return
		}
		f, err := root.Open(rel)
		if err != nil {
			http.Error(w, "文件不存在", http.StatusNotFound)
			return
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil || fi.IsDir() {
			http.Error(w, "文件不存在", http.StatusNotFound)
			return
		}

		name := filepath.Base(rel)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
		http.ServeContent(w, r, name, fi.ModTime(), f)
	}
}

func listHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := store.ListCerts(cfg.OutputBase, cfg.RenewBefore)
		if err != nil {
			slog.Error("证书列表查询失败", "err", err)
			writeError(w, err.Error())
			return
		}
		writeJSON(w, map[string]any{"certs": entries})
	}
}

func detailHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := store.ValidLeafName(name); err != nil {
			writeError(w, err.Error())
			return
		}
		dir := filepath.Join(cfg.OutputBase, name)
		info, err := store.ParseCertInDir(dir)
		if err != nil {
			slog.Error("证书详情查询失败", "name", name, "err", err)
			writeError(w, err.Error())
			return
		}
		writeJSON(w, info)
	}
}

func issueHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ca.IssueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("签发请求体解析失败", "err", err)
			writeError(w, "请求体解析失败")
			return
		}
		res, err := ca.Issue(cfg, req)
		if err != nil {
			slog.Error("签发失败", "name", req.Name, "err", err)
			writeError(w, err.Error())
			return
		}
		slog.Info("签发成功", "domain", res.Domain, "path", res.Path)
		writeJSON(w, map[string]any{
			"success":  true,
			"domain":   res.Domain,
			"path":     res.Path,
			"crt_file": res.CRTFile,
			"key_file": res.KeyFile,
		})
	}
}

func renewHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := ca.Renew(cfg, name); err != nil {
			slog.Error("续签失败", "name", name, "err", err)
			writeError(w, err.Error())
			return
		}
		slog.Info("续签成功", "name", name)
		writeJSON(w, map[string]any{"success": true})
	}
}

// reissueHandler 编辑重签：名称锁定，SAN/有效期/密钥类型/描述可改，原位替换旧证书
func reissueHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		var req ca.IssueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("编辑重签请求体解析失败", "err", err)
			writeError(w, "请求体解析失败")
			return
		}
		res, err := ca.Reissue(cfg, name, req)
		if err != nil {
			slog.Error("编辑重签失败", "name", name, "err", err)
			writeError(w, err.Error())
			return
		}
		slog.Info("编辑重签成功", "domain", res.Domain, "path", res.Path)
		writeJSON(w, map[string]any{
			"success":  true,
			"domain":   res.Domain,
			"path":     res.Path,
			"crt_file": res.CRTFile,
			"key_file": res.KeyFile,
		})
	}
}

func revokeHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := ca.Revoke(cfg, name); err != nil {
			slog.Error("吊销失败", "name", name, "err", err)
			writeError(w, err.Error())
			return
		}
		slog.Info("吊销成功", "name", name)
		writeJSON(w, map[string]any{"success": true})
	}
}

func deleteHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := store.DeleteCert(cfg.OutputBase, name); err != nil {
			slog.Error("删除失败", "name", name, "err", err)
			writeError(w, err.Error())
			return
		}
		slog.Info("删除成功", "name", name)
		writeJSON(w, map[string]any{"success": true})
	}
}

// importHandler 导入外部证书（仅归档，origin=imported）。
func importHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ca.ImportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("导入请求体解析失败", "err", err)
			writeError(w, "请求体解析失败")
			return
		}
		res, err := ca.Import(cfg, req)
		if err != nil {
			slog.Error("导入失败", "name", req.Name, "err", err)
			writeError(w, err.Error())
			return
		}
		slog.Info("导入成功", "name", res.Name, "path", res.Path)
		writeJSON(w, map[string]any{
			"success":  true,
			"name":     res.Name,
			"path":     res.Path,
			"crt_file": res.CRTFile,
			"key_file": res.KeyFile,
		})
	}
}

// startedAt 记录进程启动时刻，供首页「运行信息」计算运行时长。
var startedAt = time.Now()

// backendStatusHandler 返回内置 CA 就绪状态与进程运行信息。
func backendStatusHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ready, msg := ca.Health(cfg)
		if !ready {
			slog.Warn("内置 CA 未就绪", "message", msg)
		}
		writeJSON(w, map[string]any{
			"ready":          ready,
			"ca_home":        cfg.CAHome,
			"root_path":      ca.RootCertPath(cfg),
			"message":        msg,
			"revoked":        ca.RevokedCount(cfg),
			"version":        cfg.Version,
			"author_name":    cfg.AuthorName,
			"author_url":     cfg.AuthorURL,
			"port":           cfg.Port,
			"output_base":    cfg.OutputBase,
			"started_at":     startedAt,
			"uptime_seconds": int(time.Since(startedAt).Seconds()),
		})
	}
}

// backendRootRotateHandler 轮换根证书；服务端硬校验 confirm 必须等于当前根 CN
func backendRootRotateHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Confirm    string `json:"confirm"`
			KeyType    string `json:"key_type"`
			CAName     string `json:"ca_name"`
			ReissueAll bool   `json:"reissue_all"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{"success": false, "error": "请求体格式错误"})
			return
		}
		res, err := ca.RotateRoot(cfg, ca.RotateOptions{
			Confirm:    req.Confirm,
			KeyType:    req.KeyType,
			CAName:     req.CAName,
			ReissueAll: req.ReissueAll,
		})
		if err != nil {
			slog.Warn("根证书轮换未执行", "err", err)
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"success": true, "result": res})
	}
}

// backendRootArchivesHandler 列出 CA_HOME/archive 下的历史根，供回滚选择。
func backendRootArchivesHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := ca.ListRootArchives(cfg)
		if err != nil {
			slog.Warn("读取历史根归档失败", "err", err)
			writeJSONStatus(w, http.StatusInternalServerError, map[string]any{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"success": true, "archives": list})
	}
}

// backendRootRollbackHandler 回滚根证书；confirm 硬校验同轮换
func backendRootRollbackHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Confirm    string `json:"confirm"`
			Dir        string `json:"dir"`
			ReissueAll bool   `json:"reissue_all"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{"success": false, "error": "请求体格式错误"})
			return
		}
		res, err := ca.RollbackRoot(cfg, ca.RollbackOptions{
			Confirm:    req.Confirm,
			Dir:        req.Dir,
			ReissueAll: req.ReissueAll,
		})
		if err != nil {
			slog.Warn("根证书回滚未执行", "err", err)
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"success": true, "result": res})
	}
}

// backendCRLHandler CRL 下载；错误保持纯文本，前端 downloadPem 直接用作提示语
func backendCRLHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := ca.CRLPath(cfg)
		if _, err := os.Stat(path); err != nil {
			http.Error(w, "尚无吊销记录（未生成 CRL）", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename=crl.pem")
		http.ServeFile(w, r, path)
	}
}

// backendRootHandler 提供内置根证书下载（专线路由，仅允许根证书文件）。
func backendRootHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := ca.RootCertPath(cfg)
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename=root_ca.crt")
		http.ServeFile(w, r, path)
	}
}

// backendRootInfoHandler 返回根证书解析详情。
func backendRootInfoHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := ca.RootInfoOf(cfg)
		if info.Exists {
			slog.Info("根证书详情读取成功", "subject", info.Subject)
		} else {
			slog.Warn("根证书详情不可用", "err", info.Error)
		}
		writeJSON(w, info)
	}
}

// renewStatusHandler 返回自动续签调度状态。
func renewStatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, scheduler.Status())
	}
}

// renewScanHandler 手动触发扫描（异步）；started=false 表示已有扫描在跑被跳过
func renewScanHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		started := scheduler.ScanNow(cfg)
		if started {
			slog.Info("手动触发自动续签扫描")
		}
		writeJSON(w, map[string]any{"success": true, "started": started})
	}
}
