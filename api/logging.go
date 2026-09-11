package api

import (
	"log/slog"
	"net/http"
	"time"
)

// statusRecorder 捕获响应状态码与字节数，供访问日志使用。
type statusRecorder struct {
	http.ResponseWriter
	status int
	size   int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.size += n
	return n, err
}

// Unwrap 透传底层 ResponseWriter，让 http.ResponseController 之类的能力仍然可用。
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// LoggingMiddleware 访问日志；字段走 slog 结构化输出，含换行的路径无法伪造日志行
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		slog.Info("access",
			"remote", r.RemoteAddr,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"bytes", rec.size,
			"duration", time.Since(start).Round(time.Millisecond).String(),
		)
	})
}
