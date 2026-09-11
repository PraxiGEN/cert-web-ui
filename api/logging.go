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

// LoggingMiddleware 记录每个请求的访问日志：远程地址、方法、路径、状态码、响应大小、耗时。
//
// 路径等来自请求的字段一律交给 slog 结构化输出。slog 会为含空格或换行的值加引号，
// 因此请求路径里编码出来的 %0A 无法再伪造出额外的日志行——
// 此前用 log.Printf 直接拼接时这是可被利用的日志注入。
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
