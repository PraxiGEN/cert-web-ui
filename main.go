package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cert-web-ui/api"
	"cert-web-ui/ca"
	"cert-web-ui/config"
	"cert-web-ui/scheduler"
)

func main() {
	// 结构化日志：来自请求的字段由 slog 自动转义，含换行的路径无法伪造额外日志行。
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg := config.Load()

	slog.Info("Cert Web UI 启动", "version", cfg.Version, "port", cfg.Port)
	slog.Info("内置 CA", "ca_home", cfg.CAHome, "root_validity", cfg.RootValidity.String())
	slog.Info("根证书", "path", ca.RootCertPath(cfg))
	slog.Info("证书输出目录", "output_base", cfg.OutputBase, "leaf_validity", cfg.LeafValidity.String())
	slog.Info("自动续签",
		"interval", cfg.RenewInterval.String(),
		"before", cfg.RenewBefore.String(),
		"password_required", cfg.UIPassword != "")

	// 确保根 CA 就绪：首次启动自动生成根证书（默认 EC P-256，10 年）
	if _, err := ca.InitRoot(cfg); err != nil {
		slog.Error("根 CA 初始化失败", "err", err)
	}

	// CSRF 防护：浏览器发起的跨站请求（Sec-Fetch-Site: cross-site）一律拒绝。
	//
	// UI_PASSWORD 默认为空，而 /api/certs/{name}/revoke、/renew、/api/renew/scan
	// 都不读请求体，可以被任意网页用 <form> 以简单请求跨站提交——恶意页面
	// 因此能直接吊销本机的证书。不带 Sec-Fetch-Site / Origin 的请求
	// （curl、脚本、监控探针）不算跨站，照常放行。
	prot := http.NewCrossOriginProtection()

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: api.LoggingMiddleware(prot.Handler(api.NewRouter(cfg))),
		// 只对「读」设超时：慢速请求头（Slowloris）是外部可达的攻击面。
		// WriteTimeout 刻意留空——轮换根证书（生成 RSA 4096 并对全部证书重签）
		// 可能持续数十秒，写入超时会把这类长任务半路掐断。
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	scheduler.Start(cfg)

	// 收到 SIGINT / SIGTERM 后停止接收新连接，并给在途请求留出收尾时间，
	// 避免 docker stop 时把正在写盘的操作拦腰截断。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("HTTP 服务已监听", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		slog.Error("HTTP 服务异常退出", "err", err)
		os.Exit(1)
	case <-ctx.Done():
		slog.Info("收到退出信号，开始优雅关停", "cause", context.Cause(ctx))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("优雅关停超时，可能有请求未收尾", "err", err)
	}
	slog.Info("已退出")
}
