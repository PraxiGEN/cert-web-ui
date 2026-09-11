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

	// 首次启动自动生成根 CA；已存在则加载，失败报错绝不覆盖
	if _, err := ca.InitRoot(cfg); err != nil {
		slog.Error("根 CA 初始化失败", "err", err)
	}

	// CSRF：UI_PASSWORD 为空时写接口可被跨站表单提交，cross-site 一律拒绝；无 Sec-Fetch-Site/Origin 的脚本请求放行。
	prot := http.NewCrossOriginProtection()

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: api.LoggingMiddleware(prot.Handler(api.NewRouter(cfg))),
		// WriteTimeout 留空：根轮换全量重签可能持续数十秒，不能被写超时掐断
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	scheduler.Start(cfg)

	// 优雅关停：给在途写盘请求留收尾时间，避免 docker stop 截断
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
