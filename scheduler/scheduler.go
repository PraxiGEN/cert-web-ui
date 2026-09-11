package scheduler

import (
	"log/slog"
	"sync"
	"time"

	"cert-web-ui/ca"
	"cert-web-ui/config"
	"cert-web-ui/store"
)

// State 是自动续签调度的可观测状态（供 API 只读展示）。
type State struct {
	Interval  string    `json:"interval"`           // 扫描间隔
	Before    string    `json:"before"`             // 临期阈值
	LastScan  time.Time `json:"last_scan,omitzero"` // 上次扫描开始时间
	NextScan  time.Time `json:"next_scan,omitzero"` // 下次预计扫描时间
	Total     int       `json:"total"`              // 证书总数
	AutoRenew int       `json:"auto_renew"`         // 加入自动续签的证书数
	Renewed   int       `json:"renewed"`            // 上次扫描续签成功数
	Failed    int       `json:"failed"`             // 上次扫描续签失败数
	Running   bool      `json:"running"`            // 是否有扫描正在执行
}

var (
	mu    sync.Mutex // 保护 state
	state State

	// scanMu 保证同一时刻只有一轮扫描在执行。
	scanMu sync.Mutex
)

// Status 返回当前调度状态快照。
func Status() State {
	mu.Lock()
	defer mu.Unlock()
	return state
}

// Start 启动后台自动续签调度（非阻塞）。
func Start(cfg config.Config) {
	mu.Lock()
	state.Interval = cfg.RenewInterval.String()
	state.Before = cfg.RenewBefore.String()
	mu.Unlock()

	slog.Info("自动续签订时器启动",
		"interval", cfg.RenewInterval.String(), "before", cfg.RenewBefore.String())

	go func() {
		// 启动即统计一次（只统计、不续签），避免首次扫描前「证书总数 / 自动续签」长期显示 0
		refreshCounts(cfg)

		ticker := time.NewTicker(cfg.RenewInterval)
		defer ticker.Stop()

		// 启动后延迟半个周期再首次执行，避免启动即触发
		mu.Lock()
		state.NextScan = time.Now().Add(cfg.RenewInterval / 2)
		mu.Unlock()
		time.Sleep(cfg.RenewInterval / 2)
		TryRun(cfg)

		for range ticker.C {
			TryRun(cfg)
		}
	}()
}

// refreshCounts 只刷新证书总数与自动续签数，不产生任何续签副作用。
func refreshCounts(cfg config.Config) {
	entries, err := store.ListCerts(cfg.OutputBase, cfg.RenewBefore)
	if err != nil {
		slog.Warn("证书数量统计失败", "err", err)
		return
	}
	total, auto := 0, 0
	for _, e := range entries {
		total++
		if e.AutoRenew {
			auto++
		}
	}
	mu.Lock()
	state.Total = total
	state.AutoRenew = auto
	mu.Unlock()
}

// ScanNow 立即触发一次扫描（异步执行），返回是否真的启动了。
//
// 已有一轮在跑时直接跳过：两轮扫描同时重签同一张证书会并发写同一个 .crt，
// 落盘结果取决于谁的 rename 后到，中途还会产生「读到半张证书」的窗口。
func ScanNow(cfg config.Config) bool {
	if !scanMu.TryLock() {
		slog.Warn("已有自动续签扫描在执行，跳过本次触发")
		return false
	}
	go func() {
		defer scanMu.Unlock()
		runOnce(cfg)
	}()
	return true
}

// TryRun 以「不重叠」的方式同步执行一轮扫描；已有扫描在跑时返回 false。
func TryRun(cfg config.Config) bool {
	if !scanMu.TryLock() {
		slog.Warn("已有自动续签扫描在执行，跳过本轮定时扫描")
		return false
	}
	defer scanMu.Unlock()
	runOnce(cfg)
	return true
}

// runOnce 执行一轮扫描：统计证书并将临期 / 过期的自动续签证书逐个续签。
// 调用方必须已持有 scanMu，本函数不再重复加锁。
func runOnce(cfg config.Config) {
	start := time.Now()
	mu.Lock()
	state.Running = true
	mu.Unlock()

	entries, err := store.ListCerts(cfg.OutputBase, cfg.RenewBefore)
	if err != nil {
		slog.Error("自动续签扫描失败", "err", err)
		mu.Lock()
		state.Running = false
		state.LastScan = start
		mu.Unlock()
		return
	}

	total, auto := 0, 0
	for _, e := range entries {
		total++
		if e.AutoRenew {
			auto++
		}
	}
	slog.Info("自动续签扫描开始", "total", total, "auto_renew", auto)

	renewed, failed := 0, 0
	for _, e := range entries {
		if !e.AutoRenew {
			continue
		}
		if e.Expired || e.Warning {
			if err := ca.Renew(cfg, e.Name); err != nil {
				slog.Error("自动续签失败", "name", e.Name, "err", err)
				failed++
			} else {
				slog.Info("自动续签成功", "name", e.Name)
				renewed++
			}
		}
	}

	mu.Lock()
	state.Total = total
	state.AutoRenew = auto
	state.Renewed = renewed
	state.Failed = failed
	state.LastScan = start
	state.NextScan = time.Now().Add(cfg.RenewInterval)
	state.Running = false
	mu.Unlock()
}
