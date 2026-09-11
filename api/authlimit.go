package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// authLimiter 按来源 IP 记录密码失败次数：连续失败达到阈值后临时锁定，
// 缓解端口暴露时对访问密码的暴力枚举。仅进程内状态，重启即清零。
type authLimiter struct {
	mu      sync.Mutex
	fails   map[string]*failState
	max     int           // 连续失败阈值
	lockFor time.Duration // 锁定时长
}

type failState struct {
	count     int
	lockUntil time.Time
}

var authLimit = &authLimiter{fails: make(map[string]*failState), max: 5, lockFor: 30 * time.Second}

// clientIP 取来源 IP（RemoteAddr 去端口）。不信任 X-Forwarded-For：
// 直连场景下该头可被任意伪造，用它做限流键等于没有限流。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// blocked 返回该 IP 是否处于锁定中，以及剩余等待秒数。
func (l *authLimiter) blocked(ip string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.fails[ip]
	if !ok {
		return false, 0
	}
	remain := int(time.Until(st.lockUntil).Seconds()) + 1
	if remain > 0 {
		return true, remain
	}
	return false, 0
}

// recordFail 记一次失败；达到阈值进入锁定。条目过多时淘汰早已过期的记录防内存增长。
func (l *authLimiter) recordFail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.fails) > 1024 {
		cutoff := time.Now().Add(-time.Hour)
		for k, st := range l.fails {
			if st.lockUntil.Before(cutoff) {
				delete(l.fails, k)
			}
		}
	}
	st := l.fails[ip]
	if st == nil {
		st = &failState{}
		l.fails[ip] = st
	}
	st.count++
	if st.count >= l.max {
		st.lockUntil = time.Now().Add(l.lockFor)
		st.count = 0
	}
}

// recordOK 密码正确，清除该 IP 的失败记录。
func (l *authLimiter) recordOK(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}
