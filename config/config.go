package config

import (
	"os"
	"path/filepath"
	"time"
)

// Config 集中存放所有环境变量配置。
// 内置 CA 形态：根 CA 与签发密钥都在本进程内管理，无任何外部依赖。
type Config struct {
	CAHome        string        // CA 数据目录（根证书、根私钥、吊销记录、CRL 都在这里）
	CAName        string        // 根 CA 的 CN
	RootKeyType   string        // 根 CA 密钥类型（ec-p256 默认 / ec-p384 / ec-p521 / rsa-2048 / rsa-4096）
	OutputBase    string        // 证书输出目录
	RootValidity  time.Duration // 根 CA 有效期（默认 10 年）
	LeafValidity  time.Duration // 叶子证书默认有效期（默认 1 年）
	UIPassword    string        // 访问门禁密码（为空则不校验）
	RenewInterval time.Duration // 后台续签扫描周期
	RenewBefore   time.Duration // 临期阈值（剩余时间小于该值即预警并尝试续签）
	Port          string        // 监听端口
	IndexPath     string        // 前端 index.html 路径
	Version       string        // 应用版本号（日志与页面共用同一来源）
	AuthorName    string        // 作者 / 项目名（硬编码，随二进制发布）
	AuthorURL     string        // 作者链接（硬编码，留空则前端不渲染为链接）
}

// authorName / authorURL 是编译期元数据：改作者信息只动这里，重新构建即生效，
// 不走环境变量——它和版本号一样属于「这份二进制是谁的产物」，而非部署期配置。
var (
	authorName = "作者"
	authorURL  = "" // 改为你的 GitHub / 联系方式链接（留空则不跳转）
)

// Load 从环境变量读取配置，缺失时使用默认值。
//
// 根证书路径刻意不单独配置：它恒为 CA_HOME/root_ca.crt，与轮换、归档、CRL 的落盘
// 位置共用同一个目录常量。此前存在 CA_ROOT_CERT 变量，只有展示与下载读它、
// 而真正的加载/生成/归档全部走 CA_HOME，一旦设置就变成「页面显示 A、实际在用 B」。
func Load() Config {
	home := getenv("CA_HOME", "/data")
	c := Config{
		CAHome:      home,
		CAName:      getenv("CA_NAME", "Cert Web UI Root CA"),
		RootKeyType: getenv("CA_ROOT_KEY_TYPE", "ec-p256"),
		OutputBase:  getenv("CERT_OUTPUT_BASE", filepath.Join(home, "certs")),
		UIPassword:  os.Getenv("UI_PASSWORD"),
		Port:        getenv("PORT", "8080"),
		IndexPath:   getenv("INDEX_HTML", "web/index.html"),
		Version:     getenv("APP_VERSION", "v1.0.0"),

		AuthorName: authorName,
		AuthorURL:  authorURL,
	}
	// 根 CA 默认 10 年（87600h）；叶子证书默认 1 年（8760h）
	c.RootValidity = parseDur(getenv("CA_ROOT_VALIDITY", "87600h"), 87600*time.Hour)
	c.LeafValidity = parseDur(getenv("CA_LEAF_VALIDITY", "8760h"), 8760*time.Hour)
	c.RenewInterval = parseDur(getenv("RENEW_INTERVAL", "24h"), 24*time.Hour)
	c.RenewBefore = parseDur(getenv("RENEW_BEFORE", "720h"), 720*time.Hour)
	return c
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func parseDur(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
