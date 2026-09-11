package ca

import (
	"fmt"
	"time"

	"cert-web-ui/config"
)

// Health 探测内置 CA 是否就绪（根证书可用且未过期）。
// 自建形态下无需网络探测：只要根证书能加载即可签发。
func Health(cfg config.Config) (bool, string) {
	root, err := InitRoot(cfg)
	if err != nil {
		return false, "内置 CA 未就绪：" + err.Error()
	}
	if !root.Cert.IsCA {
		return false, "根证书不是 CA 证书（缺少基本约束 CA:TRUE）"
	}
	if time.Now().After(root.Cert.NotAfter) {
		return false, fmt.Sprintf("根 CA 已于 %s 过期，需重新生成", root.Cert.NotAfter.Format("2006-01-02"))
	}
	return true, fmt.Sprintf("内置 CA 就绪（CN=%s，有效期至 %s）",
		root.Cert.Subject.CommonName, root.Cert.NotAfter.Format("2006-01-02"))
}
