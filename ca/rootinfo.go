package ca

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"cert-web-ui/config"
)

// RootInfo 是 CA 根证书的解析详情（供「后端管理」展示与核验）。
type RootInfo struct {
	Exists       bool      `json:"exists"`
	Path         string    `json:"path"`
	Subject      string    `json:"subject"`
	CommonName   string    `json:"common_name"`
	Issuer       string    `json:"issuer"`
	Serial       string    `json:"serial"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	ExpiresInSec int64     `json:"expires_in_seconds"`
	DaysLeft     int       `json:"days_left"`
	Expired      bool      `json:"expired"`
	Fingerprint  string    `json:"fingerprint_sha256"`
	SigAlg       string    `json:"signature_algorithm"`
	PubKeyAlg    string    `json:"public_key_algorithm"`
	IsCA         bool      `json:"is_ca"`
	SelfSigned   bool      `json:"self_signed"`
	Error        string    `json:"error,omitempty"`
}

// RootInfoOf 解析根证书详情；缺失/错误写入 Error 字段而非返回 error，便于前端统一展示
func RootInfoOf(cfg config.Config) RootInfo {
	path := RootCertPath(cfg)
	info := RootInfo{Path: path}

	data, err := os.ReadFile(path)
	if err != nil {
		info.Error = "读取失败: " + err.Error()
		return info
	}
	block, _ := pem.Decode(data)
	if block == nil {
		info.Error = "文件不是合法的 PEM"
		return info
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		info.Error = "解析证书失败: " + err.Error()
		return info
	}
	info.Exists = true
	info.Subject = c.Subject.String()
	info.CommonName = c.Subject.CommonName
	info.Issuer = c.Issuer.String()
	info.Serial = c.SerialNumber.Text(16)
	info.NotBefore = c.NotBefore
	info.NotAfter = c.NotAfter
	info.ExpiresInSec = int64(time.Until(c.NotAfter).Seconds())
	info.DaysLeft = int(time.Until(c.NotAfter).Hours() / 24)
	info.Expired = time.Now().After(c.NotAfter)
	sum := sha256.Sum256(c.Raw)
	info.Fingerprint = formatFingerprint(sum[:])
	info.SigAlg = c.SignatureAlgorithm.String()
	info.PubKeyAlg = pubKeyAlg(c)
	info.IsCA = c.IsCA
	info.SelfSigned = c.Subject.String() == c.Issuer.String()
	return info
}

func pubKeyAlg(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = strings.ToUpper(fmt.Sprintf("%02x", x))
	}
	return strings.Join(parts, ":")
}
