package store

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertInfo 是从 .crt 中解析出的证书明细。
type CertInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Serial    string    `json:"serial"`
	DNSNames  []string  `json:"dns_names"`
	IPs       []string  `json:"ips"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// ParseCert 读取并解析证书文件。
func ParseCert(path string) (*CertInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertData(data)
}

// ParseCertData 从 PEM 数据中提取第一张 CERTIFICATE。
func ParseCertData(data []byte) (*CertInfo, error) {
	rest := data
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			return certToInfo(c), nil
		}
		rest = next
	}
	return nil, fmt.Errorf("未找到证书块")
}

func certToInfo(c *x509.Certificate) *CertInfo {
	info := &CertInfo{
		Subject:   c.Subject.CommonName,
		Issuer:    c.Issuer.CommonName,
		Serial:    c.SerialNumber.Text(16),
		DNSNames:  c.DNSNames,
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
	}
	for _, ip := range c.IPAddresses {
		info.IPs = append(info.IPs, ip.String())
	}
	return info
}

// ParseCertInDir 在目录中寻找 .crt 并解析。
func ParseCertInDir(dir string) (*CertInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".crt") {
			return ParseCert(filepath.Join(dir, e.Name()))
		}
	}
	return nil, fmt.Errorf("目录中未找到 .crt 文件")
}
