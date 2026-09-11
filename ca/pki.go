package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cert-web-ui/config"
	"cert-web-ui/store"
)

// CA 数据目录内的固定文件名。
const (
	rootCertName = "root_ca.crt"
	rootKeyName  = "root_ca.key"
	revokedName  = "revoked.json"
	crlName      = "crl.pem"
)

// RootCA 进程内自建根 CA；根私钥只由本程序生成，不导入外部根
type RootCA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

var (
	rootMu    sync.Mutex
	rootCache *RootCA

	// swapMu 隔离「切根」与「用根签发」：签发类取读锁、轮换类取写锁；锁序 swapMu → rootMu
	swapMu sync.RWMutex
)

// RootCertPath 返回 CA_HOME/root_ca.crt，全部路径统一由此取，避免分叉
func RootCertPath(cfg config.Config) string {
	return filepath.Join(cfg.CAHome, rootCertName)
}

// RootKeyPath 返回根私钥的固定路径（CA_HOME/root_ca.key）。
func RootKeyPath(cfg config.Config) string {
	return filepath.Join(cfg.CAHome, rootKeyName)
}

// InitRoot 确保根 CA 就绪：已存在则加载，不存在则生成。幂等且并发安全。
func InitRoot(cfg config.Config) (*RootCA, error) {
	rootMu.Lock()
	defer rootMu.Unlock()
	if rootCache != nil {
		return rootCache, nil
	}
	if err := os.MkdirAll(cfg.CAHome, 0o700); err != nil {
		return nil, fmt.Errorf("创建 CA 目录失败: %w", err)
	}

	crtPath := RootCertPath(cfg)
	keyPath := RootKeyPath(cfg)

	// 已存在根证书：必须能加载成功，绝不静默覆盖（覆盖等于轮换根，客户端全部失效）
	if fileExists(crtPath) {
		cert, key, err := loadRootPair(crtPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("根 CA 已存在但加载失败: %w", err)
		}
		rootCache = &RootCA{Cert: cert, Key: key}
		slog.Info("根 CA 已加载", "cn", cert.Subject.CommonName, "not_after", cert.NotAfter.Format("2006-01-02"))
		return rootCache, nil
	}

	cert, key, err := generateRoot(cfg, cfg.RootKeyType, cfg.CAName)
	if err != nil {
		return nil, err
	}
	if err := writePEMFile(crtPath, "CERTIFICATE", cert.Raw, 0o644); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writePEMFile(keyPath, "PRIVATE KEY", der, 0o600); err != nil {
		return nil, err
	}
	rootCache = &RootCA{Cert: cert, Key: key}
	slog.Info("已生成新根 CA", "cn", cert.Subject.CommonName, "key_type", pubKeyAlg(cert), "not_after", cert.NotAfter.Format("2006-01-02"))
	return rootCache, nil
}

// generateRootKey 按类型生成根密钥对（未知类型回退 EC P-256）。
func generateRootKey(keyType string) (crypto.Signer, error) {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "ec-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ec-p521":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	default: // ec-p256
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}

// generateRoot 生成自签根证书（密钥类型由 keyType 决定，有效期取 cfg.RootValidity，默认 10 年）。
func generateRoot(cfg config.Config, keyType, caName string) (*x509.Certificate, crypto.Signer, error) {
	key, err := generateRootKey(keyType)
	if err != nil {
		return nil, nil, fmt.Errorf("生成根私钥失败: %w", err)
	}
	if strings.TrimSpace(caName) == "" {
		caName = cfg.CAName
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	validity := cfg.RootValidity
	if validity <= 0 {
		validity = 87600 * time.Hour
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: caName, Organization: []string{"Cert Web UI"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("生成根证书失败: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// readCertFile 只读取并解析 PEM 证书，不校验私钥（归档目录可能只留下证书）。
func readCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, fmt.Errorf("%s 不是合法 PEM", path)
	}
	return x509.ParseCertificate(b.Bytes)
}

// loadRootPair 从磁盘加载根证书与根私钥，并校验两者确实配对。
func loadRootPair(crtPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	cert, err := readCertFile(crtPath)
	if err != nil {
		return nil, nil, err
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	signer, err := parsePrivateKey(keyData)
	if err != nil {
		return nil, nil, err
	}
	// 私钥被错配会让签名校验全部失败，宁可启动即报错
	if !publicKeysEqual(cert.PublicKey, signer.Public()) {
		return nil, nil, fmt.Errorf("根私钥与根证书不匹配")
	}
	return cert, signer, nil
}

// publicKeysEqual 比较两个公钥是否一致（PKIX 编码后逐字节比对，兼容 EC / RSA）。
func publicKeysEqual(a, b any) bool {
	da, err1 := x509.MarshalPKIXPublicKey(a)
	db, err2 := x509.MarshalPKIXPublicKey(b)
	return err1 == nil && err2 == nil && bytes.Equal(da, db)
}

// leafKey 描述生成的叶子私钥。
type leafKey struct {
	Signer  crypto.Signer
	PEM     []byte
	KeyType string // 人类可读标签，如 "EC P-256"
	RSA     bool
}

// generateLeafKey 按前端选项生成密钥对。
func generateLeafKey(keyType string) (leafKey, error) {
	switch keyType {
	case "rsa-2048":
		return newRSAKey(2048, "RSA 2048")
	case "rsa-4096":
		return newRSAKey(4096, "RSA 4096")
	case "ec-p384":
		return newECKey(elliptic.P384(), "EC P-384")
	case "ec-p521":
		return newECKey(elliptic.P521(), "EC P-521")
	default: // ec-p256
		return newECKey(elliptic.P256(), "EC P-256")
	}
}

func newECKey(curve elliptic.Curve, label string) (leafKey, error) {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return leafKey{}, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return leafKey{}, err
	}
	return leafKey{
		Signer:  k,
		PEM:     pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
		KeyType: label,
	}, nil
}

func newRSAKey(bits int, label string) (leafKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return leafKey{}, err
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	return leafKey{
		Signer:  k,
		PEM:     pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}),
		KeyType: label,
		RSA:     true,
	}, nil
}

// parsePrivateKey 解析 PEM 私钥（兼容 EC / RSA / PKCS#8）。
func parsePrivateKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("私钥不是合法 PEM")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("不支持的私钥类型")
		}
		return s, nil
	default:
		return nil, fmt.Errorf("不支持的私钥类型: %s", block.Type)
	}
}

// buildLeafTemplate 构造叶子证书模板（自动区分 DNS 与 IP）。
func buildLeafTemplate(cn string, sans []string, validity time.Duration, rsaKey bool) (*x509.Certificate, error) {
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	if validity <= 0 {
		validity = 8760 * time.Hour
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if rsaKey {
		// RSA 需要 KeyEncipherment 才能参与 TLS 密钥传输
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	return tmpl, nil
}

// durationOf 解析前端传入的有效期字符串，非法或为空时回退到 cfg.LeafValidity。
func durationOf(cfg config.Config, s string) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil && d > 0 {
		return d
	}
	if cfg.LeafValidity > 0 {
		return cfg.LeafValidity
	}
	return 8760 * time.Hour
}

// randSerial 生成 128 位随机正序列号。
func randSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	b[0] &= 0x7f // 保证为正数
	return new(big.Int).SetBytes(b), nil
}

// writePEMFile 原子写入 PEM 文件（建目录由 store.WriteFileAtomic 内部完成）。
func writePEMFile(path, blockType string, der []byte, perm os.FileMode) error {
	return store.WriteFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), perm)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
