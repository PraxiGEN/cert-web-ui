package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cert-web-ui/config"
	"cert-web-ui/store"
)

// Renew 用原私钥按当前根重签（保留 CN/SAN）并刷新 metadata，私钥字节不变
func Renew(cfg config.Config, folder string) error {
	swapMu.RLock()
	defer swapMu.RUnlock()
	return renewLocked(cfg, folder)
}

// renewLocked 不加锁内核：换根流程已持写锁，RWMutex 不可重入，重签统一走这里
func renewLocked(cfg config.Config, folder string) error {
	if err := store.ValidLeafName(folder); err != nil {
		return err
	}
	dir := filepath.Join(cfg.OutputBase, folder)
	crtPath, keyPath := findCertKey(dir)
	if crtPath == "" {
		return fmt.Errorf("目录 %s 中未找到证书", folder)
	}
	if keyPath == "" {
		return fmt.Errorf("未找到私钥，无法续签（证书需与私钥同目录）")
	}

	meta, hasMeta := store.ReadMeta(dir)
	if hasMeta && meta.Origin == "imported" {
		return fmt.Errorf("导入的外部证书不支持续签")
	}

	old, err := store.ParseCert(crtPath)
	if err != nil {
		return fmt.Errorf("解析现有证书失败: %w", err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("读取私钥失败: %w", err)
	}
	signer, err := parsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("解析私钥失败: %w", err)
	}

	root, err := InitRoot(cfg)
	if err != nil {
		return err
	}

	// 沿用原有效期，metadata 缺失回退默认 1 年
	validity := cfg.LeafValidity
	if hasMeta && strings.TrimSpace(meta.Duration) != "" {
		if d, e := time.ParseDuration(meta.Duration); e == nil && d > 0 {
			validity = d
		}
	}
	validity = clampToRoot(validity, root)
	if validity <= 0 {
		return fmt.Errorf("根证书已过期，无法续签")
	}

	sans := append([]string{}, old.DNSNames...)
	sans = append(sans, old.IPs...)
	if len(sans) == 0 {
		sans = []string{old.Subject}
	}

	_, isRSA := signer.(*rsa.PrivateKey)
	tmpl, err := buildLeafTemplate(old.Subject, sans, validity, isRSA)
	if err != nil {
		return err
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Cert, signer.Public(), root.Key)
	if err != nil {
		return fmt.Errorf("续签失败: %w", err)
	}
	if err := writePEMFile(crtPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}

	if hasMeta {
		if info, perr := store.ParseCert(crtPath); perr == nil {
			meta.Serial = info.Serial
			meta.ExpiresAt = info.NotAfter
		}
		meta.IssuedAt = time.Now()
		// 新证书是新序列号，清除此前的吊销标记
		meta.Revoked = false
		meta.RevokedAt = time.Time{}
		if err := store.WriteMeta(dir, meta); err != nil {
			return fmt.Errorf("写入元数据失败: %w", err)
		}
	}
	return nil
}
