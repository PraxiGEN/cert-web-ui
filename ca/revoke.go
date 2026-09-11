package ca

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"cert-web-ui/config"
	"cert-web-ui/store"
)

// revokedRecord 是本地吊销列表中的一条记录。
type revokedRecord struct {
	Serial    string    `json:"serial"`
	Subject   string    `json:"subject"`
	Folder    string    `json:"folder"`
	RevokedAt time.Time `json:"revoked_at"`
}

// Revoke 在本地吊销记录中登记该证书（按序列号），并重新生成 CRL。
// 自建 CA 无 OCSP，吊销的落地形式就是 CA 目录下的 revoked.json + crl.pem。
func Revoke(cfg config.Config, folder string) error {
	swapMu.RLock()
	defer swapMu.RUnlock()
	return revokeLocked(cfg, folder)
}

// revokeLocked 是 Revoke 的加锁内核（换根流程持有写锁时直接调用）。
func revokeLocked(cfg config.Config, folder string) error {
	if err := store.ValidLeafName(folder); err != nil {
		return err
	}
	dir := filepath.Join(cfg.OutputBase, folder)
	crtPath, _ := findCertKey(dir)
	if crtPath == "" {
		return fmt.Errorf("目录 %s 中未找到证书", folder)
	}

	// 导入证书不由本根签发，把它的序列号写进本根签名的 CRL 既不生效，
	// 又会让 CRL 里出现解释不了的条目。
	if m, ok := store.ReadMeta(dir); ok && m.Origin == "imported" {
		return fmt.Errorf("导入的外部证书不支持吊销（它不由本 CA 签发）")
	}

	info, err := store.ParseCert(crtPath)
	if err != nil {
		return fmt.Errorf("解析证书失败: %w", err)
	}
	if info.Serial == "" {
		return fmt.Errorf("证书序列号为空，无法吊销")
	}

	root, err := InitRoot(cfg)
	if err != nil {
		return err
	}

	list, _ := loadRevoked(cfg.CAHome)
	dup := false
	for _, r := range list {
		if r.Serial == info.Serial {
			dup = true
			break
		}
	}
	if !dup {
		list = append(list, revokedRecord{
			Serial:    info.Serial,
			Subject:   info.Subject,
			Folder:    folder,
			RevokedAt: time.Now(),
		})
	}
	if err := saveRevoked(cfg.CAHome, list); err != nil {
		return err
	}
	if err := writeCRL(cfg.CAHome, root, list); err != nil {
		return fmt.Errorf("生成 CRL 失败: %w", err)
	}

	if m, ok := store.ReadMeta(dir); ok {
		m.Revoked = true
		m.RevokedAt = time.Now()
		_ = store.WriteMeta(dir, m)
	}
	return nil
}

// RevokedCount 返回本地吊销记录条数（供后端管理展示）。
func RevokedCount(cfg config.Config) int {
	list, _ := loadRevoked(cfg.CAHome)
	return len(list)
}

// CRLPath 返回 CRL 文件路径。
func CRLPath(cfg config.Config) string {
	return filepath.Join(cfg.CAHome, crlName)
}

func loadRevoked(caHome string) ([]revokedRecord, error) {
	b, err := os.ReadFile(filepath.Join(caHome, revokedName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var list []revokedRecord
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func saveRevoked(caHome string, list []revokedRecord) error {
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(filepath.Join(caHome, revokedName), b, 0o644)
}

// writeCRL 依据本地吊销记录生成 X.509 CRL（有效期 24 小时）。
func writeCRL(caHome string, root *RootCA, list []revokedRecord) error {
	now := time.Now()
	entries := make([]x509.RevocationListEntry, 0, len(list))
	for _, r := range list {
		serial, ok := new(big.Int).SetString(r.Serial, 16)
		if !ok {
			continue
		}
		rt := r.RevokedAt
		if rt.IsZero() {
			rt = now
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: rt,
		})
	}
	tmpl := &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    nextCRLNumber(filepath.Join(caHome, crlName), now),
		ThisUpdate:                now.Add(-time.Minute),
		NextUpdate:                now.Add(24 * time.Hour),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, root.Cert, root.Key)
	if err != nil {
		return err
	}
	return writePEMFile(filepath.Join(caHome, crlName), "X509 CRL", der, 0o644)
}

// nextCRLNumber 产出严格单调递增的 CRL 序号。
//
// RFC 5280 要求同一签发者的 CRL 序号只能增大：直接用 Unix 秒作序号时，
// 同一秒内连续两次生成（吊销后立刻重建）会撞出重复序号。
func nextCRLNumber(crlPath string, now time.Time) *big.Int {
	cur := big.NewInt(now.Unix())
	data, err := os.ReadFile(crlPath)
	if err != nil {
		return cur
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return cur
	}
	rl, perr := x509.ParseRevocationList(block.Bytes)
	if perr != nil || rl.Number == nil {
		return cur
	}
	if next := new(big.Int).Add(rl.Number, big.NewInt(1)); next.Cmp(cur) > 0 {
		return next
	}
	return cur
}
