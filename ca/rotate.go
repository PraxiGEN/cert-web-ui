// Package ca 实现自建内置 CA：根证书生命周期、签发、续签、吊销与轮换。
package ca

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"cert-web-ui/config"
	"cert-web-ui/store"
)

// 归档相关约定：CA_HOME/archive/root-<时间戳>/ 内存放被替换下去的那一份根材料。
const (
	archiveDirName    = "archive"
	rootArchivePrefix = "root-"
	archiveStampFmt   = "20060102-150405"
)

// RotateOptions 是根证书轮换的入参。
type RotateOptions struct {
	Confirm    string // 必须与当前根证书的 CN 完全一致（服务端硬校验，防误触 / 防绕过前端）
	KeyType    string // 新根密钥类型：ec-p256（默认）/ ec-p384 / ec-p521 / rsa-2048 / rsa-4096
	CAName     string // 新根 CN，留空则沿用当前根 CN
	ReissueAll bool   // 是否立即用新根重签全部本系统签发的证书
}

// RollbackOptions 是根证书回滚的入参。
type RollbackOptions struct {
	Confirm    string // 必须与「当前」根证书的 CN 完全一致（服务端硬校验）
	Dir        string // 目标归档目录：目录名或绝对路径，最终都会被收敛到 CA_HOME/archive 之内
	ReissueAll bool   // 是否立即用该历史根重签全部本系统签发的证书
}

// RootSwapResult 是根证书轮换 / 回滚的统一结果，供前端展示与留档。
type RootSwapResult struct {
	Mode           string    `json:"mode"` // rotate | rollback
	OldSubject     string    `json:"old_subject"`
	NewSubject     string    `json:"new_subject"`
	NewKeyType     string    `json:"new_key_type"`
	NewNotAfter    time.Time `json:"new_not_after"`
	NewFingerprint string    `json:"new_fingerprint_sha256"`
	ArchiveDir     string    `json:"archive_dir"`    // 本次被替换下去的根归档到哪里
	SourceArchive  string    `json:"source_archive"` // 仅回滚：恢复的历史根取自哪里
	Reissued       int       `json:"reissued"`       // 重签成功数
	Failed         []string  `json:"failed"`         // 重签失败明细
	Untouched      int       `json:"untouched"`      // 导入证书数（无法重签，保持原样）
}

// RootArchive 描述 CA_HOME/archive 下的一份历史根材料。
type RootArchive struct {
	Dir         string    `json:"dir"`
	Name        string    `json:"name"`
	ArchivedAt  time.Time `json:"archived_at"`
	Subject     string    `json:"subject"`
	CommonName  string    `json:"common_name"`
	KeyType     string    `json:"key_type"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint_sha256"`
	HasKey      bool      `json:"has_key"`    // 私钥缺失或不配对时无法回滚
	IsCurrent   bool      `json:"is_current"` // 与当前根是同一张，回滚无意义
}

// ListRootArchives 列出全部历史根归档，按归档时间倒序；目录不存在时返回空列表。
func ListRootArchives(cfg config.Config) ([]RootArchive, error) {
	base := filepath.Join(cfg.CAHome, archiveDirName)
	ents, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return []RootArchive{}, nil
		}
		return nil, fmt.Errorf("读取归档目录失败: %w", err)
	}

	curFP := ""
	if cur, cerr := InitRoot(cfg); cerr == nil {
		sum := sha256.Sum256(cur.Cert.Raw)
		curFP = formatFingerprint(sum[:])
	}

	out := make([]RootArchive, 0, len(ents))
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), rootArchivePrefix) {
			continue
		}
		dir := filepath.Join(base, e.Name())
		item := RootArchive{Dir: dir, Name: e.Name(), ArchivedAt: dirTimestamp(e)}

		cert, _, perr := loadRootPair(filepath.Join(dir, rootCertName), filepath.Join(dir, rootKeyName))
		if perr == nil {
			item.HasKey = true
		} else {
			// 私钥缺失/不配对：仍可展示，但前端置灰不可选
			c, rerr := readCertFile(filepath.Join(dir, rootCertName))
			if rerr != nil {
				slog.Warn("跳过无法解析的归档", "archive", e.Name(), "err", rerr)
				continue
			}
			cert = c
		}
		item.Subject = cert.Subject.String()
		item.CommonName = cert.Subject.CommonName
		item.KeyType = pubKeyAlg(cert)
		item.NotAfter = cert.NotAfter
		sum := sha256.Sum256(cert.Raw)
		item.Fingerprint = formatFingerprint(sum[:])
		item.IsCurrent = curFP != "" && item.Fingerprint == curFP
		out = append(out, item)
	}

	slices.SortFunc(out, func(a, b RootArchive) int { return b.ArchivedAt.Compare(a.ArchivedAt) })
	return out, nil
}

// dirTimestamp 优先从归档目录名解析时间，失败退回归档文件的修改时间。
func dirTimestamp(e os.DirEntry) time.Time {
	if t, err := time.ParseInLocation(archiveStampFmt, strings.TrimPrefix(e.Name(), rootArchivePrefix), time.Local); err == nil {
		return t
	}
	if fi, err := e.Info(); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

// RotateRoot 轮换根证书：归档旧根 → 生成新根 →（可选）全量重签。
func RotateRoot(cfg config.Config, opts RotateOptions) (RootSwapResult, error) {
	// 持写锁：换根期间禁止签发/续签/吊销，避免孤儿证书
	swapMu.Lock()
	defer swapMu.Unlock()

	var res RootSwapResult

	cur, err := InitRoot(cfg)
	if err != nil {
		return res, fmt.Errorf("当前根 CA 不可用: %w", err)
	}
	curCN := cur.Cert.Subject.CommonName
	if strings.TrimSpace(opts.Confirm) != curCN {
		return res, fmt.Errorf("确认信息不匹配：需逐字输入当前根证书的名称「%s」", curCN)
	}
	res.Mode = "rotate"
	res.OldSubject = cur.Cert.Subject.String()

	caName := strings.TrimSpace(opts.CAName)
	if caName == "" {
		caName = curCN
	}

	// 先生成新根（纯内存，失败则现有根毫发无损）
	newCert, newKey, err := generateRoot(cfg, opts.KeyType, caName)
	if err != nil {
		return res, fmt.Errorf("生成新根失败: %w", err)
	}

	root, archiveDir, err := activateRoot(cfg, newCert, newKey)
	if err != nil {
		return res, err
	}
	res.ArchiveDir = archiveDir
	fillResult(&res, root)
	slog.Info("根证书已轮换", "from", curCN, "to", caName, "key_type", res.NewKeyType, "archive_dir", archiveDir)

	rebuildCRL(cfg, root)
	return finishSwap(cfg, &res, opts.ReissueAll, "轮换")
}

// RollbackRoot 把归档中的历史根恢复为当前根；当前根会被再归档，回滚可再回滚
func RollbackRoot(cfg config.Config, opts RollbackOptions) (RootSwapResult, error) {
	swapMu.Lock()
	defer swapMu.Unlock()

	var res RootSwapResult

	cur, err := InitRoot(cfg)
	if err != nil {
		return res, fmt.Errorf("当前根 CA 不可用: %w", err)
	}
	curCN := cur.Cert.Subject.CommonName
	if strings.TrimSpace(opts.Confirm) != curCN {
		return res, fmt.Errorf("确认信息不匹配：需逐字输入当前根证书的名称「%s」", curCN)
	}

	srcDir, err := resolveArchiveDir(cfg, opts.Dir)
	if err != nil {
		return res, err
	}
	cert, key, err := loadRootPair(filepath.Join(srcDir, rootCertName), filepath.Join(srcDir, rootKeyName))
	if err != nil {
		return res, fmt.Errorf("加载历史根失败（归档可能缺少私钥）: %w", err)
	}
	// 归档里必须是一张能签发的 CA 证书，否则装上去会让整个 PKI 失效
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return res, fmt.Errorf("归档中的证书不是可签发的 CA 证书，拒绝回滚")
	}
	// 与当前根是同一张：既无意义，又会让当前根被重复归档一份
	if publicKeysEqual(cur.Cert.PublicKey, cert.PublicKey) {
		return res, fmt.Errorf("目标归档与当前根证书相同，无需回滚")
	}

	res.Mode = "rollback"
	res.OldSubject = cur.Cert.Subject.String()
	res.SourceArchive = srcDir

	root, archiveDir, err := activateRoot(cfg, cert, key)
	if err != nil {
		return res, err
	}
	res.ArchiveDir = archiveDir
	fillResult(&res, root)
	slog.Info("根证书已回滚",
		"from", curCN, "to", cert.Subject.CommonName, "key_type", res.NewKeyType,
		"source_archive", srcDir, "archive_dir", archiveDir)

	rebuildCRL(cfg, root)
	return finishSwap(cfg, &res, opts.ReissueAll, "回滚")
}

// finishSwap 收尾：按需用新根重签全部已签发证书。
func finishSwap(cfg config.Config, res *RootSwapResult, reissueAll bool, verb string) (RootSwapResult, error) {
	if !reissueAll {
		return *res, nil
	}
	if err := reissueIssued(cfg, res); err != nil {
		return *res, err
	}
	slog.Info(verb+"后重签完成",
		"reissued", res.Reissued, "failed", len(res.Failed), "untouched", res.Untouched)
	return *res, nil
}

// activateRoot 备好新材料 → 归档旧根 → 落盘新根 → 换缓存；任一步失败把归档搬回，避免信任锚真空
func activateRoot(cfg config.Config, newCert *x509.Certificate, newKey crypto.Signer) (*RootCA, string, error) {
	newKeyDER, err := x509.MarshalPKCS8PrivateKey(newKey)
	if err != nil {
		return nil, "", fmt.Errorf("序列化新根私钥失败: %w", err)
	}

	archiveDir, err := uniqueArchiveDir(filepath.Join(cfg.CAHome, archiveDirName, rootArchivePrefix+time.Now().Format(archiveStampFmt)))
	if err != nil {
		return nil, "", err
	}

	// 归档旧根材料（revoked.json 不归档：按序列号保存，与新根不冲突）
	moved := make([]string, 0, 3)
	for _, name := range []string{rootCertName, rootKeyName, crlName} {
		src := filepath.Join(cfg.CAHome, name)
		if !fileExists(src) {
			continue
		}
		if err := os.Rename(src, filepath.Join(archiveDir, name)); err != nil {
			rollbackMoves(archiveDir, cfg.CAHome, moved)
			return nil, "", fmt.Errorf("归档旧根失败: %w", err)
		}
		moved = append(moved, name)
	}

	// 写入新根；任一步失败都把归档的旧根搬回来
	if err := writePEMFile(RootCertPath(cfg), "CERTIFICATE", newCert.Raw, 0o644); err != nil {
		rollbackMoves(archiveDir, cfg.CAHome, moved)
		return nil, "", fmt.Errorf("写入新根证书失败: %w", err)
	}
	if err := writePEMFile(RootKeyPath(cfg), "PRIVATE KEY", newKeyDER, 0o600); err != nil {
		rollbackMoves(archiveDir, cfg.CAHome, moved)
		return nil, "", fmt.Errorf("写入新根私钥失败: %w", err)
	}

	// 替换内存缓存：此后所有签发 / 续签 / 重签都用新的根
	root := &RootCA{Cert: newCert, Key: newKey}
	rootMu.Lock()
	rootCache = root
	rootMu.Unlock()
	return root, archiveDir, nil
}

// uniqueArchiveDir 秒级时间戳目录名可能撞名，追加序号避免静默覆盖上一份归档
func uniqueArchiveDir(base string) (string, error) {
	for i := 0; i < 1000; i++ {
		dir := base
		if i > 0 {
			dir = fmt.Sprintf("%s-%d", base, i)
		}
		if fileExists(dir) {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("创建归档目录失败: %w", err)
		}
		return dir, nil
	}
	return "", fmt.Errorf("创建归档目录失败：同名目录过多")
}

// rebuildCRL 用当前根重建 CRL。旧 CRL 由旧根签名，留着会让客户端验签失败。
func rebuildCRL(cfg config.Config, root *RootCA) {
	list, err := loadRevoked(cfg.CAHome)
	if err != nil || len(list) == 0 {
		return
	}
	if cerr := writeCRL(cfg.CAHome, root, list); cerr != nil {
		slog.Warn("新根 CRL 生成失败", "err", cerr)
	}
}

// reissueIssued 用当前根重签全部 issued 证书（已持写锁，走不加锁 renewLocked）
func reissueIssued(cfg config.Config, res *RootSwapResult) error {
	entries, err := store.ListCerts(cfg.OutputBase, cfg.RenewBefore)
	if err != nil {
		return fmt.Errorf("根已切换，但扫描证书失败: %w", err)
	}
	for _, e := range entries {
		if e.Origin == "imported" {
			res.Untouched++
			continue
		}
		if rerr := renewLocked(cfg, e.Name); rerr != nil {
			slog.Error("切换根后重签失败", "name", e.Name, "err", rerr)
			res.Failed = append(res.Failed, e.Name+"："+rerr.Error())
			continue
		}
		res.Reissued++
	}
	return nil
}

// fillResult 汇总「切换后的根」的展示字段。
func fillResult(res *RootSwapResult, root *RootCA) {
	sum := sha256.Sum256(root.Cert.Raw)
	res.NewSubject = root.Cert.Subject.String()
	res.NewKeyType = pubKeyAlg(root.Cert)
	res.NewNotAfter = root.Cert.NotAfter
	res.NewFingerprint = formatFingerprint(sum[:])
}

// resolveArchiveDir 只取路径末段做单层名校验后拼接，结果必然落在 archive 目录内
func resolveArchiveDir(cfg config.Config, raw string) (string, error) {
	name := filepath.Base(strings.TrimSpace(raw))
	if err := store.ValidLeafName(name); err != nil {
		return "", fmt.Errorf("归档目录名不合法：%w", err)
	}
	if !strings.HasPrefix(name, rootArchivePrefix) || name == rootArchivePrefix {
		return "", fmt.Errorf("归档目录名不合法：%q", raw)
	}
	dir := filepath.Join(cfg.CAHome, archiveDirName, name)
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return "", fmt.Errorf("归档目录不存在：%s", name)
	}
	return dir, nil
}

// rollbackMoves 把已归档的文件搬回原位（尽力而为，仅在写入新根失败时调用）。
func rollbackMoves(archiveDir, caHome string, names []string) {
	for _, n := range names {
		if err := os.Rename(filepath.Join(archiveDir, n), filepath.Join(caHome, n)); err != nil {
			slog.Error("回滚归档文件失败", "file", n, "err", err)
		}
	}
}
