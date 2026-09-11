package ca

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"cert-web-ui/config"
	"cert-web-ui/store"
)

// clampToRoot 叶子有效期压到当前根剩余寿命内：叶子活得比根久只会掩盖故障
func clampToRoot(validity time.Duration, root *RootCA) time.Duration {
	remaining := time.Until(root.Cert.NotAfter).Truncate(time.Minute)
	if remaining <= 0 {
		return 0
	}
	if validity > remaining {
		return remaining
	}
	return validity
}

// validateSAN 只挡路径分隔符与不可见字符，不做完整 DNS 文法（避免误伤 _acme-challenge）
func validateSAN(s string) error {
	if s == "" || s == "." || s == ".." {
		return fmt.Errorf("SAN 不能为 %q", s)
	}
	if strings.ContainsAny(s, "/\\\x00\n\r\t ") {
		return fmt.Errorf("SAN %q 含非法字符（不允许空格、斜杠或控制字符）", s)
	}
	return nil
}

// certFileName 白名单转安全文件名：文件名进入下载链接与 onclick，任何引号括号都是存储型 XSS
func certFileName(domain string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(domain) {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		}
	}
	name := strings.Trim(b.String(), ".")
	if name == "" {
		name = "cert"
	}
	return name
}

// leafArtifact 一次签发的中间产物：解析后的目标 + 密钥 + 证书 DER
type leafArtifact struct {
	domain   string
	sans     []string
	folder   string
	der      []byte
	key      leafKey
	validity time.Duration
}

// resolveTarget 解析并校验主域名、SAN 列表与文件夹名；folderFrom 非空时文件夹名以它为准（编辑重签：名称锁定）
func resolveTarget(req IssueRequest, folderFrom string) (domain, folder string, sans []string, err error) {
	domain = strings.TrimSpace(req.Domain)
	sans = parseSANs(req.SANs)
	if domain == "" {
		if len(sans) == 0 {
			return "", "", nil, fmt.Errorf("请至少填写一个域名 / SAN")
		}
		domain = sans[0]
	}
	if !slices.Contains(sans, domain) {
		sans = append([]string{domain}, sans...)
	}
	for _, s := range sans {
		if err = validateSAN(s); err != nil {
			return "", "", nil, err
		}
	}

	folder = SanitizeFolder(folderFrom)
	if folder == "" {
		folder = SanitizeFolder(req.Name)
	}
	if folder == "" {
		folder = SanitizeFolder(domain)
	}
	if err = store.ValidLeafName(folder); err != nil {
		return "", "", nil, fmt.Errorf("名称不合法（仅允许英文/数字/连字符/下划线）：%w", err)
	}
	return domain, folder, sans, nil
}

// signLeaf 在换根读锁内生成私钥并用当前根签出叶子证书
func signLeaf(cfg config.Config, domain string, sans []string, req IssueRequest) (leafArtifact, error) {
	var a leafArtifact

	// 持读锁：换根（写锁）期间禁止签发，避免出现旧根签发的孤儿证书
	swapMu.RLock()
	defer swapMu.RUnlock()

	root, err := InitRoot(cfg)
	if err != nil {
		return a, err
	}

	a.key, err = generateLeafKey(req.KeyType)
	if err != nil {
		return a, fmt.Errorf("生成私钥失败: %w", err)
	}

	a.validity = clampToRoot(durationOf(cfg, req.Duration), root)
	if a.validity <= 0 {
		return a, fmt.Errorf("根证书已过期，无法签发新证书")
	}

	tmpl, err := buildLeafTemplate(domain, sans, a.validity, a.key.RSA)
	if err != nil {
		return a, err
	}

	a.der, err = x509.CreateCertificate(rand.Reader, tmpl, root.Cert, a.key.Signer.Public(), root.Key)
	if err != nil {
		return a, fmt.Errorf("签发失败: %w", err)
	}
	a.domain, a.sans = domain, sans
	return a, nil
}

// writeLeaf 证书/私钥/元数据落盘；replace=true（编辑重签）先移除目录内旧 .crt/.key，避免主域名变更后残留旧文件
func writeLeaf(outputDir string, replace bool, req IssueRequest, a leafArtifact) (IssueResult, error) {
	if replace {
		items, err := os.ReadDir(outputDir)
		if err != nil {
			return IssueResult{}, err
		}
		for _, it := range items {
			if it.IsDir() {
				continue
			}
			if strings.HasSuffix(it.Name(), ".crt") || strings.HasSuffix(it.Name(), ".key") {
				if err := os.Remove(filepath.Join(outputDir, it.Name())); err != nil {
					return IssueResult{}, fmt.Errorf("清理旧证书文件失败: %w", err)
				}
			}
		}
	} else if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return IssueResult{}, err
	}

	baseName := certFileName(a.domain)
	crtPath := filepath.Join(outputDir, baseName+".crt")
	keyPath := filepath.Join(outputDir, baseName+".key")

	if err := writePEMFile(crtPath, "CERTIFICATE", a.der, 0o644); err != nil {
		return IssueResult{}, err
	}
	if err := store.WriteFileAtomic(keyPath, a.key.PEM, 0o600); err != nil {
		return IssueResult{}, err
	}

	meta := store.Metadata{
		Domain:      a.domain,
		Folder:      a.folder,
		SANs:        a.sans,
		KeyType:     a.key.KeyType,
		Duration:    a.validity.String(),
		IssuedAt:    time.Now(),
		AutoRenew:   req.AutoRenew,
		Origin:      "issued",
		Description: store.SanitizeDescription(req.Description),
	}
	if info, perr := store.ParseCert(crtPath); perr == nil {
		meta.Serial = info.Serial
		meta.ExpiresAt = info.NotAfter
	}
	if err := store.WriteMeta(outputDir, meta); err != nil {
		return IssueResult{}, fmt.Errorf("写入元数据失败: %w", err)
	}

	return IssueResult{
		Domain:  a.domain,
		Path:    outputDir,
		CRTFile: crtPath,
		KeyFile: keyPath,
	}, nil
}

// Issue 使用内置根 CA 直接签发新证书（进程内完成，无外部依赖），并写入 metadata。
func Issue(cfg config.Config, req IssueRequest) (IssueResult, error) {
	domain, folder, sans, err := resolveTarget(req, "")
	if err != nil {
		return IssueResult{}, err
	}

	outputDir := filepath.Join(cfg.OutputBase, folder)
	// 同名文件夹一律拒绝：挤同一目录会让另一张证书静默隐身
	if fi, serr := os.Stat(outputDir); serr == nil && fi.IsDir() {
		return IssueResult{}, fmt.Errorf("已存在同名文件夹 %q，请换一个名称，或先删除它", folder)
	}

	a, err := signLeaf(cfg, domain, sans, req)
	if err != nil {
		return IssueResult{}, err
	}
	a.folder = folder
	return writeLeaf(outputDir, false, req, a)
}

// Reissue 编辑重签：名称锁定，同一文件夹内换新私钥重签并整体替换旧证书/私钥/元数据
func Reissue(cfg config.Config, name string, req IssueRequest) (IssueResult, error) {
	if err := store.ValidLeafName(name); err != nil {
		return IssueResult{}, err
	}
	folder := SanitizeFolder(name)
	outputDir := filepath.Join(cfg.OutputBase, folder)
	if fi, serr := os.Stat(outputDir); serr != nil || !fi.IsDir() {
		return IssueResult{}, fmt.Errorf("证书 %q 不存在，无法编辑重签", folder)
	}
	// 与 Renew 同一守卫：导入的外部证书只作归档，不能进签发流程
	if meta, hasMeta := store.ReadMeta(outputDir); hasMeta && meta.Origin == "imported" {
		return IssueResult{}, fmt.Errorf("导入的外部证书不支持编辑重签，可删除后重新导入")
	}

	domain, _, sans, err := resolveTarget(req, folder)
	if err != nil {
		return IssueResult{}, err
	}

	a, err := signLeaf(cfg, domain, sans, req)
	if err != nil {
		return IssueResult{}, err
	}
	a.folder = folder
	return writeLeaf(outputDir, true, req, a)
}

func parseSANs(s string) []string {
	var out []string
	for line := range strings.SplitSeq(s, "\n") {
		san := strings.TrimSpace(line)
		if san != "" {
			out = append(out, san)
		}
	}
	return out
}
