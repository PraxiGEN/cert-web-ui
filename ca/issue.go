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

// clampToRoot 把叶子有效期压到「当前根剩余寿命」之内（向下取整到分钟）。
//
// 客户端信任链条的终点就是这张根：叶子活得比根更久没有任何意义，
// 只会让证书在根过期之后依旧显示「未到期」，把真正的故障点藏起来。
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

// validateSAN 拒绝必然非法、且会污染文件名的 SAN 条目。
// 不追求完整的 DNS 名文法（那样会误伤 _acme-challenge 之类），只挡路径分隔符与不可见字符。
func validateSAN(s string) error {
	if s == "" || s == "." || s == ".." {
		return fmt.Errorf("SAN 不能为 %q", s)
	}
	if strings.ContainsAny(s, "/\\\x00\n\r\t ") {
		return fmt.Errorf("SAN %q 含非法字符（不允许空格、斜杠或控制字符）", s)
	}
	return nil
}

// certFileName 把域名转成安全的文件名主干。
// 与 SanitizeFolder 同一白名单（字母/数字/连字符/下划线，另放行点号）：
// 文件名会原样进入前端的下载链接与复制按钮，任何引号、括号都可能构成
// 存储型 XSS，所以这里不做「替换危险字符」而做「只保留安全字符」。
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

// Issue 使用内置根 CA 直接签发新证书（进程内完成，无外部依赖），并写入 metadata。
func Issue(cfg config.Config, req IssueRequest) (IssueResult, error) {
	// 全程持读锁：换根（写锁）期间不允许插入签名动作，
	// 否则会出现「证书由已经被归档的旧根签发」的孤儿。
	swapMu.RLock()
	defer swapMu.RUnlock()

	// 主域名(=证书 CN)可选：未填时从 SAN 第一行取。TLS 客户端只看 SAN，
	// 因此这里会把 CN 一并写进 SAN 列表，只填一个域名也完全有效。
	domain := strings.TrimSpace(req.Domain)
	sans := parseSANs(req.SANs)
	if domain == "" {
		if len(sans) == 0 {
			return IssueResult{}, fmt.Errorf("请至少填写一个域名 / SAN")
		}
		domain = sans[0]
	}
	if !slices.Contains(sans, domain) {
		sans = append([]string{domain}, sans...)
	}
	for _, s := range sans {
		if err := validateSAN(s); err != nil {
			return IssueResult{}, err
		}
	}

	// 名称即文件夹名；为空时回退用主域名。先按白名单清洗，再按单层路径校验，
	// 保证 "." / ".." / 带分隔符的名称根本进不到文件系统。
	folder := SanitizeFolder(req.Name)
	if folder == "" {
		folder = SanitizeFolder(domain)
	}
	if err := store.ValidLeafName(folder); err != nil {
		return IssueResult{}, fmt.Errorf("名称不合法（仅允许英文/数字/连字符/下划线）：%w", err)
	}

	root, err := InitRoot(cfg)
	if err != nil {
		return IssueResult{}, err
	}

	outputDir := filepath.Join(cfg.OutputBase, folder)
	// 同名文件夹一律拒绝：两个域名挤进同一目录时，findCertKey / ListCerts
	// 只按文件名字典序取到最后一张 .crt，另一张会静默隐身。
	if fi, serr := os.Stat(outputDir); serr == nil && fi.IsDir() {
		return IssueResult{}, fmt.Errorf("已存在同名文件夹 %q，请换一个名称，或先删除它", folder)
	}

	lk, err := generateLeafKey(req.KeyType)
	if err != nil {
		return IssueResult{}, fmt.Errorf("生成私钥失败: %w", err)
	}

	validity := clampToRoot(durationOf(cfg, req.Duration), root)
	if validity <= 0 {
		return IssueResult{}, fmt.Errorf("根证书已过期，无法签发新证书")
	}
	tmpl, err := buildLeafTemplate(domain, sans, validity, lk.RSA)
	if err != nil {
		return IssueResult{}, err
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Cert, lk.Signer.Public(), root.Key)
	if err != nil {
		return IssueResult{}, fmt.Errorf("签发失败: %w", err)
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return IssueResult{}, err
	}
	baseName := certFileName(domain)
	crtPath := filepath.Join(outputDir, baseName+".crt")
	keyPath := filepath.Join(outputDir, baseName+".key")

	if err := writePEMFile(crtPath, "CERTIFICATE", der, 0o644); err != nil {
		return IssueResult{}, err
	}
	if err := store.WriteFileAtomic(keyPath, lk.PEM, 0o600); err != nil {
		return IssueResult{}, err
	}

	meta := store.Metadata{
		Domain:    domain,
		Folder:    folder,
		SANs:      sans,
		KeyType:   lk.KeyType,
		Duration:  validity.String(),
		IssuedAt:  time.Now(),
		AutoRenew: req.AutoRenew,
		Origin:    "issued",
	}
	if info, perr := store.ParseCert(crtPath); perr == nil {
		meta.Serial = info.Serial
		meta.ExpiresAt = info.NotAfter
	}
	if err := store.WriteMeta(outputDir, meta); err != nil {
		return IssueResult{}, fmt.Errorf("写入元数据失败: %w", err)
	}

	return IssueResult{
		Domain:  domain,
		Path:    outputDir,
		CRTFile: crtPath,
		KeyFile: keyPath,
	}, nil
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
