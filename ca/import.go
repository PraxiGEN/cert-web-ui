package ca

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cert-web-ui/config"
	"cert-web-ui/store"
)

// ImportRequest 是导入证书的请求参数。
type ImportRequest struct {
	Name string `json:"name"` // 文件夹名（将清洗）
	CRT  string `json:"crt"`  // 证书 PEM（必填）
	Key  string `json:"key"`  // 私钥 PEM（可选）
}

// ImportResult 是导入成功后的返回。
type ImportResult struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	CRTFile string `json:"crt_file"`
	KeyFile string `json:"key_file,omitempty"`
}

// Import 将外部证书（及可选私钥）写入 OUTPUT_BASE/<name>/，标记为 imported（仅归档）。
// 该类证书不支持续签/吊销，仅用于集中查看与到期提醒。
func Import(cfg config.Config, req ImportRequest) (ImportResult, error) {
	name := SanitizeFolder(req.Name)
	if err := store.ValidLeafName(name); err != nil {
		return ImportResult{}, fmt.Errorf("名称不合法（仅允许英文/数字/连字符/下划线）：%w", err)
	}
	if strings.TrimSpace(req.CRT) == "" {
		return ImportResult{}, fmt.Errorf("证书内容不能为空")
	}

	// 校验证书 PEM 合法性与可解析
	info, err := store.ParseCertData([]byte(req.CRT))
	if err != nil {
		return ImportResult{}, fmt.Errorf("证书内容不是合法 PEM 证书: %v", err)
	}

	// 私钥可选：提供则校验为合法 PEM 私钥块
	if strings.TrimSpace(req.Key) != "" {
		if !isPEMPrivateKey(req.Key) {
			return ImportResult{}, fmt.Errorf("私钥内容不是合法的 PEM 私钥")
		}
	}

	outputDir := filepath.Join(cfg.OutputBase, name)
	if fi, serr := os.Stat(outputDir); serr == nil && fi.IsDir() {
		return ImportResult{}, fmt.Errorf("已存在同名文件夹 %q，导入中止以免覆盖已有证书", name)
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return ImportResult{}, err
	}

	crtPath := filepath.Join(outputDir, name+".crt")
	if err := store.WriteFileAtomic(crtPath, []byte(normalizePEM(req.CRT)), 0o644); err != nil {
		return ImportResult{}, err
	}

	res := ImportResult{Name: name, Path: outputDir, CRTFile: crtPath}

	if strings.TrimSpace(req.Key) != "" {
		keyPath := filepath.Join(outputDir, name+".key")
		if err := store.WriteFileAtomic(keyPath, []byte(normalizePEM(req.Key)), 0o600); err != nil {
			return ImportResult{}, err
		}
		res.KeyFile = keyPath
	}

	meta := store.Metadata{
		Domain:    info.Subject,
		Folder:    name,
		SANs:      append(info.DNSNames, info.IPs...),
		IssuedAt:  info.NotBefore,
		Serial:    info.Serial,
		ExpiresAt: info.NotAfter,
		Origin:    "imported",
		AutoRenew: false,
	}
	if err := store.WriteMeta(outputDir, meta); err != nil {
		return ImportResult{}, fmt.Errorf("写入元数据失败: %w", err)
	}

	return res, nil
}

// isPEMPrivateKey 校验文本中含至少一个 PEM 私钥块（类型为 *PRIVATE KEY）。
func isPEMPrivateKey(s string) bool {
	rest := []byte(s)
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return true
		}
		rest = next
	}
	return false
}

// normalizePEM 去除首尾空白并保证以换行结尾。
func normalizePEM(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}
