package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Metadata 与 .crt/.key 同目录存放；时间字段用 omitzero（omitempty 对结构体字段永不判空）
type Metadata struct {
	Domain      string    `json:"domain"`
	Folder      string    `json:"folder"`
	SANs        []string  `json:"sans"`
	KeyType     string    `json:"key_type"`
	Duration    string    `json:"duration"`
	IssuedAt    time.Time `json:"issued_at"`
	AutoRenew   bool      `json:"auto_renew"`
	Serial      string    `json:"serial,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitzero"`
	Origin      string    `json:"origin,omitempty"` // issued（本系统签发）/ imported（导入归档）
	Revoked     bool      `json:"revoked,omitempty"`
	RevokedAt   time.Time `json:"revoked_at,omitzero"`
	Description string    `json:"description,omitempty"` // 备注描述（纯展示，支持中文）
}

// CertEntry 是列表/详情返回给前端的证书条目。
type CertEntry struct {
	Name      string    `json:"name"`     // 文件夹名
	Folder    string    `json:"folder"`   // 完整目录
	Domain    string    `json:"domain"`   // 主域名
	CRT       string    `json:"crt"`      // .crt 完整路径
	Key       string    `json:"key"`      // .key 完整路径（可能为空）
	HasKey    bool      `json:"has_key"`
	SANs      []string  `json:"sans"`
	KeyType   string    `json:"key_type"`
	Duration  string    `json:"duration,omitempty"` // 签发时长（如 8760h0m0s），编辑重签预填用
	AutoRenew bool      `json:"auto_renew"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresIn int64     `json:"expires_in_seconds"`
	Warning   bool      `json:"warning"` // 临期
	Expired   bool      `json:"expired"` // 已过期
	Origin    string    `json:"origin"`  // issued / imported
	Revoked   bool      `json:"revoked"` // 已吊销
	RevokedAt time.Time `json:"revoked_at,omitzero"`
	Desc      string    `json:"description,omitempty"` // 备注描述
}

const metaFile = "metadata.json"

// MetaPath 返回某目录下 metadata 文件的完整路径。
func MetaPath(dir string) string { return filepath.Join(dir, metaFile) }

// WriteMeta 将元数据原子写入目录下的 metadata.json。
func WriteMeta(dir string, m Metadata) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(MetaPath(dir), b, 0o644)
}

// ReadMeta 读取目录下的 metadata.json，不存在或损坏时返回 false。
func ReadMeta(dir string) (Metadata, bool) {
	var m Metadata
	b, err := os.ReadFile(MetaPath(dir))
	if err != nil {
		return m, false
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, false
	}
	return m, true
}

// ValidLeafName 名字拼进路径前的最后一道硬门槛（此前前缀比对在 name="." 时形同虚设）
func ValidLeafName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("名称不能为空")
	case name == "." || name == "..":
		return fmt.Errorf("名称不能是 %q", name)
	case strings.ContainsAny(name, "/\\\x00"):
		return fmt.Errorf("名称不能包含路径分隔符")
	case filepath.Base(name) != name:
		return fmt.Errorf("名称不是合法的单层路径")
	}
	return nil
}

// SanitizeDescription 描述是纯展示文本：去控制字符（防日志/渲染注入）、TrimSpace、限长 200 字符
func SanitizeDescription(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	rs := []rune(strings.TrimSpace(b.String()))
	if len(rs) > 200 {
		rs = rs[:200]
	}
	return string(rs)
}

// ListCerts 扫描输出目录返回全部证书条目，renewBefore 用于临期预警
func ListCerts(outputBase string, renewBefore time.Duration) ([]CertEntry, error) {
	entries, err := os.ReadDir(outputBase)
	if err != nil {
		if os.IsNotExist(err) {
			return []CertEntry{}, nil
		}
		return nil, err
	}

	var out []CertEntry
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(outputBase, e.Name())
		items, _ := os.ReadDir(dir)
		var crt, key string
		for _, it := range items {
			if it.IsDir() {
				continue
			}
			switch {
			case strings.HasSuffix(it.Name(), ".crt"):
				crt = filepath.Join(dir, it.Name())
			case strings.HasSuffix(it.Name(), ".key"):
				key = filepath.Join(dir, it.Name())
			}
		}
		if crt == "" {
			continue
		}

		entry := CertEntry{
			Name:   e.Name(),
			Folder: dir,
			CRT:    crt,
			Key:    key,
			HasKey: key != "",
			Origin: "issued",
		}

		if m, ok := ReadMeta(dir); ok {
			entry.Domain = m.Domain
			entry.KeyType = m.KeyType
			entry.Duration = m.Duration
			entry.AutoRenew = m.AutoRenew
			entry.Serial = m.Serial
			entry.IssuedAt = m.IssuedAt
			entry.SANs = m.SANs
			entry.Revoked = m.Revoked
			entry.RevokedAt = m.RevokedAt
			entry.Desc = m.Description
			if m.Origin != "" {
				entry.Origin = m.Origin
			}
		}

		if info, perr := ParseCert(crt); perr == nil {
			entry.Serial = info.Serial
			entry.NotAfter = info.NotAfter
			entry.NotBefore = info.NotBefore
			entry.Domain = info.Subject
			if len(entry.SANs) == 0 {
				entry.SANs = append(info.DNSNames, info.IPs...)
			}
		}

		if !entry.NotAfter.IsZero() {
			diff := time.Until(entry.NotAfter)
			entry.ExpiresIn = int64(diff.Seconds())
			entry.Expired = diff <= 0
			entry.Warning = diff > 0 && diff <= renewBefore
		}

		out = append(out, entry)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// DeleteCert 用 os.Root 沙箱删除证书目录：符号链接与 ".." 无法逃逸
func DeleteCert(outputBase, folder string) error {
	if err := ValidLeafName(folder); err != nil {
		return err
	}
	root, err := os.OpenRoot(outputBase)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.RemoveAll(folder)
}
