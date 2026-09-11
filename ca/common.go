package ca

import (
	"os"
	"path/filepath"
	"strings"
)

// IssueRequest 是签发接口的请求参数。
type IssueRequest struct {
	Domain    string `json:"domain"`
	Name      string `json:"name"`
	SANs      string `json:"sans"`
	Duration  string `json:"duration"`
	KeyType   string `json:"key_type"`
	AutoRenew bool   `json:"auto_renew"`
}

// IssueResult 是签发成功后的返回。
type IssueResult struct {
	Domain  string `json:"domain"`
	Path    string `json:"path"`
	CRTFile string `json:"crt_file"`
	KeyFile string `json:"key_file"`
}

// SanitizeFolder 清洗文件夹名：只放行英文字母、数字、连字符、下划线。
//
// 与前端输入校验保持同一套字符集，并在服务端强制执行。白名单写法顺带
// 把 "." / ".." / "/" / "\" 这些能改变路径语义的输入直接抹掉，
// 而不是像旧实现那样只做两次 ReplaceAll 后就把结果当可信名称使用。
func SanitizeFolder(folder string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(folder) {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// findCertKey 在目录中寻找 .crt 与 .key 文件。
func findCertKey(dir string) (crt, key string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch {
		case strings.HasSuffix(e.Name(), ".crt"):
			crt = filepath.Join(dir, e.Name())
		case strings.HasSuffix(e.Name(), ".key"):
			key = filepath.Join(dir, e.Name())
		}
	}
	return
}
