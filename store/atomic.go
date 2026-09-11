package store

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic 以「同目录临时文件 → fsync → rename」的方式原子落盘。
//
// 不能直接用 os.WriteFile：进程被 kill 或宿主机断电时，写了一半的文件会留在磁盘上。
// 对根私钥、根证书、revoked.json 这类文件来说，半截内容意味着信任锚或吊销列表
// 在没有任何报错的情况下静默损坏。rename 在同一文件系统内是原子的，
// 因此读方要么看到完整的旧文件，要么看到完整的新文件。
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// 任何提前返回的路径都要清掉临时文件；rename 成功后置空以避免误删目标。
	defer func() {
		if tmp != "" {
			_ = os.Remove(tmp)
		}
	}()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	// 先落盘再 rename，否则崩溃可能 rename 一个内容还在页缓存里的空壳。
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// CreateTemp 固定建 0600，这里改回调用方要求的权限。
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	tmp = ""
	return nil
}
