#!/bin/bash
# cert-web-ui 飞牛 fnOS .fpk 打包脚本
#
# 用法：fnpack 需可执行（PATH 中或 FNPACK 指定路径）；PKG_VERSION 缺省取 config.go 的 var Version。
#   FNPACK=/path/to/fnpack bash build-fpk.sh
# 产物：fnos/cert-web-ui.fpk
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$SCRIPT_DIR/cert-web-ui"

# 版本单一权威 = config.go 的 var Version（形如 v1.0.6 → 1.0.6）
if [ -z "${PKG_VERSION:-}" ]; then
  PKG_VERSION=$(grep -oP 'var Version = "\K[^"]+' "$SCRIPT_DIR/../config/config.go")
fi
PKG_VERSION="${PKG_VERSION#v}"
echo "=== Building cert-web-ui fpk (pkg ${PKG_VERSION}) ==="

# 同步版本号到 manifest（与 config.go 保持一致）
sed -i "s/^version=.*/version=${PKG_VERSION}/" "$APP_DIR/manifest"

FNPACK_BIN="${FNPACK:-fnpack}"
command -v "$FNPACK_BIN" >/dev/null 2>&1 || { echo "ERROR: fnpack not found (set FNPACK=/path/to/fnpack)" >&2; exit 1; }

cd "$APP_DIR"
"$FNPACK_BIN" build

FPK="$APP_DIR/cert-web-ui.fpk"
[ -f "$FPK" ] || FPK="cert-web-ui.fpk"
[ -f "$FPK" ] || { echo "ERROR: fpk not produced" >&2; exit 1; }

# fnpack 在 Windows 上打包会丢失可执行位（全 666），重打一层 tar 把 cmd/* 修成 755
TMP=$(mktemp -d)
tar xzf "$FPK" -C "$TMP"
chmod 755 "$TMP"/cmd/* 2>/dev/null || true
tar czf "$FPK" -C "$TMP" app.tgz cmd config wizard manifest ICON.PNG ICON_256.PNG
rm -rf "$TMP"

mv "$FPK" "$SCRIPT_DIR/cert-web-ui.fpk"
echo "=== Done: $SCRIPT_DIR/cert-web-ui.fpk ==="
