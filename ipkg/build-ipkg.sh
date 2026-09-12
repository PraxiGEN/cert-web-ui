#!/bin/bash
# cert-web-ui iKuai v4 .ipkg builder（改自技能 ikuai-ipkg-packager 的通用脚本）
#
# 布局：ipkg/build-ipkg.sh + ipkg/cert-web-ui/（含 manifest.json）
# 用法：cd ipkg && bash build-ipkg.sh
# 环境变量：
#   PKG_VERSION   包版本（默认取 manifest.json 里的 version）
#   IMAGE         覆盖要内嵌的镜像（默认读 manifest.json 的 image 字段）
#   SKIP_IMAGE=1  只出结构骨架（不可安装，用于校验目录）
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$(find "$SCRIPT_DIR" -maxdepth 2 -name manifest.json | head -1 | xargs -r dirname)"
if [ -z "$APP_DIR" ]; then
  echo "ERROR: no manifest.json found under $SCRIPT_DIR" >&2
  exit 1
fi
APP_NAME="$(basename "$APP_DIR")"
PKG_VERSION="${PKG_VERSION:-$(grep -oP '"version"\s*:\s*"\K[^"]+' "$APP_DIR/manifest.json" | head -1)}"

if [ -n "${IMAGE:-}" ]; then
  IMG="$IMAGE"
else
  IMG="$(grep -oP '"image"\s*:\s*"\K[^"]+' "$APP_DIR/manifest.json" | head -1)"
fi
[ -z "$IMG" ] && { echo "ERROR: image not set." >&2; exit 1; }

echo "=== Building ${APP_NAME} ipkg (pkg ${PKG_VERSION}, image ${IMG}) ==="

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker CLI not found." >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "ERROR: docker daemon unreachable." >&2; exit 1; }

# 1. 同步版本与镜像名到 manifest.json
echo "[1/3] Syncing manifest.json ..."
sed -i "s/\"version\": *\"[^\"]*\"/\"version\": \"${PKG_VERSION}\"/" "$APP_DIR/manifest.json"
sed -i "s|\"image\": *\"[^\"]*\"|\"image\": \"${IMG}\"|" "$APP_DIR/manifest.json"

# 2. 内嵌离线镜像（本地已有则跳过 pull，便于用本地构建测试）
if [ -n "${SKIP_IMAGE:-}" ]; then
  echo "[2/3] SKIP_IMAGE set — skeleton only (NOT installable on iKuai)."
else
  if docker image inspect "$IMG" >/dev/null 2>&1; then
    echo "[2/3] Image ${IMG} exists locally — skip pull."
  else
    echo "[2/3] Pulling ${IMG} ..."
    docker pull "$IMG"
  fi
  docker save "$IMG" | gzip > "$APP_DIR/docker_image.tar.gz"
  echo "    image bundle: $(du -h "$APP_DIR/docker_image.tar.gz" | cut -f1)"
fi

# 3. 打包（固定一层 <app>/ 目录）
echo "[3/3] Packaging ipkg ..."
cd "$SCRIPT_DIR"
[ -n "${SKIP_IMAGE:-}" ] && echo "WARN: skeleton package (no image) — NOT installable on iKuai."
tar -czf "${APP_NAME}-${PKG_VERSION}.ipkg" "$APP_NAME/"
IPKG_SIZE="$(du -h "${APP_NAME}-${PKG_VERSION}.ipkg" | cut -f1)"

[ -z "${SKIP_IMAGE:-}" ] && rm -f "$APP_DIR/docker_image.tar.gz"

echo ""
echo "=== Done ==="
echo "Output: ${SCRIPT_DIR}/${APP_NAME}-${PKG_VERSION}.ipkg (${IPKG_SIZE})"
echo "Install on iKuai: 高级应用 → 应用市场 → 本地安装"
