#!/bin/sh
set -e

REPO="Shasheen8/Broly"
BINARY="broly"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux|darwin) ;;
  *) echo "Unsupported OS: $OS" && exit 1 ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)         ARCH="amd64" ;;
  aarch64|arm64)  ARCH="arm64" ;;
  *)              echo "Unsupported architecture: $ARCH" && exit 1 ;;
esac

# Get latest release version
VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | cut -d'"' -f4)

if [ -z "$VERSION" ]; then
  echo "error: could not determine latest version" && exit 1
fi

ARCHIVE="broly_${VERSION#v}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

echo "Installing broly ${VERSION} (${OS}/${ARCH})..."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$URL" -o "${TMP}/${ARCHIVE}"
tar -xzf "${TMP}/${ARCHIVE}" -C "$TMP" "$BINARY"

if [ -w "$INSTALL_DIR" ]; then
  mv "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  sudo mv "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

echo "broly ${VERSION} installed to ${INSTALL_DIR}/${BINARY}"
echo ""
echo "Note: SAST and AI features require a Together AI API key:"
echo "  export TOGETHER_API_KEY=your_key_here"
