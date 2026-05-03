#!/usr/bin/env bash
# Overtrust Linux Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/cheese-cakee/overtrust/master/install.sh | bash

set -euo pipefail

REPO="cheese-cakee/overtrust"
VERSION="${1:-latest}"
INSTALL_DIR="${HOME}/.local/bin"
BINARY="overtrust"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}:: Installing overtrust...${NC}"

mkdir -p "$INSTALL_DIR"

if command -v curl &>/dev/null; then
    DL="curl -fsSL"
elif command -v wget &>/dev/null; then
    DL="wget -qO-"
else
    echo -e "${RED}Error: curl or wget required${NC}"
    exit 1
fi

if [ "$VERSION" = "latest" ]; then
    URL="https://github.com/${REPO}/releases/latest/download/${BINARY}"
else
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}"
fi

echo -e "   Downloading ${URL}"
$DL "$URL" > "${INSTALL_DIR}/${BINARY}"
chmod +x "${INSTALL_DIR}/${BINARY}"

# Add to PATH if not already there
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "${HOME}/.bashrc"
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "${HOME}/.zshrc" 2>/dev/null || true
    echo -e "   Added ${INSTALL_DIR} to PATH"
fi

echo -e "${GREEN}:: Done! Run 'overtrust' from any terminal.${NC}"
echo -e "   (Restart your terminal or run: export PATH=\"\$HOME/.local/bin:\$PATH\")"
