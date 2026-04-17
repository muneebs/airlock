#!/bin/bash
set -euo pipefail

# Airlock Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/muneebs/airlock/main/install.sh | bash

REPO="muneebs/airlock"
INSTALL_DIR="${HOME}/.local/bin"
BINARY="airlock"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

# --- Detect architecture ---

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64)  GOARCH="x86_64" ;;
    arm64)   GOARCH="arm64" ;;
    *)       error "Unsupported architecture: ${ARCH}" ;;
esac

[[ "$(uname)" == "Darwin" ]] || error "macOS required. airlock uses Apple Virtualization framework via Lima."

# --- Find latest release ---

get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name"' \
        | head -1 \
        | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

VERSION="${INSTALL_VERSION:-}"
if [[ -z "${VERSION}" ]]; then
    VERSION="$(get_latest_version)"
fi

if [[ -z "${VERSION}" ]]; then
    error "Could not determine latest version. Set INSTALL_VERSION or check https://github.com/${REPO}/releases"
fi

# Strip leading 'v' if present
VERSION="${VERSION#v}"

# --- Download ---

FILENAME="airlock_${VERSION}_darwin_${GOARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/${FILENAME}"

mkdir -p "${INSTALL_DIR}"

info "Downloading airlock v${VERSION} for macOS ${GOARCH}..."
if ! curl -fsSL "${DOWNLOAD_URL}" -o /tmp/airlock.tar.gz; then
    error "Download failed from ${DOWNLOAD_URL}. Check the version and try again."
fi

tar -xzf /tmp/airlock.tar.gz -C /tmp/ airlock
mv /tmp/airlock "${INSTALL_DIR}/airlock"
chmod +x "${INSTALL_DIR}/airlock"
rm -f /tmp/airlock.tar.gz

info "Installed to ${INSTALL_DIR}/airlock"

# --- Ensure PATH includes install dir ---

add_to_path() {
    local shell_rc="$1"
    if [[ -f "$shell_rc" ]] && grep -q '\.local/bin' "$shell_rc" 2>/dev/null; then
        return 0
    fi
    echo '' >> "$shell_rc"
    echo '# airlock CLI' >> "$shell_rc"
    echo 'export PATH="${HOME}/.local/bin:${PATH}"' >> "$shell_rc"
    warn "Added ~/.local/bin to PATH in $(basename "$shell_rc")"
}

if ! echo "$PATH" | grep -q "${HOME}/.local/bin"; then
    case "$(basename "$SHELL")" in
        zsh)  add_to_path "${HOME}/.zshrc" ;;
        bash) add_to_path "${HOME}/.bashrc" ;;
        *)    warn "Add ~/.local/bin to your PATH manually" ;;
    esac
    warn "Restart your shell or run: export PATH=\"\${HOME}/.local/bin:\${PATH}\""
fi

# --- Verify ---

echo ""
info "${BOLD}airlock v${VERSION} installed!${NC}"
echo ""
echo -e "  Next steps:"
echo -e "    ${BOLD}airlock setup${NC}       Create a Lima VM (one-time)"
echo -e "    ${BOLD}airlock sandbox ./dir${NC}  Create an isolated sandbox"
echo -e "    ${BOLD}airlock help${NC}         Show all commands"
echo ""