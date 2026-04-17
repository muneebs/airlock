#!/bin/bash
set -euo pipefail

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

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64)  GOARCH="x86_64" ;;
    arm64)   GOARCH="arm64" ;;
    *)       error "Unsupported architecture: ${ARCH}" ;;
esac

[[ "$(uname)" == "Darwin" ]] || error "macOS required. airlock uses Apple Virtualization framework via Lima."

# --- sha256 tool discovery ---

if command -v shasum >/dev/null 2>&1; then
    SHA256="shasum -a 256"
elif command -v sha256sum >/dev/null 2>&1; then
    SHA256="sha256sum"
else
    error "Neither shasum nor sha256sum found. Cannot verify download integrity."
fi

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

VERSION="${VERSION#v}"

FILENAME="airlock_${VERSION}_darwin_${GOARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"
ARCHIVE_URL="${BASE_URL}/${FILENAME}"
CHECKSUMS_URL="${BASE_URL}/checksums.txt"

# --- Isolated scratch dir (avoid symlink/race in /tmp) ---

WORKDIR="$(mktemp -d -t airlock-install.XXXXXX)"
cleanup() { rm -rf "${WORKDIR}"; }
trap cleanup EXIT

mkdir -p "${INSTALL_DIR}"

info "Downloading airlock v${VERSION} for macOS ${GOARCH}..."
if ! curl -fsSL "${ARCHIVE_URL}" -o "${WORKDIR}/${FILENAME}"; then
    error "Download failed from ${ARCHIVE_URL}. Check the version and try again."
fi

info "Fetching checksums..."
if ! curl -fsSL "${CHECKSUMS_URL}" -o "${WORKDIR}/checksums.txt"; then
    error "Checksum download failed from ${CHECKSUMS_URL}."
fi

info "Verifying checksum..."
EXPECTED="$(grep " ${FILENAME}\$" "${WORKDIR}/checksums.txt" | awk '{print $1}')"
if [[ -z "${EXPECTED}" ]]; then
    error "No checksum entry for ${FILENAME} in checksums.txt."
fi
ACTUAL="$(${SHA256} "${WORKDIR}/${FILENAME}" | awk '{print $1}')"
if [[ "${EXPECTED}" != "${ACTUAL}" ]]; then
    error "Checksum mismatch for ${FILENAME}. Expected ${EXPECTED}, got ${ACTUAL}."
fi

tar -xzf "${WORKDIR}/${FILENAME}" -C "${WORKDIR}" "${BINARY}"
install -m 0755 "${WORKDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"

info "Installed to ${INSTALL_DIR}/${BINARY}"

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

echo ""
info "${BOLD}airlock v${VERSION} installed!${NC}"
echo ""
echo -e "  Next steps:"
echo -e "    ${BOLD}airlock setup${NC}       Create a Lima VM (one-time)"
echo -e "    ${BOLD}airlock sandbox ./dir${NC}  Create an isolated sandbox"
echo -e "    ${BOLD}airlock help${NC}         Show all commands"
echo ""
