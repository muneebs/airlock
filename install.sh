#!/bin/bash
set -euo pipefail

# Airlock Installer
# Usage: curl -fsSL <raw-url>/install.sh | bash

INSTALL_DIR="${HOME}/.local/bin"
REPO_URL="https://raw.githubusercontent.com/muneebsamuels/airlock/main/bin/airlock"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

# --- Preflight checks ---

[[ "$(uname)" == "Darwin" ]] || error "macOS required. Lima uses Apple Virtualization framework."

if ! command -v brew &>/dev/null; then
    error "Homebrew not found. Install from https://brew.sh first."
fi

# --- Install dependencies ---

install_if_missing() {
    local cmd="$1" pkg="${2:-$1}"
    if command -v "$cmd" &>/dev/null; then
        info "$cmd already installed"
    else
        info "Installing $pkg..."
        brew install "$pkg"
    fi
}

install_if_missing lima
install_if_missing jq
install_if_missing yq
if ! yq --version 2>&1 | grep -q 'version v4'; then
    warn "yq found but may not be v4. TOML support requires 'brew install yq' (mikefarah/yq)."
fi

# --- Install airlock binary ---

mkdir -p "$INSTALL_DIR"

if [[ -t 0 ]]; then
    # Interactive: try downloading from repo
    info "Downloading airlock..."
    if curl -fsSL "$REPO_URL" -o "${INSTALL_DIR}/airlock"; then
        info "Downloaded from repository"
    else
        warn "Download failed. Checking for local copy..."
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if [[ -f "${SCRIPT_DIR}/bin/airlock" ]]; then
            cp "${SCRIPT_DIR}/bin/airlock" "${INSTALL_DIR}/airlock"
            info "Copied from local repo"
        else
            error "No airlock binary found. Clone the repo and run install.sh locally."
        fi
    fi
else
    # Piped (curl | bash): download from repo
    info "Downloading airlock..."
    curl -fsSL "$REPO_URL" -o "${INSTALL_DIR}/airlock" \
        || error "Download failed. Check URL and network."
fi

chmod +x "${INSTALL_DIR}/airlock"
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
info "${BOLD}Installation complete!${NC}"
echo ""
echo -e "  Next steps:"
echo -e "    ${BOLD}airlock setup${NC}    Create the Lima VM (one-time)"
echo -e "    ${BOLD}airlock help${NC}     Show all commands"
echo ""
echo -e "  Quick start after setup:"
echo -e "    ${BOLD}airlock npm ./my-project${NC}        Audit packages"
echo -e "    ${BOLD}airlock pnpm ./my-app dev${NC}       Dev mode with mount"
echo -e "    ${BOLD}airlock status${NC}                  Check VM state"
echo ""
