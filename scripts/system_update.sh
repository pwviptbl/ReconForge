#!/usr/bin/env bash
# ReconForge system dependencies installer (Debian/Ubuntu/Kali)
# Installs OS packages and external tools required/optional for ReconForge.

set -e

YELLOW="\033[1;33m"
GREEN="\033[1;32m"
RED="\033[1;31m"
NC="\033[0m"

if ! command -v apt-get >/dev/null 2>&1; then
  echo -e "${RED}apt-get not found. This script is for Debian/Ubuntu/Kali.${NC}"
  exit 1
fi

run_as_root() {
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    "$@"
  fi
}

install_pkg() {
  local pkg="$1"
  if command -v dpkg >/dev/null 2>&1; then
    if dpkg -s "$pkg" 2>/dev/null | grep -q "Status: install ok installed"; then
      echo -e "  ${GREEN}✔${NC} $pkg already installed"
      return 0
    fi
  fi
  echo -e "  ${YELLOW}→${NC} Installing $pkg"
  run_as_root apt-get install -y "$pkg" >/dev/null 2>&1 || true

  if command -v dpkg >/dev/null 2>&1; then
    if dpkg -s "$pkg" 2>/dev/null | grep -q "Status: install ok installed"; then
      echo -e "  ${GREEN}✔${NC} $pkg installed"
    else
      echo -e "  ${YELLOW}!${NC} $pkg not installed (package may be missing in repo)"
    fi
  fi
}

ensure_go_bin_on_path() {
  local shell_rc="$HOME/.bashrc"
  local path_line='export PATH="$HOME/go/bin:$PATH"'

  if [ -n "${ZSH_VERSION:-}" ] || [ "$(basename "${SHELL:-}")" = "zsh" ]; then
    shell_rc="$HOME/.zshrc"
  fi

  mkdir -p "$HOME/go/bin"

  # PATH for current shell execution
  export PATH="$HOME/go/bin:$PATH"

  # Persist for next shells
  if [ -f "$shell_rc" ]; then
    if ! grep -Fq "$path_line" "$shell_rc"; then
      echo "" >> "$shell_rc"
      echo "# ReconForge Go tools" >> "$shell_rc"
      echo "$path_line" >> "$shell_rc"
      echo -e "  ${GREEN}✔${NC} Added ~/go/bin to PATH in $shell_rc"
    fi
  else
    {
      echo "# ReconForge Go tools"
      echo "$path_line"
    } > "$shell_rc"
    echo -e "  ${GREEN}✔${NC} Created $shell_rc with ~/go/bin on PATH"
  fi
}

install_go_tool() {
  local tool_name="$1"
  local module_path="$2"

  if command -v "$tool_name" >/dev/null 2>&1; then
    echo -e "  ${GREEN}✔${NC} $tool_name already installed ($(command -v "$tool_name"))"
    return 0
  fi

  if ! command -v go >/dev/null 2>&1; then
    echo -e "  ${YELLOW}→${NC} Go not found, installing golang-go"
    install_pkg golang-go
  fi

  if ! command -v go >/dev/null 2>&1; then
    echo -e "  ${YELLOW}!${NC} Could not install Go. Skipping $tool_name."
    return 0
  fi

  ensure_go_bin_on_path

  echo -e "  ${YELLOW}→${NC} Installing $tool_name via go install"
  if GO111MODULE=on go install -v "${module_path}@latest" >/dev/null 2>&1; then
    hash -r || true
    if command -v "$tool_name" >/dev/null 2>&1; then
      echo -e "  ${GREEN}✔${NC} $tool_name installed ($(command -v "$tool_name"))"
    elif [ -x "$HOME/go/bin/$tool_name" ]; then
      echo -e "  ${GREEN}✔${NC} $tool_name installed at $HOME/go/bin/$tool_name"
      echo -e "  ${YELLOW}!${NC} Open a new shell or run: export PATH=\"\$HOME/go/bin:\$PATH\""
    else
      echo -e "  ${YELLOW}!${NC} $tool_name installation finished but binary was not found"
    fi
  else
    echo -e "  ${YELLOW}!${NC} Failed to install $tool_name via Go"
  fi
}

echo -e "${YELLOW}[1/4] Updating apt lists...${NC}"
run_as_root apt-get update -y >/dev/null 2>&1 || true

echo -e "${YELLOW}[2/4] Verifying/installing Python 3, pip, and venv...${NC}"
install_pkg python3
install_pkg python3-pip
install_pkg python3-venv
install_pkg build-essential

echo -e "${YELLOW}[3/4] Installing external tools (apt default)...${NC}"
install_pkg nmap
install_pkg sqlmap
install_pkg nuclei
install_pkg subfinder
install_pkg whatweb
install_pkg exploitdb
install_pkg sslscan
install_pkg dnsutils
install_pkg whois
install_pkg curl
install_pkg wget
install_pkg git
install_pkg net-tools
install_pkg unzip
install_pkg tar
install_pkg jq
install_pkg openssl

echo -e "${YELLOW}[4/4] Installing optional Go-based tools (katana/gau)...${NC}"
install_go_tool katana github.com/projectdiscovery/katana/cmd/katana
install_go_tool gau github.com/lc/gau/v2/cmd/gau

echo -e "${GREEN}Done.${NC}"
echo -e "Checks:"
echo -e "  nmap:      $(command -v nmap 2>/dev/null || echo 'not found')"
echo -e "  nuclei:    $(command -v nuclei 2>/dev/null || echo 'not found')"
echo -e "  subfinder: $(command -v subfinder 2>/dev/null || echo 'not found')"
echo -e "  whatweb:   $(command -v whatweb 2>/dev/null || echo 'not found')"
echo -e "  katana:    $(command -v katana 2>/dev/null || echo 'not found')"
echo -e "  gau:       $(command -v gau 2>/dev/null || echo 'not found')"

if ! command -v katana >/dev/null 2>&1 || ! command -v gau >/dev/null 2>&1; then
  echo -e "${YELLOW}Note:${NC} if katana/gau are in ~/go/bin, start a new shell or run:"
  echo -e "  export PATH=\"\$HOME/go/bin:\$PATH\""
fi
