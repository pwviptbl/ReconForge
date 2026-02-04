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

install_pkg() {
  local pkg="$1"
  if command -v dpkg >/dev/null 2>&1; then
    if dpkg -s "$pkg" 2>/dev/null | grep -q "Status: install ok installed"; then
      echo -e "  ${GREEN}✔${NC} $pkg already installed"
      return 0
    fi
  fi
  echo -e "  ${YELLOW}→${NC} Installing $pkg"
  if command -v sudo >/dev/null 2>&1; then
    sudo apt-get install -y "$pkg" >/dev/null 2>&1 || true
  else
    apt-get install -y "$pkg" >/dev/null 2>&1 || true
  fi

  if command -v dpkg >/dev/null 2>&1; then
    if dpkg -s "$pkg" 2>/dev/null | grep -q "Status: install ok installed"; then
      echo -e "  ${GREEN}✔${NC} $pkg installed"
    else
      echo -e "  ${YELLOW}!${NC} $pkg not installed (package may be missing in repo)"
    fi
  fi
}

echo -e "${YELLOW}[1/3] Updating apt lists...${NC}"
if command -v sudo >/dev/null 2>&1; then
  sudo apt-get update -y >/dev/null 2>&1 || true
else
  apt-get update -y >/dev/null 2>&1 || true
fi

echo -e "${YELLOW}[2/3] Verifying/installing Python 3, pip, and venv...${NC}"
install_pkg python3
install_pkg python3-pip
install_pkg python3-venv
install_pkg build-essential

echo -e "${YELLOW}[3/3] Installing external tools (apt default)...${NC}"
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
