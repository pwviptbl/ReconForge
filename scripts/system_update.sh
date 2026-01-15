#!/bin/bash

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Verifica se é root
if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Este script requer permissões de root.${NC}"
        echo "Execute com: sudo bash scripts/system_update.sh"
        exit 1
fi

echo -e "${YELLOW}=== ReconForge Setup (Ubuntu/Mint) ===${NC}"
echo ""

# Atualizar e atualizar sistema
echo -e "${YELLOW}[1/7] Atualizando lista de pacotes...${NC}"
apt update

echo -e "${YELLOW}[2/7] Atualizando pacotes instalados...${NC}"
apt upgrade -y

# Função auxiliar para instalar pacotes via apt, ignorando erros se não existir
install_pkg() {
    local pkg="$1"
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ $pkg já instalado${NC}"
    else
        echo -e "${YELLOW}→ Instalando $pkg...${NC}"
        if apt install -y "$pkg" >/dev/null 2>&1; then
            echo -e "${GREEN}✓ $pkg instalado${NC}"
        else
            echo -e "${RED}✗ Pacote $pkg não encontrado nos repositórios padrão. Ignorando.${NC}"
        fi
    fi
}

# Instalar Python 3, pip e venv
echo -e "${YELLOW}[3/7] Verificando/instalando Python 3, pip e venv...${NC}"
install_pkg python3
install_pkg python3-pip
install_pkg python3-venv
install_pkg build-essential

# Instalar ferramentas externas
echo -e "${YELLOW}[4/7] Instalando ferramentas externas (apt padrão)...${NC}"
install_pkg nmap
install_pkg sqlmap
install_pkg nuclei      # pode não existir em todos os repositórios
install_pkg rustscan    # pode não existir em todos os repositórios
install_pkg sslscan
install_pkg dnsutils    # fornece "dig"
install_pkg whois
install_pkg curl
install_pkg wget
install_pkg git
install_pkg net-tools
install_pkg unzip
install_pkg tar
install_pkg jq
install_pkg openssl

# Criar ou atualizar venv (.venv preferencial)
echo -e "${YELLOW}[5/7] Criando/atualizando ambiente virtual...${NC}"
VENV_DIR=".venv"
if [ -d "venv" ] && [ ! -d ".venv" ]; then
    VENV_DIR="venv"
fi

if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}→ Criando ambiente virtual em $VENV_DIR...${NC}"
    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}✓ Ambiente virtual criado${NC}"
else
    echo -e "${GREEN}✓ Ambiente virtual já existe em $VENV_DIR${NC}"
fi

# Ativar venv
echo -e "${YELLOW}[6/7] Ativando ambiente virtual...${NC}"
source "$VENV_DIR/bin/activate"

# Atualizar pip e instalar dependências Python
echo -e "${YELLOW}→ Atualizando pip, setuptools, wheel...${NC}"
pip install --upgrade pip setuptools wheel

echo -e "${YELLOW}[7/7] Instalando dependências Python...${NC}"
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt && echo -e "${GREEN}✓ Dependências instaladas${NC}" || echo -e "${RED}✗ Falha ao instalar dependências${NC}"
else
    echo -e "${RED}✗ arquivo requirements.txt não encontrado${NC}"
fi

echo ""
echo -e "${GREEN}=== Setup Concluído ===${NC}"
echo ""
echo "Para ativar o ambiente virtual depois:"
echo "  source $VENV_DIR/bin/activate"
echo ""
echo "Para executar o programa:"
echo "  python main.py"
