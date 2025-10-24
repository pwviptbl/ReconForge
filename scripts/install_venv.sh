echo "Pronto. Para sair do venv: deactivate"
#!/usr/bin/env bash
set -euo pipefail

# Uso: ./create_venv.sh [--install] [--with-ai] [--name VENV_NAME]
# Cria um virtualenv (por padrão em .venv). Se --install for passado,
# instala dependências a partir de requirements.txt quando disponível,
# caso contrário instala um conjunto mínimo (requests, pyyaml). Use --with-ai
# para também instalar o pacote opcional google-generativeai.

VENV_DIR=".venv"
INSTALL=false
WITH_AI=false

print_usage() {
  cat <<EOF
Usage: $0 [--install] [--with-ai] [--name VENV_NAME]

Options:
  --install         Instala dependências (requer internet).
  --with-ai         Instala dependência opcional de IA (google-generativeai).
  --name VENV_NAME  Nome/pasta do virtualenv (default: .venv).
EOF
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install)
      INSTALL=true; shift ;;
    --with-ai)
      WITH_AI=true; shift ;;
    --name)
      VENV_DIR="$2"; shift 2 ;;
    -h|--help)
      print_usage; exit 0 ;;
    *)
      echo "Unknown option: $1"; print_usage; exit 1 ;;
  esac
done

# Detectar python
PYTHON=python3
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  PYTHON=python
fi

echo "Criando virtualenv em ${VENV_DIR} usando ${PYTHON}..."
"${PYTHON}" -m venv "${VENV_DIR}"

ACTIVATE_CMD="source ${VENV_DIR}/bin/activate"
echo "Ative com: ${ACTIVATE_CMD}"

# Copiar configuração de exemplo se necessário
EXAMPLE_CONFIG="config/default.exemple.yaml"
TARGET_CONFIG="config/default.yaml"
if [[ ! -f "${TARGET_CONFIG}" && -f "${EXAMPLE_CONFIG}" ]]; then
  mkdir -p "config"
  cp "${EXAMPLE_CONFIG}" "${TARGET_CONFIG}"
  echo "Arquivo de configuração padrão criado: ${TARGET_CONFIG} (copiado de ${EXAMPLE_CONFIG})"
fi

if $INSTALL; then
  PIP_EXEC="${VENV_DIR}/bin/pip"
  echo "Atualizando pip..."
  "${PIP_EXEC}" install --upgrade pip

  # Instalar ferramentas de sistema necessárias
  echo "Instalando ferramentas de segurança do sistema..."
  if command -v apt >/dev/null 2>&1; then
    echo "Sistema Debian/Ubuntu detectado. Instalando ferramentas com apt..."
    sudo apt update
    
    # Instalar ferramentas disponíveis via apt
    sudo apt install -y \
      sqlmap \
      nmap \
      dnsutils \
      curl \
      wget \
      git \
      build-essential
    
    # Instalar rustscan via snap (mais confiável que apt)
    if ! command -v rustscan >/dev/null 2>&1; then
      echo "Instalando rustscan via snap..."
      sudo snap install rustscan || {
        echo "Falhou instalação via snap. Tentando instalação manual..."
        # Fallback: tentar instalar via cargo/rust se disponível
        if command -v cargo >/dev/null 2>&1; then
          cargo install rustscan || echo "Aviso: rustscan não pôde ser instalado automaticamente"
        else
          echo "Aviso: rustscan não pôde ser instalado. Instale manualmente de https://github.com/RustScan/RustScan"
        fi
      }
    fi
    
    # Instalar nuclei manualmente (não disponível em repositórios padrão)
    if ! command -v nuclei >/dev/null 2>&1; then
      echo "Instalando nuclei..."
      # Baixar a versão mais recente do GitHub
      NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
      if [ -n "$NUCLEI_VERSION" ]; then
        wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" -O nuclei.zip
        unzip -q nuclei.zip
        sudo mv nuclei /usr/local/bin/ || mv nuclei ~/bin/
        rm nuclei.zip
      else
        echo "Aviso: Não foi possível determinar versão do nuclei. Instale manualmente de https://github.com/projectdiscovery/nuclei"
      fi
    fi
    
    # Instalar exploitdb (searchsploit)
    if ! command -v searchsploit >/dev/null 2>&1; then
      echo "Instalando exploitdb..."
      sudo apt install -y exploitdb || {
        echo "Tentando instalar via git..."
        git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
        sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
      }
    fi
    
  elif command -v yum >/dev/null 2>&1; then
    echo "Sistema RHEL/CentOS detectado. Instalando ferramentas com yum..."
    sudo yum update -y
    sudo yum install -y \
      sqlmap \
      nmap \
      bind-utils \
      curl \
      wget \
      git \
      gcc \
      make
    echo "Aviso: rustscan, nuclei e exploitdb podem precisar ser instalados manualmente neste sistema"
    
  elif command -v dnf >/dev/null 2>&1; then
    echo "Sistema Fedora detectado. Instalando ferramentas com dnf..."
    sudo dnf update -y
    sudo dnf install -y \
      sqlmap \
      nmap \
      bind-utils \
      curl \
      wget \
      git \
      gcc \
      make
    echo "Aviso: rustscan, nuclei e exploitdb podem precisar ser instalados manualmente neste sistema"
    
  elif command -v pacman >/dev/null 2>&1; then
    echo "Sistema Arch Linux detectado. Instalando ferramentas com pacman..."
    sudo pacman -Syu --noconfirm \
      sqlmap \
      nmap \
      bind \
      curl \
      wget \
      git \
      gcc \
      make \
      rustscan \
      nuclei \
      exploitdb
  else
    echo "Aviso: Gerenciador de pacotes não detectado. Instale manualmente:"
    echo "  - rustscan (https://github.com/RustScan/RustScan)"
    echo "  - nuclei (https://github.com/projectdiscovery/nuclei)"
    echo "  - sqlmap"
    echo "  - exploitdb/searchsploit"
    echo "  - nmap"
    echo "  - dnsutils/bind-utils"
  fi

  if [[ -f "requirements.txt" ]]; then
    echo "Instalando dependências de requirements.txt..."
    "${PIP_EXEC}" install -r requirements.txt
  else
    echo "requirements.txt não encontrado — instalando conjunto mínimo de dependências..."
    # Instalar conjunto mínimo + IA por padrão (a aplicação usa google-generativeai)
    PKGS=(requests pyyaml google-generativeai)
    echo "Instalando: ${PKGS[*]}"
    "${PIP_EXEC}" install "${PKGS[@]}"
  fi

  echo "Dependências instaladas. Ative o venv com: ${ACTIVATE_CMD}"
else
  if $WITH_AI; then
    echo "Aviso: --with-ai foi passado mas sem --install não haverá instalação. Use --install --with-ai para instalar google-generativeai."
  fi
fi

echo "Pronto. Para sair do venv: deactivate"
