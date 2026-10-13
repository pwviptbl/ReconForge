#!/usr/bin/env bash
# ReconForge launcher for Linux/Mac
# Cria/ativa venv, instala dependências (sob demanda) e inicia o app.

set -e

# Verifica suporte a venv/ensurepip
if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
  echo "ensurepip não está disponível."
  if command -v apt-get >/dev/null 2>&1; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    VENV_PKG="python${PY_VER}-venv"
    echo "Instalando dependência venv: ${VENV_PKG} (ou python3-venv)..."
    if command -v sudo >/dev/null 2>&1; then
      sudo apt-get install -y "${VENV_PKG}" python3-venv || true
    else
      apt-get install -y "${VENV_PKG}" python3-venv || true
    fi
  else
    echo "Por favor, instale o pacote venv (ex: python3-venv) e tente novamente."
    exit 1
  fi
fi

# Cria venv se não existir
NEED_INSTALL=0
if [ ! -d ".venv" ]; then
  echo "Criando ambiente virtual (.venv)..."
  python3 -m venv .venv
  NEED_INSTALL=1
fi

# Ativa o ambiente virtual
# shellcheck disable=SC1091
source .venv/bin/activate

# Instala dependências se for a primeira vez ou se chamado com --update
if [ "$1" = "--update" ] || [ "$NEED_INSTALL" = "1" ]; then
  echo "Instalando/atualizando dependências no .venv..."
  python -m pip install --upgrade pip
  pip install -r requirements.txt

  echo "Garantindo browser do Playwright..."
  python -m playwright install chromium 2>/dev/null || true

  if [ "$1" = "--update" ]; then
    echo "Dependências atualizadas com sucesso."
    shift
    if [ $# -eq 0 ]; then
      exit 0
    fi
  fi
fi

# Inicia o ReconForge CLI
python scripts/main.py "$@"
