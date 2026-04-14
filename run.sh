#!/usr/bin/env bash
# ReconForge launcher for Linux/Mac
# Cria/ativa venv, instala dependências e inicia o app.

set -e

echo "Iniciando ReconForge..."

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

# Modo seguro para problemas de renderização (opcional)
if [ "${RECONFORGE_SAFE_MODE}" = "1" ]; then
  echo "Modo seguro ativado: forçando renderização por software..."
  export QT_OPENGL=software
  export LIBGL_ALWAYS_SOFTWARE=1
fi

# Cria venv se não existir
if [ ! -d ".venv" ]; then
  echo "Criando ambiente virtual (.venv)..."
  python3 -m venv .venv
fi

echo "Ativando ambiente virtual..."
# shellcheck disable=SC1091
source .venv/bin/activate

echo "Atualizando pip..."
python -m pip install --upgrade pip

echo "Instalando/atualizando dependências..."
pip install -r requirements.txt

echo "Garantindo que o Chromium do Playwright esteja instalado..."
python -m playwright install chromium

# Inicia o aplicativo
echo "Iniciando ReconForge..."
python scripts/main.py "$@"
