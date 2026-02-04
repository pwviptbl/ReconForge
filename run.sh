#!/usr/bin/env bash
# ReconForge launcher for Linux/Mac
# Creates/activates venv, installs deps, and starts the app.

set -e

echo "Starting ReconForge..."

# Check venv/ensurepip support
if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
  echo "ensurepip is not available."
  if command -v apt-get >/dev/null 2>&1; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    VENV_PKG="python${PY_VER}-venv"
    echo "Installing venv dependency: ${VENV_PKG} (or python3-venv)..."
    if command -v sudo >/dev/null 2>&1; then
      sudo apt-get install -y "${VENV_PKG}" python3-venv || true
    else
      apt-get install -y "${VENV_PKG}" python3-venv || true
    fi
  else
    echo "Please install the venv package (e.g., python3-venv) and try again."
    exit 1
  fi
fi

# Safe mode for rendering issues (optional)
if [ "${RECONFORGE_SAFE_MODE}" = "1" ]; then
  echo "Safe mode enabled: forcing software rendering..."
  export QT_OPENGL=software
  export LIBGL_ALWAYS_SOFTWARE=1
fi

# Create venv if missing
if [ ! -d ".venv" ]; then
  echo "Creating virtual environment (.venv)..."
  python3 -m venv .venv
fi

echo "Activating virtual environment..."
# shellcheck disable=SC1091
source .venv/bin/activate

echo "Upgrading pip..."
python -m pip install --upgrade pip

echo "Installing/updating dependencies..."
pip install -r requirements.txt

# Start application
echo "Launching ReconForge..."
python scripts/main.py "$@"
