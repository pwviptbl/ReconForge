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
