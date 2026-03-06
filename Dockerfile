FROM kalilinux/kali-rolling

LABEL maintainer="ReconForge" \
      description="ReconForge — Automated Security Reconnaissance Pipeline" \
      version="3.0"

# ---- Variáveis de ambiente ----
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GOPATH=/root/go \
    PATH="/root/go/bin:/usr/local/go/bin:$PATH" \
    DEBIAN_FRONTEND=noninteractive

# ---- Dependências do sistema ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Ferramentas de rede / pentest nativas Kali
    nmap \
    whatweb \
    exploitdb \
    traceroute \
    dnsutils \
    curl \
    wget \
    git \
    # Go toolchain (para compilar projectdiscovery tools)
    golang \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    # Chromium + driver (para playwright / browser engine)
    chromium \
    chromium-driver \
    # Deps extras
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# ---- Ferramentas Go (projectdiscovery + gau) ----
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

# ---- Aplicação ----
WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Instalar playwright browsers (para fase 4 — browser engine)
RUN python3 -m playwright install chromium 2>/dev/null || true

COPY . .

# Criar diretórios de dados
RUN mkdir -p data/evidencias data/relatorios dados/relatorios logs

# ---- Ponto de entrada ----
# Exemplos de uso:
#   docker run -it --net=host --cap-add=NET_RAW reconforge https://alvo.com --pipeline
#   docker run -it --net=host --cap-add=NET_RAW reconforge --help
ENTRYPOINT ["python3", "scripts/main.py"]
CMD ["--help"]
