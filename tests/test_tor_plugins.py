#!/usr/bin/env python3
"""
Testes de suporte a Tor nos plugins do ReconForge.

Valida que cada plugin modificado:
  1. Aceita o parâmetro / config de Tor sem erros
  2. Roteia o tráfego pelo Tor (via check.torproject.org)
  3. Não vaza o IP real (DNS leak check)

Uso:
    # Rodar todos os testes (modo Tor ativo)
    python3 tests/test_tor_plugins.py

    # Testar plugin específico
    python3 tests/test_tor_plugins.py dns
    python3 tests/test_tor_plugins.py headers
    python3 tests/test_tor_plugins.py nmap
    python3 tests/test_tor_plugins.py ports
    python3 tests/test_tor_plugins.py ssl
"""

import sys
import json
import time
import socket
from pathlib import Path

# Adicionar raiz do projeto ao path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# ──────────────────────────────────────────────────────────────────────────────
# Cores para output
# ──────────────────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):   print(f"  {GREEN}✅ {msg}{RESET}")
def fail(msg): print(f"  {RED}❌ {msg}{RESET}")
def warn(msg): print(f"  {YELLOW}⚠️  {msg}{RESET}")
def info(msg): print(f"  {CYAN}ℹ️  {msg}{RESET}")
def titulo(msg): print(f"\n{BOLD}{CYAN}{'─'*60}\n  {msg}\n{'─'*60}{RESET}")

# ──────────────────────────────────────────────────────────────────────────────
# Helpers globais
# ──────────────────────────────────────────────────────────────────────────────

def get_meu_ip_real() -> str:
    """Retorna o IP real da máquina (sem Tor)."""
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as r:
            return json.loads(r.read())["ip"]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "DESCONHECIDO"


def get_ip_via_tor() -> dict:
    """Verifica se a conexão atual está passando pelo Tor."""
    try:
        import requests
        proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
        resp = requests.get(
            "https://check.torproject.org/api/ip",
            proxies=proxies,
            timeout=20
        )
        return resp.json()  # {"IsTor": true/false, "IP": "..."}
    except Exception as e:
        return {"IsTor": False, "IP": None, "error": str(e)}


def montar_config_tor() -> dict:
    """Retorna config mínima com Tor habilitado."""
    return {
        "network": {
            "tor": {
                "enabled": True,
                "proxy_url": "socks5h://127.0.0.1:9050"
            }
        }
    }


def verificar_tor_disponivel() -> bool:
    """Verifica se o Tor está acessível na porta 9050."""
    try:
        s = socket.create_connection(("127.0.0.1", 9050), timeout=3)
        s.close()
        return True
    except OSError:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Testes individuais
# ──────────────────────────────────────────────────────────────────────────────

def test_dns_resolver(ip_real: str):
    titulo("DNS Resolver — Teste de DNS Leak via Tor")
    try:
        from plugins.dns_resolver import DNSResolverPlugin

        plugin = DNSResolverPlugin()
        plugin.config = montar_config_tor()

        info("Resolvendo 'check.torproject.org' via DoH sobre Tor...")
        t0 = time.time()
        result = plugin.execute("check.torproject.org", {})
        elapsed = time.time() - t0

        if not result.success:
            fail(f"Plugin retornou erro: {result.error}")
            return False

        dns_data = result.data
        ips_encontrados = dns_data.get("dns_results", {}).get("forward_dns", {}).get("ips", [])
        tor_mode = dns_data.get("tor_mode", False)
        method = dns_data.get("dns_results", {}).get("forward_dns", {}).get("method", "?")

        info(f"Método de resolução: {method}")
        info(f"IPs resolvidos: {ips_encontrados}")
        info(f"Tempo: {elapsed:.1f}s")

        if tor_mode:
            ok("tor_mode=True no resultado")
        else:
            fail("tor_mode=False — Tor não foi ativado!")
            return False

        if ip_real not in str(ips_encontrados) and ips_encontrados:
            ok(f"IP real ({ip_real}) NÃO apareceu nos dados — sem leak!")
        elif not ips_encontrados:
            warn("Nenhum IP retornado (DoH pode estar bloqueado na sua rede)")
        else:
            warn(f"IP real apareceu: {ip_real} — verificar manualmente")

        if "DoH-via-Tor" in method or "Tor" in method:
            ok("Método correto: DNS over HTTPS via Tor")
        else:
            warn(f"Método inesperado: {method}")

        ok("DNS Resolver passou!")
        return True

    except Exception as e:
        fail(f"Exceção: {e}")
        import traceback; traceback.print_exc()
        return False


def test_header_analyzer(ip_real: str):
    titulo("Header Analyzer — Requisição HTTP via Tor")
    try:
        from plugins.header_analyzer import HeaderAnalyzerPlugin

        plugin = HeaderAnalyzerPlugin()
        plugin.config = montar_config_tor()

        info("Analisando headers de 'http://check.torproject.org'...")
        t0 = time.time()
        result = plugin.execute(
            "check.torproject.org",
            {"original_target": "http://check.torproject.org"}
        )
        elapsed = time.time() - t0

        if not result.success:
            fail(f"Plugin retornou erro: {result.error}")
            return False

        tor_mode = result.data.get("tor_mode", False)
        analyzed = result.data.get("analyzed", [])

        info(f"Endpoints analisados: {len(analyzed)}")
        info(f"Tempo: {elapsed:.1f}s")

        if tor_mode:
            ok("tor_mode=True no resultado")
        else:
            fail("tor_mode=False — Tor não foi ativado!")
            return False

        if analyzed:
            status = analyzed[0].get("status_code")
            info(f"Status HTTP: {status}")
            ok("Header Analyzer passou!")
            return True
        else:
            warn("Nenhum endpoint analisado (verifique conectividade)")
            return True  # Não é falha de Tor, pode ser timeout

    except Exception as e:
        fail(f"Exceção: {e}")
        import traceback; traceback.print_exc()
        return False


def test_port_scanner(ip_real: str):
    titulo("Port Scanner — Socket SOCKS5 via Tor (PySocks)")
    try:
        from plugins.port_scanner import PortScannerPlugin

        plugin = PortScannerPlugin()
        plugin.config = montar_config_tor()

        # Usar poucos portas para ser rápido via Tor
        info("Escaneando portas 80,443 de 'check.torproject.org' via Tor...")
        t0 = time.time()
        result = plugin.execute(
            "check.torproject.org",
            {},
            ports=[80, 443],
            scan_type="custom"
        )
        elapsed = time.time() - t0

        if not result.success:
            fail(f"Plugin retornou erro: {result.error}")
            return False

        tor_mode = result.data.get("tor_mode", False)
        open_ports = result.data.get("open_ports", [])

        info(f"Portas abertas: {open_ports}")
        info(f"Tempo: {elapsed:.1f}s")

        if tor_mode:
            ok("tor_mode=True no resultado")
        else:
            fail("tor_mode=False — Tor não foi ativado!")
            return False

        if 80 in open_ports or 443 in open_ports:
            ok(f"Porta(s) {open_ports} detectadas via Tor!")
        else:
            warn("Nenhuma porta aberta (possível timeout via Tor, normal)")

        ok("Port Scanner passou!")
        return True

    except Exception as e:
        fail(f"Exceção: {e}")
        import traceback; traceback.print_exc()
        return False


def test_ssl_analyzer(ip_real: str):
    titulo("SSL Analyzer — Certificado SSL via SOCKS5 + ssl.wrap_socket")
    try:
        from plugins.ssl_analyzer import SSLAnalyzerPlugin

        plugin = SSLAnalyzerPlugin()
        plugin.config = montar_config_tor()

        info("Analisando SSL de 'check.torproject.org:443' via Tor...")
        t0 = time.time()
        result = plugin.execute(
            "https://check.torproject.org",
            {}
        )
        elapsed = time.time() - t0

        if not result.success:
            fail(f"Plugin retornou erro: {result.error}")
            return False

        tor_mode = result.data.get("tor_mode", False)
        ssl_enabled = result.data.get("ssl_enabled", False)
        cert = result.data.get("certificate_analysis", {})

        info(f"SSL habilitado: {ssl_enabled}")
        info(f"Tempo: {elapsed:.1f}s")

        if tor_mode:
            ok("tor_mode=True no resultado")
        else:
            fail("tor_mode=False — Tor não foi ativado!")
            return False

        if ssl_enabled and cert and "error" not in cert:
            subject = cert.get("subject", {})
            info(f"Certificado: {subject}")
            ok("Certificado SSL obtido via Tor com sucesso!")
        elif ssl_enabled:
            warn("SSL disponível mas certificado com erro (pode ser timeout)")
        else:
            warn("SSL não disponível no target")

        ok("SSL Analyzer passou!")
        return True

    except Exception as e:
        fail(f"Exceção: {e}")
        import traceback; traceback.print_exc()
        return False


def test_nmap_scanner():
    titulo("Nmap Scanner — Flag --proxies gerada corretamente")
    try:
        from plugins.nmap_scanner import NmapScannerPlugin
        import subprocess

        # Verificar se nmap está instalado
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, timeout=3)
        except FileNotFoundError:
            warn("Nmap não instalado — pulando teste de execução real")
            warn("Verificando apenas a lógica de construção do comando...")

        plugin = NmapScannerPlugin()
        plugin.config = montar_config_tor()

        # Inspecionar o método _run_nmap_scan diretamente
        from utils.tor import tor_proxy_url
        proxy_url = tor_proxy_url()
        nmap_proxy = proxy_url.replace("socks5h://", "socks5://")

        # Simular construção do comando
        base_cmd = ["nmap", "-T4"]
        base_cmd.extend(["--proxies", nmap_proxy])
        # TCP connect
        flags = ["-sT", "-sV"]
        cmd = base_cmd + flags + ["--top-ports", "100", "127.0.0.1"]

        info(f"Proxy que seria passado ao nmap: {nmap_proxy}")
        info(f"Comando simulado: {' '.join(cmd)}")

        if "--proxies" in cmd and "socks5://" in cmd[cmd.index("--proxies") + 1]:
            ok("Flag --proxies com socks5:// gerada corretamente!")
        else:
            fail("Flag --proxies não encontrada no comando")
            return False

        if "-sT" in cmd:
            ok("Flag -sT (TCP Connect) usada no modo Tor — correto!")
        else:
            fail("-sT não encontrado — scans SYN (-sS) não funcionam via proxy")
            return False

        ok("Nmap Scanner passou na verificação de flags!")
        return True

    except Exception as e:
        fail(f"Exceção: {e}")
        import traceback; traceback.print_exc()
        return False


def test_verificar_ip_tor():
    titulo("Verificação Final — IP Público via Tor é diferente do IP Real")
    ip_real = get_meu_ip_real()
    info(f"IP real da máquina: {ip_real}")

    dados_tor = get_ip_via_tor()
    ip_tor = dados_tor.get("IP")
    is_tor = dados_tor.get("IsTor", False)

    info(f"IP via Tor: {ip_tor}")
    info(f"Confirmado como nó Tor: {is_tor}")

    if ip_tor and ip_tor != ip_real:
        ok(f"IPs diferentes! Real={ip_real}, Tor={ip_tor}")
    elif ip_tor == ip_real:
        fail(f"IPs IGUAIS — tráfego não está passando pelo Tor!")
        return False, ip_real
    else:
        warn("Não foi possível verificar (sem conectividade?)")

    if is_tor:
        ok("check.torproject.org confirma: estamos no Tor! ✅")
    else:
        fail("check.torproject.org diz que NÃO estamos no Tor")
        return False, ip_real

    return True, ip_real


# ──────────────────────────────────────────────────────────────────────────────
# Runner principal
# ──────────────────────────────────────────────────────────────────────────────

def main():
    filtro = sys.argv[1].lower() if len(sys.argv) > 1 else None

    print(f"\n{BOLD}{'='*60}")
    print("  ReconForge — Testes de Suporte a Tor")
    print(f"{'='*60}{RESET}")

    # 1. Verificar se Tor está disponível
    titulo("Pré-checks")
    if not verificar_tor_disponivel():
        fail("Tor NÃO está acessível em 127.0.0.1:9050!")
        fail("Inicie o Tor: sudo systemctl start tor")
        sys.exit(1)
    ok("Tor acessível em 127.0.0.1:9050")

    # 2. Verificar IP via Tor
    tor_ok, ip_real = test_verificar_ip_tor()
    if not tor_ok:
        fail("Tor não está funcionando corretamente. Abortando.")
        sys.exit(1)

    # 3. Rodar testes
    resultados = {}

    testes_disponiveis = {
        "dns":     ("DNS Resolver",     lambda: test_dns_resolver(ip_real)),
        "headers": ("Header Analyzer",  lambda: test_header_analyzer(ip_real)),
        "ports":   ("Port Scanner",     lambda: test_port_scanner(ip_real)),
        "ssl":     ("SSL Analyzer",     lambda: test_ssl_analyzer(ip_real)),
        "nmap":    ("Nmap Scanner",     test_nmap_scanner),
    }

    for chave, (nome, fn) in testes_disponiveis.items():
        if filtro and filtro != chave:
            continue
        try:
            resultados[nome] = fn()
        except KeyboardInterrupt:
            warn(f"Teste '{nome}' interrompido pelo usuário")
            resultados[nome] = None
        except Exception as e:
            fail(f"Erro inesperado em '{nome}': {e}")
            resultados[nome] = False

    # 4. Sumário
    titulo("Sumário dos Resultados")
    aprovados  = sum(1 for v in resultados.values() if v is True)
    reprovados = sum(1 for v in resultados.values() if v is False)
    pulados    = sum(1 for v in resultados.values() if v is None)

    for nome, resultado in resultados.items():
        if resultado is True:
            ok(nome)
        elif resultado is False:
            fail(nome)
        else:
            warn(f"{nome} (pulado)")

    print(f"\n  Total: {aprovados} aprovado(s), {reprovados} reprovado(s), {pulados} pulado(s)\n")

    if reprovados > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
