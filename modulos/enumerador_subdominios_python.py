#!/usr/bin/env python3
"""
Enumerador de Subdomínios em Python
Substituto para Subfinder/Sublist3r - Enumerador de subdomínios eficiente em Python puro
"""

import socket
import dns.resolver
import dns.exception
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional
from datetime import datetime
import requests
import json

from utils.logger import obter_logger


class EnumeradorSubdominiosPython:
    """Enumerador de subdomínios eficiente em Python puro"""

    def __init__(self):
        self.logger = obter_logger("SubdomainEnumerator")
        self.timeout = 2.0
        self.max_workers = 50

        # Wordlist padrão de subdomínios comuns
        self.wordlist_padrao = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'app', 'blog', 'shop', 'store', 'news', 'webmail', 'remote',
            'server', 'ns1', 'ns2', 'smtp', 'pop', 'imap', 'vpn', 'ssh',
            'git', 'svn', 'cloud', 'cdn', 'static', 'files', 'upload',
            'download', 'backup', 'old', 'new', 'temp', 'tmp', 'cache',
            'beta', 'alpha', 'demo', 'sandbox', 'portal', 'login', 'auth',
            'secure', 'ssl', 'm', 'mobile', 'wap', 'web', 'site', 'my',
            'your', 'our', 'client', 'customer', 'user', 'member', 'account',
            'profile', 'dashboard', 'panel', 'control', 'manage', 'admin',
            'administrator', 'root', 'sys', 'system', 'db', 'database',
            'sql', 'mysql', 'postgres', 'mongo', 'redis', 'elastic',
            'search', 'log', 'logs', 'monitor', 'monitoring', 'stats',
            'status', 'health', 'check', 'ping', 'api', 'rest', 'soap',
            'xml', 'json', 'rss', 'feed', 'atom', 'sitemap', 'robots'
        ]

        # Extensões numéricas comuns
        self.extensoes_numericas = [f"{i:02d}" for i in range(1, 21)] + \
                                  [f"{i:03d}" for i in range(1, 11)]

        # DNS servers para resolução
        self.dns_servers = [
            '8.8.8.8',      # Google
            '1.1.1.1',      # Cloudflare
            '208.67.222.222',  # OpenDNS
            '8.8.4.4',      # Google Secondary
            '1.0.0.1'       # Cloudflare Secondary
        ]

    def enumerar_completo(self, dominio: str, wordlist_customizada: Optional[List[str]] = None,
                         usar_dns_brute: bool = True, usar_certificado_ssl: bool = True,
                         usar_virustotal: bool = False) -> Dict:
        """
        Executa enumeração completa de subdomínios

        Args:
            dominio: Domínio alvo (ex: 'example.com')
            wordlist_customizada: Lista customizada de palavras
            usar_dns_brute: Usar brute force DNS
            usar_certificado_ssl: Verificar certificados SSL
            usar_virustotal: Usar API VirusTotal (requer chave)

        Returns:
            Dict com resultados da enumeração
        """
        self.logger.info(f"🔍 Iniciando enumeração de subdomínios: {dominio}")

        inicio = time.time()
        subdominios_encontrados = set()

        try:
            # 1. DNS Brute Force
            if usar_dns_brute:
                self.logger.info("🔨 Executando DNS brute force...")
                subdominios_dns = self._dns_brute_force(dominio, wordlist_customizada)
                subdominios_encontrados.update(subdominios_dns)

            # 2. Verificação de certificados SSL
            if usar_certificado_ssl:
                self.logger.info("🔒 Verificando certificados SSL...")
                subdominios_ssl = self._verificar_certificado_ssl(dominio)
                subdominios_encontrados.update(subdominios_ssl)

            # 3. Busca em VirusTotal (se habilitado)
            if usar_virustotal:
                self.logger.info("🦠 Consultando VirusTotal...")
                subdominios_vt = self._buscar_virustotal(dominio)
                subdominios_encontrados.update(subdominios_vt)

            # 4. Verificar registros CNAME
            self.logger.info("🔗 Verificando registros CNAME...")
            subdominios_cname = self._verificar_cname(dominio, list(subdominios_encontrados))
            subdominios_encontrados.update(subdominios_cname)

            # 5. Analisar subdomínios encontrados
            subdominios_analisados = self._analisar_subdominios(dominio, list(subdominios_encontrados))

            duracao = time.time() - inicio

            resultado = {
                'sucesso': True,
                'dominio_alvo': dominio,
                'total_subdominios': len(subdominios_encontrados),
                'subdominios_analisados': subdominios_analisados,
                'metodos_usados': {
                    'dns_brute_force': usar_dns_brute,
                    'ssl_certificate': usar_certificado_ssl,
                    'virustotal': usar_virustotal
                },
                'timestamp': datetime.now().isoformat(),
                'duracao_segundos': round(duracao, 2)
            }

            self.logger.info(f"✅ Enumeração concluída: {len(subdominios_encontrados)} subdomínios encontrados")
            return resultado

        except Exception as e:
            self.logger.error(f"❌ Erro na enumeração: {e}")
            return {
                'sucesso': False,
                'erro': str(e),
                'dominio': dominio,
                'timestamp': datetime.now().isoformat()
            }

    def _dns_brute_force(self, dominio: str, wordlist_customizada: Optional[List[str]]) -> Set[str]:
        """Executa brute force DNS para descobrir subdomínios"""
        subdominios = set()

        # Preparar wordlist
        if wordlist_customizada:
            palavras = wordlist_customizada
        else:
            palavras = self.wordlist_padrao + self.extensoes_numericas

        def testar_subdominio(palavra: str):
            subdominio = f"{palavra}.{dominio}"
            try:
                # Tentar resolver A record
                respostas = dns.resolver.resolve(subdominio, 'A')
                for resposta in respostas:
                    if resposta:
                        subdominios.add(subdominio)
                        self.logger.debug(f"✅ Subdomínio encontrado: {subdominio} -> {resposta}")
                        break

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                # Subdomínio não existe ou timeout
                pass
            except Exception as e:
                self.logger.debug(f"Erro ao testar {subdominio}: {e}")

        # Executar em paralelo
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(testar_subdominio, palavra) for palavra in palavras]

            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass

        return subdominios

    def _verificar_certificado_ssl(self, dominio: str) -> Set[str]:
        """Verifica certificados SSL para descobrir subdomínios"""
        subdominios = set()

        try:
            # Conectar ao domínio principal
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((dominio, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                    cert = ssock.getpeercert()

                    # Verificar Subject Alternative Names (SAN)
                    if 'subjectAltName' in cert:
                        for tipo, nome in cert['subjectAltName']:
                            if tipo == 'DNS' and nome.endswith(f".{dominio}"):
                                subdominios.add(nome)
                                self.logger.debug(f"🔒 Subdomínio SSL encontrado: {nome}")

        except Exception as e:
            self.logger.debug(f"Erro ao verificar certificado SSL: {e}")

        return subdominios

    def _buscar_virustotal(self, dominio: str) -> Set[str]:
        """Busca subdomínios no VirusTotal (requer API key)"""
        subdominios = set()

        # Nota: Implementação básica - em produção precisaria de API key
        try:
            # Simulação - em produção faria request real para VT API
            self.logger.debug("VirusTotal API não implementado (requer chave API)")

        except Exception as e:
            self.logger.debug(f"Erro ao consultar VirusTotal: {e}")

        return subdominios

    def _verificar_cname(self, dominio: str, subdominios: List[str]) -> Set[str]:
        """Verifica registros CNAME para descobrir mais subdomínios"""
        novos_subdominios = set()

        def verificar_cname(subdominio: str):
            try:
                respostas = dns.resolver.resolve(subdominio, 'CNAME')
                for resposta in respostas:
                    cname = str(resposta.target).rstrip('.')
                    if cname.endswith(f".{dominio}") and cname != subdominio:
                        novos_subdominios.add(cname)
                        self.logger.debug(f"🔗 CNAME encontrado: {subdominio} -> {cname}")

            except:
                pass

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(verificar_cname, sub) for sub in subdominios]

            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass

        return novos_subdominios

    def _analisar_subdominios(self, dominio: str, subdominios: List[str]) -> List[Dict]:
        """Analisa subdomínios encontrados para obter mais informações"""
        subdominios_analisados = []

        def analisar_subdominio(subdominio: str):
            info = {
                'subdominio': subdominio,
                'ip': None,
                'resolvivel': False,
                'servidor_web': False,
                'porta_80_aberta': False,
                'porta_443_aberta': False,
                'titulo_pagina': None
            }

            try:
                # Resolver IP
                try:
                    ip = socket.gethostbyname(subdominio)
                    info['ip'] = ip
                    info['resolvivel'] = True
                except:
                    return info

                # Verificar porta 80 (HTTP)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0)
                    if sock.connect_ex((subdominio, 80)) == 0:
                        info['porta_80_aberta'] = True
                        info['servidor_web'] = True
                    sock.close()
                except:
                    pass

                # Verificar porta 443 (HTTPS)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0)
                    if sock.connect_ex((subdominio, 443)) == 0:
                        info['porta_443_aberta'] = True
                        info['servidor_web'] = True
                    sock.close()
                except:
                    pass

                # Tentar obter título da página
                if info['servidor_web']:
                    try:
                        response = requests.get(f"http://{subdominio}", timeout=3, verify=False)
                        if response.status_code == 200:
                            # Extrair título da página
                            import re
                            title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
                            if title_match:
                                info['titulo_pagina'] = title_match.group(1).strip()
                    except:
                        pass

            except Exception as e:
                self.logger.debug(f"Erro ao analisar {subdominio}: {e}")

            return info

        # Analisar em paralelo
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(analisar_subdominio, sub) for sub in subdominios]

            for future in as_completed(futures):
                try:
                    resultado = future.result()
                    if resultado['resolvivel']:
                        subdominios_analisados.append(resultado)
                except:
                    pass

        # Ordenar por subdomínio
        subdominios_analisados.sort(key=lambda x: x['subdominio'])

        return subdominios_analisados

    def salvar_resultados(self, resultado: Dict, formato: str = 'json', arquivo: str = None):
        """Salva resultados da enumeração em arquivo"""
        if not arquivo:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            arquivo = f"subdominios_{resultado['dominio_alvo']}_{timestamp}.{formato}"

        if formato == 'json':
            with open(arquivo, 'w', encoding='utf-8') as f:
                json.dump(resultado, f, indent=2, ensure_ascii=False)

        elif formato == 'txt':
            with open(arquivo, 'w', encoding='utf-8') as f:
                f.write(f"Enumeração de Subdomínios - {resultado['dominio_alvo']}\\n")
                f.write(f"Total encontrado: {resultado['total_subdominios']}\\n")
                f.write(f"Data: {resultado['timestamp']}\\n\\n")

                for sub in resultado['subdominios_analisados']:
                    f.write(f"{sub['subdominio']}\\n")
                    if sub['ip']:
                        f.write(f"  IP: {sub['ip']}\\n")
                    if sub['titulo_pagina']:
                        f.write(f"  Título: {sub['titulo_pagina']}\\n")
                    f.write("\\n")

        self.logger.info(f"💾 Resultados salvos em: {arquivo}")


# Funções de compatibilidade
def enumerar_subdominios(dominio: str) -> Dict:
    """Função de compatibilidade para enumeração básica"""
    enumerador = EnumeradorSubdominiosPython()
    return enumerador.enumerar_completo(dominio)

def enumerar_subdominios_com_wordlist(dominio: str, wordlist: List[str]) -> Dict:
    """Função de compatibilidade com wordlist customizada"""
    enumerador = EnumeradorSubdominiosPython()
    return enumerador.enumerar_completo(dominio, wordlist_customizada=wordlist)


if __name__ == "__main__":
    # Teste do enumerador
    enumerador = EnumeradorSubdominiosPython()

    # Teste com domínio de exemplo
    dominio_teste = "google.com"

    print(f"🔍 Testando enumeração de subdomínios para: {dominio_teste}")
    resultado = enumerador.enumerar_completo(dominio_teste, usar_dns_brute=True, usar_certificado_ssl=False)

    if resultado['sucesso']:
        print(f"✅ Encontrados {resultado['total_subdominios']} subdomínios")
        print("\\n📋 Alguns subdomínios encontrados:")
        for sub in resultado['subdominios_analisados'][:10]:
            status = "🌐" if sub['servidor_web'] else "🔌"
            print(f"  {status} {sub['subdominio']} ({sub['ip'] or 'N/A'})")
    else:
        print(f"❌ Erro: {resultado.get('erro', 'Erro desconhecido')}")
