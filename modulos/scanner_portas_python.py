#!/usr/bin/env python3
"""
Scanner de Portas em Python
Substituto completo para Nmap/RustScan - Scanner de portas eficiente em Python puro
"""

import socket
import threading
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Set
from datetime import datetime
import struct

from utils.logger import obter_logger


class ScannerPortasPython:
    """Scanner de portas eficiente em Python puro"""

    def __init__(self):
        self.logger = obter_logger("PortScanner")
        self.timeout_padrao = 1.0
        self.max_workers = 100
        self.chunk_size = 1000

        # Portas comuns para scan rápido
        self.portas_comuns = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
            993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443
        ]

        # Portas bem conhecidas (0-1023)
        self.portas_bem_conhecidas = list(range(1, 1024))

        # Portas registradas (1024-49151)
        self.portas_registradas = list(range(1024, 49152, 10))  # Amostragem

        # Serviços conhecidos
        self.servicos_conhecidos = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }

    def scan_completo(self, alvo: str, tipo_scan: str = "rapido",
                      portas_customizadas: Optional[List[int]] = None) -> Dict:
        """
        Executa scan completo de portas

        Args:
            alvo: IP ou hostname
            tipo_scan: 'rapido', 'completo', 'bem_conhecidas', 'customizado'
            portas_customizadas: Lista de portas específicas (para tipo 'customizado')

        Returns:
            Dict com resultados do scan
        """
        self.logger.info(f"🔍 Iniciando scan de portas: {alvo} (tipo: {tipo_scan})")

        inicio = time.time()

        try:
            # Resolver hostname para IP
            try:
                ip_alvo = socket.gethostbyname(alvo)
                hostname_resolvido = alvo if ip_alvo == alvo else socket.gethostbyaddr(ip_alvo)[0]
            except:
                ip_alvo = alvo
                hostname_resolvido = alvo

            # Determinar portas a escanear
            if tipo_scan == "customizado" and portas_customizadas:
                portas_para_scan = portas_customizadas
            elif tipo_scan == "completo":
                portas_para_scan = self.portas_bem_conhecidas + self.portas_registradas[:1000]
            elif tipo_scan == "bem_conhecidas":
                portas_para_scan = self.portas_bem_conhecidas
            else:  # rapido
                portas_para_scan = self.portas_comuns

            self.logger.info(f"📋 Escaneando {len(portas_para_scan)} portas...")

            # Executar scan
            portas_abertas = self._scan_portas(ip_alvo, portas_para_scan)

            # Analisar portas abertas
            portas_analisadas = self._analisar_portas_abertas(ip_alvo, portas_abertas)

            duracao = time.time() - inicio

            resultado = {
                'sucesso': True,
                'alvo_original': alvo,
                'ip_alvo': ip_alvo,
                'hostname_resolvido': hostname_resolvido,
                'tipo_scan': tipo_scan,
                'total_portas_scaneadas': len(portas_para_scan),
                'portas_abertas': len(portas_abertas),
                'portas_fechadas': len(portas_para_scan) - len(portas_abertas),
                'portas_analisadas': portas_analisadas,
                'timestamp': datetime.now().isoformat(),
                'duracao_segundos': round(duracao, 2),
                'taxa_sucesso': round(len(portas_abertas) / len(portas_para_scan) * 100, 2) if portas_para_scan else 0
            }

            self.logger.info(f"✅ Scan concluído: {len(portas_abertas)} portas abertas encontradas")
            return resultado

        except Exception as e:
            self.logger.error(f"❌ Erro no scan: {e}")
            return {
                'sucesso': False,
                'erro': str(e),
                'alvo': alvo,
                'tipo_scan': tipo_scan,
                'timestamp': datetime.now().isoformat()
            }

    def _scan_portas(self, ip: str, portas: List[int]) -> List[int]:
        """Escaneia portas usando múltiplas threads"""
        portas_abertas = []
        lock = threading.Lock()

        def scan_porta(porta: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout_padrao)
                resultado = sock.connect_ex((ip, porta))

                if resultado == 0:
                    with lock:
                        portas_abertas.append(porta)

                sock.close()
            except:
                pass

        # Dividir em chunks para melhor performance
        for i in range(0, len(portas), self.chunk_size):
            chunk = portas[i:i + self.chunk_size]

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(scan_porta, porta) for porta in chunk]

                # Aguardar conclusão do chunk
                for future in as_completed(futures):
                    try:
                        future.result()
                    except:
                        pass

        return sorted(portas_abertas)

    def _analisar_portas_abertas(self, ip: str, portas_abertas: List[int]) -> List[Dict]:
        """Analisa portas abertas para identificar serviços"""
        portas_analisadas = []

        for porta in portas_abertas:
            try:
                # Tentar banner grabbing
                banner = self._banner_grab(ip, porta)

                # Identificar serviço
                servico = self._identificar_servico(porta, banner)

                # Analisar versão se possível
                versao = self._extrair_versao(banner, servico)

                porta_info = {
                    'porta': porta,
                    'servico': servico,
                    'versao': versao,
                    'banner': banner,
                    'estado': 'aberta',
                    'protocolo': 'tcp'
                }

                portas_analisadas.append(porta_info)

            except Exception as e:
                self.logger.debug(f"Erro ao analisar porta {porta}: {e}")

                porta_info = {
                    'porta': porta,
                    'servico': 'desconhecido',
                    'versao': 'desconhecida',
                    'banner': '',
                    'estado': 'aberta',
                    'protocolo': 'tcp'
                }

                portas_analisadas.append(porta_info)

        return portas_analisadas

    def _banner_grab(self, ip: str, porta: int, timeout: float = 2.0) -> str:
        """Captura banner do serviço"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, porta))

            # Enviar dados específicos por serviço
            if porta == 80 or porta == 8080:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif porta == 443 or porta == 8443:
                # HTTPS - handshake SSL básico
                context = socket.ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = socket.ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=ip)
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif porta == 21:
                # FTP espera banner automaticamente
                pass
            elif porta == 22:
                # SSH envia banner automaticamente
                pass
            elif porta == 25:
                # SMTP
                sock.send(b"EHLO test\r\n")
            elif porta == 110:
                # POP3
                sock.send(b"USER test\r\n")
            elif porta == 143:
                # IMAP
                sock.send(b"a001 LOGIN test test\r\n")
            else:
                # Enviar quebra de linha genérica
                sock.send(b"\r\n")

            # Receber resposta
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            return banner

        except:
            return ""

    def _identificar_servico(self, porta: int, banner: str) -> str:
        """Identifica serviço baseado na porta e banner"""
        # Primeiro tentar por porta conhecida
        if porta in self.servicos_conhecidos:
            servico_base = self.servicos_conhecidos[porta]
        else:
            servico_base = 'desconhecido'

        # Refinar baseado no banner
        banner_lower = banner.lower()

        if 'ssh' in banner_lower:
            return 'SSH'
        elif 'ftp' in banner_lower or '220' in banner:
            return 'FTP'
        elif 'smtp' in banner_lower or '220' in banner:
            return 'SMTP'
        elif 'pop3' in banner_lower:
            return 'POP3'
        elif 'imap' in banner_lower:
            return 'IMAP'
        elif 'http' in banner_lower or 'server:' in banner_lower:
            return 'HTTP'
        elif 'mysql' in banner_lower:
            return 'MySQL'
        elif 'postgresql' in banner_lower:
            return 'PostgreSQL'
        elif 'microsoft' in banner_lower or 'windows' in banner_lower:
            return 'SMB/RPC'
        elif 'redis' in banner_lower:
            return 'Redis'

        return servico_base

    def _extrair_versao(self, banner: str, servico: str) -> str:
        """Extrai versão do serviço do banner"""
        import re

        if servico == 'SSH':
            match = re.search(r'OpenSSH_([0-9]+\.[0-9]+)', banner)
            if match:
                return f"OpenSSH {match.group(1)}"

        elif servico == 'FTP':
            if 'vsftpd' in banner:
                match = re.search(r'vsftpd ([0-9]+\.[0-9]+\.[0-9]+)', banner)
                if match:
                    return f"vsftpd {match.group(1)}"
            elif 'ProFTPD' in banner:
                match = re.search(r'ProFTPD ([0-9]+\.[0-9]+\.[0-9]+)', banner)
                if match:
                    return f"ProFTPD {match.group(1)}"

        elif servico == 'HTTP':
            match = re.search(r'Server:\s*([^\\r\\n]+)', banner, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        elif servico == 'MySQL':
            match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+)', banner)
            if match:
                return f"MySQL {match.group(1)}"

        return 'desconhecida'

    def scan_range_ip(self, rede: str, portas: List[int] = None) -> Dict:
        """
        Escaneia range de IPs em uma rede

        Args:
            rede: CIDR (ex: '192.168.1.0/24')
            portas: Lista de portas para escanear

        Returns:
            Dict com hosts ativos e portas abertas
        """
        if not portas:
            portas = self.portas_comuns

        self.logger.info(f"🔍 Escaneando rede: {rede}")

        try:
            network = ipaddress.ip_network(rede, strict=False)
            hosts_ativos = []

            for ip in network.hosts():
                ip_str = str(ip)

                # Ping básico (TCP SYN scan na porta 80)
                if self._host_ativo(ip_str):
                    portas_abertas = self._scan_portas(ip_str, portas)

                    if portas_abertas:
                        host_info = {
                            'ip': ip_str,
                            'portas_abertas': portas_abertas,
                            'hostname': self._resolver_hostname(ip_str)
                        }
                        hosts_ativos.append(host_info)

            return {
                'sucesso': True,
                'rede': rede,
                'hosts_ativos': hosts_ativos,
                'total_hosts': len(hosts_ativos),
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"❌ Erro no scan de rede: {e}")
            return {
                'sucesso': False,
                'erro': str(e),
                'rede': rede
            }

    def _host_ativo(self, ip: str) -> bool:
        """Verifica se host está ativo (ping TCP)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            resultado = sock.connect_ex((ip, 80))
            sock.close()
            return resultado == 0
        except:
            return False

    def _resolver_hostname(self, ip: str) -> str:
        """Resolve hostname do IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ip


# Funções de compatibilidade
def scan_portas_rapido(alvo: str) -> Dict:
    """Função de compatibilidade para scan rápido"""
    scanner = ScannerPortasPython()
    return scanner.scan_completo(alvo, "rapido")

def scan_portas_completo(alvo: str) -> Dict:
    """Função de compatibilidade para scan completo"""
    scanner = ScannerPortasPython()
    return scanner.scan_completo(alvo, "completo")

def scan_rede(rede: str) -> Dict:
    """Função de compatibilidade para scan de rede"""
    scanner = ScannerPortasPython()
    return scanner.scan_range_ip(rede)


if __name__ == "__main__":
    # Teste do scanner
    scanner = ScannerPortasPython()

    # Scan rápido
    print("🔍 Testando scan rápido...")
    resultado = scanner.scan_completo("127.0.0.1", "rapido")
    print(f"Portas abertas: {resultado['portas_abertas']}")

    # Scan completo
    print("\\n🔍 Testando scan completo...")
    resultado = scanner.scan_completo("127.0.0.1", "bem_conhecidas")
    print(f"Total portas scaneadas: {resultado['total_portas_scaneadas']}")
    print(f"Portas abertas: {resultado['portas_abertas']}")
