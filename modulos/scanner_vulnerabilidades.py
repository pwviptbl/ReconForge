#!/usr/bin/env python3
"""
Scanner de Vulnerabilidades Python
Substituto completo para OpenVAS - Detecção de vulnerabilidades em serviços
"""

import socket
import ssl
import subprocess
import requests
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
import paramiko
from ftplib import FTP
from utils.logger import obter_logger

# Conectores de banco opcionais
try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False

try:
    import psycopg2
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False

class ScannerVulnerabilidades:
    def __init__(self):
        self.logger = obter_logger("VulnScanner")
        self.vulnerabilidades = []
        self.servicos_detectados = {}
        
        # Base de dados de vulnerabilidades comuns
        self.cve_database = {
            'ssh': {
                'OpenSSH_7.4': ['CVE-2018-15473', 'CVE-2016-6210'],
                'OpenSSH_6.6': ['CVE-2016-0777', 'CVE-2016-0778'],
                'OpenSSH_5.3': ['CVE-2010-4478', 'CVE-2010-5107']
            },
            'apache': {
                '2.4.29': ['CVE-2019-0197', 'CVE-2018-17199'],
                '2.4.18': ['CVE-2017-15710', 'CVE-2017-15715'],
                '2.2.22': ['CVE-2017-9788', 'CVE-2017-7679']
            },
            'nginx': {
                '1.10.3': ['CVE-2017-7529'],
                '1.6.2': ['CVE-2014-3616']
            },
            'mysql': {
                '5.7.20': ['CVE-2018-2562', 'CVE-2018-2612'],
                '5.6.35': ['CVE-2017-3308', 'CVE-2017-3309']
            },
            'ftp': {
                'vsftpd_2.3.4': ['CVE-2011-2523'],
                'proftpd_1.3.0': ['CVE-2006-5815']
            }
        }
        
        # Portas e serviços comuns
        self.portas_servicos = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 135: 'rpc',
            139: 'netbios', 143: 'imap', 443: 'https', 445: 'smb',
            993: 'imaps', 995: 'pop3s', 1433: 'mssql', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis'
        }
    
    def scan_vulnerabilidades(self, alvo, portas_abertas=None):
        """Executa scan completo de vulnerabilidades"""
        self.logger.info(f"🔍 Iniciando scan de vulnerabilidades para {alvo}")
        
        inicio = time.time()
        
        try:
            # Se não temos portas, fazer scan básico
            if not portas_abertas:
                portas_abertas = self._scan_portas_basico(alvo)
            
            # Detectar serviços e versões
            self._detectar_servicos(alvo, portas_abertas)
            
            # Executar testes de vulnerabilidade
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                
                for porta in portas_abertas:
                    servico = self.portas_servicos.get(porta, 'unknown')
                    future = executor.submit(self._testar_vulnerabilidades_porta, alvo, porta, servico)
                    futures.append(future)
                
                # Aguardar conclusão
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.warning(f"⚠️ Erro em teste: {e}")
            
            # Análise final
            duracao = time.time() - inicio
            
            resultado = {
                'alvo': alvo,
                'timestamp': datetime.now().isoformat(),
                'duracao_segundos': round(duracao, 2),
                'servicos_detectados': self.servicos_detectados,
                'vulnerabilidades': self.vulnerabilidades,
                'total_vulnerabilidades': len(self.vulnerabilidades),
                'criticidade_alta': len([v for v in self.vulnerabilidades if v.get('criticidade') == 'ALTA']),
                'criticidade_media': len([v for v in self.vulnerabilidades if v.get('criticidade') == 'MÉDIA']),
                'criticidade_baixa': len([v for v in self.vulnerabilidades if v.get('criticidade') == 'BAIXA'])
            }
            
            self.logger.info(f"✅ Scan concluído: {len(self.vulnerabilidades)} vulnerabilidades encontradas")
            return resultado
            
        except Exception as e:
            self.logger.error(f"❌ Erro no scan: {e}")
            return {'erro': str(e), 'alvo': alvo}
    
    def _scan_portas_basico(self, alvo):
        """Scan básico de portas se não fornecidas"""
        portas_comuns = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 3306, 3389, 5432]
        portas_abertas = []
        
        for porta in portas_comuns:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((alvo, porta))
                if result == 0:
                    portas_abertas.append(porta)
                sock.close()
            except:
                pass
        
        return portas_abertas
    
    def _detectar_servicos(self, alvo, portas):
        """Detecta serviços e versões nas portas abertas"""
        for porta in portas:
            try:
                servico_info = self._banner_grab(alvo, porta)
                if servico_info:
                    self.servicos_detectados[porta] = servico_info
            except Exception as e:
                self.logger.debug(f"Erro ao detectar serviço na porta {porta}: {e}")
    
    def _banner_grab(self, alvo, porta):
        """Captura banner do serviço"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((alvo, porta))
            
            # Enviar dados específicos por serviço
            if porta == 80:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif porta == 443:
                # HTTPS - usar SSL
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=alvo)
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif porta == 21:
                pass  # FTP envia banner automaticamente
            elif porta == 22:
                pass  # SSH envia banner automaticamente
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return self._parse_banner(banner, porta)
            
        except Exception as e:
            return None
    
    def _parse_banner(self, banner, porta):
        """Extrai informações do banner"""
        info = {'porta': porta, 'banner': banner}
        
        # HTTP/HTTPS
        if porta in [80, 443]:
            if 'Server:' in banner:
                server_line = [line for line in banner.split('\n') if 'Server:' in line]
                if server_line:
                    server = server_line[0].split('Server:')[1].strip()
                    info['servico'] = 'apache' if 'Apache' in server else 'nginx' if 'nginx' in server else 'http'
                    info['versao'] = self._extrair_versao_http(server)
        
        # SSH
        elif porta == 22:
            if 'SSH' in banner:
                info['servico'] = 'ssh'
                info['versao'] = self._extrair_versao_ssh(banner)
        
        # FTP
        elif porta == 21:
            if 'FTP' in banner or '220' in banner:
                info['servico'] = 'ftp'
                info['versao'] = self._extrair_versao_ftp(banner)
        
        return info
    
    def _extrair_versao_http(self, server_header):
        """Extrai versão do servidor HTTP"""
        patterns = [
            r'Apache/([0-9]+\.[0-9]+\.[0-9]+)',
            r'nginx/([0-9]+\.[0-9]+\.[0-9]+)',
            r'Microsoft-IIS/([0-9]+\.[0-9]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, server_header)
            if match:
                return match.group(1)
        return 'unknown'
    
    def _extrair_versao_ssh(self, banner):
        """Extrai versão do SSH"""
        match = re.search(r'OpenSSH_([0-9]+\.[0-9]+)', banner)
        if match:
            return f"OpenSSH_{match.group(1)}"
        return 'unknown'
    
    def _extrair_versao_ftp(self, banner):
        """Extrai versão do FTP"""
        if 'vsftpd' in banner:
            match = re.search(r'vsftpd ([0-9]+\.[0-9]+\.[0-9]+)', banner)
            if match:
                return f"vsftpd_{match.group(1)}"
        elif 'ProFTPD' in banner:
            match = re.search(r'ProFTPD ([0-9]+\.[0-9]+\.[0-9]+)', banner)
            if match:
                return f"proftpd_{match.group(1)}"
        return 'unknown'
    
    def _testar_vulnerabilidades_porta(self, alvo, porta, servico):
        """Testa vulnerabilidades específicas da porta"""
        if porta == 21:
            self._testar_ftp(alvo, porta)
        elif porta == 22:
            self._testar_ssh(alvo, porta)
        elif porta in [80, 443]:
            self._testar_web(alvo, porta)
        elif porta == 445:
            self._testar_smb(alvo, porta)
        elif porta == 3306:
            self._testar_mysql(alvo, porta)
        elif porta == 5432:
            self._testar_postgresql(alvo, porta)
        
        # Verificar CVEs conhecidas
        self._verificar_cves(alvo, porta, servico)
    
    def _testar_ftp(self, alvo, porta):
        """Testa vulnerabilidades FTP"""
        try:
            # Teste anonymous login
            ftp = FTP()
            ftp.connect(alvo, porta, timeout=10)
            try:
                ftp.login('anonymous', 'anonymous@test.com')
                self._adicionar_vulnerabilidade(
                    alvo, porta, 'FTP Anonymous Login',
                    'FTP permite login anônimo', 'MÉDIA',
                    'Configurar FTP para desabilitar login anônimo'
                )
                ftp.quit()
            except:
                pass
        except Exception as e:
            self.logger.debug(f"Erro teste FTP: {e}")
    
    def _testar_ssh(self, alvo, porta):
        """Testa vulnerabilidades SSH"""
        try:
            # Teste configurações fracas
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Teste senhas comuns (apenas algumas tentativas)
            usuarios_comuns = ['admin', 'root', 'user']
            senhas_comuns = ['admin', 'password', '123456']
            
            for usuario in usuarios_comuns[:2]:  # Limitar tentativas
                for senha in senhas_comuns[:2]:
                    try:
                        ssh.connect(alvo, port=porta, username=usuario, password=senha, timeout=5)
                        self._adicionar_vulnerabilidade(
                            alvo, porta, 'SSH Credenciais Fracas',
                            f'Login SSH com credenciais fracas: {usuario}:{senha}', 'ALTA',
                            'Configurar senhas fortes e chaves SSH'
                        )
                        ssh.close()
                        return
                    except:
                        pass
            
        except Exception as e:
            self.logger.debug(f"Erro teste SSH: {e}")
    
    def _testar_web(self, alvo, porta):
        """Testa vulnerabilidades Web"""
        try:
            protocolo = 'https' if porta == 443 else 'http'
            base_url = f"{protocolo}://{alvo}:{porta}"
            
            # Teste diretórios sensíveis
            diretorios_sensiveis = [
                '/admin', '/phpmyadmin', '/wp-admin', '/.git',
                '/backup', '/config', '/.env', '/test'
            ]
            
            for diretorio in diretorios_sensiveis:
                try:
                    resp = requests.get(f"{base_url}{diretorio}", timeout=5, verify=False)
                    if resp.status_code in [200, 403]:
                        self._adicionar_vulnerabilidade(
                            alvo, porta, 'Diretório Sensível Exposto',
                            f'Diretório sensível acessível: {diretorio}', 'MÉDIA',
                            'Restringir acesso a diretórios administrativos'
                        )
                except:
                    pass
            
            # Teste headers de segurança
            try:
                resp = requests.get(base_url, timeout=5, verify=False)
                headers_seguranca = [
                    'X-Frame-Options', 'X-XSS-Protection', 
                    'X-Content-Type-Options', 'Strict-Transport-Security'
                ]
                
                headers_faltando = [h for h in headers_seguranca if h not in resp.headers]
                if headers_faltando:
                    self._adicionar_vulnerabilidade(
                        alvo, porta, 'Headers de Segurança Ausentes',
                        f'Headers faltando: {", ".join(headers_faltando)}', 'BAIXA',
                        'Configurar headers de segurança no servidor web'
                    )
            except:
                pass
                
        except Exception as e:
            self.logger.debug(f"Erro teste Web: {e}")
    
    def _testar_smb(self, alvo, porta):
        """Testa vulnerabilidades SMB"""
        try:
            # Verificar SMB v1 (vulnerável)
            proc = subprocess.run([
                'smbclient', '-L', f'//{alvo}', '-N'
            ], capture_output=True, text=True, timeout=10)
            
            if 'NT_STATUS_OK' in proc.stdout or 'Sharename' in proc.stdout:
                self._adicionar_vulnerabilidade(
                    alvo, porta, 'SMB Compartilhamentos Expostos',
                    'SMB permite listagem de compartilhamentos', 'MÉDIA',
                    'Configurar autenticação adequada para SMB'
                )
        except:
            pass
    
    def _testar_mysql(self, alvo, porta):
        """Testa vulnerabilidades MySQL"""
        if not MYSQL_AVAILABLE:
            self.logger.debug("MySQL connector não disponível - pulando teste")
            return
            
        try:
            # Teste login sem senha
            conn = mysql.connector.connect(
                host=alvo, port=porta, user='root', password='',
                connect_timeout=5
            )
            conn.close()
            
            self._adicionar_vulnerabilidade(
                alvo, porta, 'MySQL Root sem Senha',
                'MySQL permite login root sem senha', 'ALTA',
                'Configurar senha para usuário root do MySQL'
            )
        except:
            pass
    
    def _testar_postgresql(self, alvo, porta):
        """Testa vulnerabilidades PostgreSQL"""
        if not POSTGRES_AVAILABLE:
            self.logger.debug("PostgreSQL connector não disponível - pulando teste")
            return
            
        try:
            # Teste configurações fracas
            conn = psycopg2.connect(
                host=alvo, port=porta, user='postgres', password='',
                connect_timeout=5
            )
            conn.close()
            
            self._adicionar_vulnerabilidade(
                alvo, porta, 'PostgreSQL sem Senha',
                'PostgreSQL permite login sem senha', 'ALTA',
                'Configurar autenticação adequada para PostgreSQL'
            )
        except:
            pass
    
    def _verificar_cves(self, alvo, porta, servico):
        """Verifica CVEs conhecidas baseadas no serviço detectado"""
        if porta not in self.servicos_detectados:
            return
        
        info_servico = self.servicos_detectados[porta]
        servico_nome = info_servico.get('servico', '')
        versao = info_servico.get('versao', '')
        
        # Buscar CVEs no nosso banco
        if servico_nome in self.cve_database:
            cves_servico = self.cve_database[servico_nome]
            if versao in cves_servico:
                for cve in cves_servico[versao]:
                    self._adicionar_vulnerabilidade(
                        alvo, porta, f'CVE Conhecido: {cve}',
                        f'Versão {versao} do {servico_nome} possui vulnerabilidade conhecida',
                        'ALTA', f'Atualizar {servico_nome} para versão mais recente'
                    )
    
    def _adicionar_vulnerabilidade(self, alvo, porta, titulo, descricao, criticidade, solucao):
        """Adiciona vulnerabilidade à lista"""
        vuln = {
            'alvo': alvo,
            'porta': porta,
            'titulo': titulo,
            'descricao': descricao,
            'criticidade': criticidade,
            'solucao': solucao,
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilidades.append(vuln)
        
        emoji = "🚨" if criticidade == 'ALTA' else "⚠️" if criticidade == 'MÉDIA' else "ℹ️"
        self.logger.info(f"{emoji} {titulo} (Porta {porta})")

def main():
    """Teste do scanner"""
    scanner = ScannerVulnerabilidades()
    resultado = scanner.scan_vulnerabilidades('127.0.0.1')
    print(json.dumps(resultado, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
