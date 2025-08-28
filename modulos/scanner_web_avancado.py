#!/usr/bin/env python3
"""
Scanner Web Avançado
Substituto completo para ZAP - Scanner profissional de vulnerabilidades web
"""

import requests
import urllib.parse
import re
import time
import random
import ssl
import socket
import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from utils.logger import obter_logger
from urllib.robotparser import RobotFileParser
from typing import Dict, List, Set, Optional
import xml.etree.ElementTree as ET

class ScannerWebAvancado:
    def __init__(self):
        self.logger = obter_logger("WebScanner")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 WebScanner/1.0'
        })
        
        # Configurações
        self.timeout = 10
        self.max_pages = 100
        self.max_depth = 3
        
        # Resultados
        self.urls_encontradas = set()
        self.formularios = []
        self.vulnerabilidades = []
        self.tecnologias = {}
        
        # Payloads para testes
        self.sql_payloads = [
            "' OR '1'='1' --",
            "' UNION SELECT NULL,NULL,NULL --",
            "' AND 1=CONVERT(int,(SELECT @@version)) --",
            "\"; DROP TABLE users; --",
            "' OR 1=1 #",
            "1' ORDER BY 3--+",
            "1' GROUP BY 1,2,3,4,5--+",
            "1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--+",
            "'; WAITFOR DELAY '00:00:05'--",
            "1)) OR 1=1--+"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<details ontoggle=alert('XSS') open>"
        ]
        
        self.lfi_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/proc/self/environ",
            "/etc/shadow",
            "C:\\boot.ini",
            "/var/log/apache2/access.log"
        ]
        
        # Diretórios comuns para brute force
        self.diretorios_comuns = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
            'backup', 'backups', 'config', 'test', 'testing', 'dev',
            'development', 'staging', 'api', 'v1', 'v2', 'docs',
            'documentation', 'files', 'uploads', 'images', 'css',
            'js', 'javascript', 'assets', 'static', 'tmp', 'temp',
            'logs', 'log', 'old', 'new', 'www', 'web', 'site',
            'portal', 'dashboard', 'panel', 'control', 'manage',
            'management', 'private', 'secure', 'secret', 'hidden'
        ]
        
        # Arquivos sensíveis
        self.arquivos_sensiveis = [
            '.git/config', '.env', '.htaccess', 'web.config',
            'config.php', 'database.yml', 'wp-config.php',
            'settings.py', 'local_settings.py', 'config.json',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'phpinfo.php', 'info.php', 'test.php',
            'backup.sql', 'dump.sql', 'readme.txt'
        ]
    
    def scan_completo(self, url_base):
        """Executa scan completo de vulnerabilidades web"""
        self.logger.info(f"🕷️ Iniciando scan web completo para: {url_base}")
        
        inicio = time.time()
        
        try:
            # Normalizar URL
            if not url_base.startswith(('http://', 'https://')):
                url_base = f"http://{url_base}"
            
            # 1. Spider - Descobrir URLs
            self.logger.info("🔍 Fase 1: Spider - Descobrindo URLs...")
            self._spider_web(url_base)
            
            # 2. Análise de tecnologias
            self.logger.info("🔧 Fase 2: Detectando tecnologias...")
            self._detectar_tecnologias(url_base)
            
            # 3. Descoberta de diretórios
            self.logger.info("📂 Fase 3: Brute force de diretórios...")
            self._brute_force_diretorios(url_base)
            
            # 4. Busca por arquivos sensíveis
            self.logger.info("📄 Fase 4: Procurando arquivos sensíveis...")
            self._buscar_arquivos_sensiveis(url_base)
            
            # 5. Análise de formulários
            self.logger.info("📝 Fase 5: Analisando formulários...")
            self._analisar_formularios()
            
            # 6. Testes de segurança
            self.logger.info("🛡️ Fase 6: Testando vulnerabilidades...")
            self._testar_vulnerabilidades()
            
            # 7. Análise SSL/TLS
            self.logger.info("🔐 Fase 7: Analisando SSL/TLS...")
            self._analisar_ssl(url_base)
            
            # 8. Headers de segurança
            self.logger.info("📋 Fase 8: Verificando headers de segurança...")
            self._verificar_headers_seguranca(url_base)
            
            duracao = time.time() - inicio
            
            resultado = {
                'url_base': url_base,
                'timestamp': datetime.now().isoformat(),
                'duracao_segundos': round(duracao, 2),
                'urls_encontradas': list(self.urls_encontradas),
                'total_urls': len(self.urls_encontradas),
                'formularios': self.formularios,
                'total_formularios': len(self.formularios),
                'tecnologias': self.tecnologias,
                'vulnerabilidades': self.vulnerabilidades,
                'total_vulnerabilidades': len(self.vulnerabilidades),
                'criticidade_alta': len([v for v in self.vulnerabilidades if v.get('criticidade') == 'ALTA']),
                'criticidade_media': len([v for v in self.vulnerabilidades if v.get('criticidade') == 'MÉDIA']),
                'criticidade_baixa': len([v for v in self.vulnerabilidades if v.get('criticidade') == 'BAIXA'])
            }
            
            self.logger.info(f"✅ Scan web concluído: {len(self.vulnerabilidades)} vulnerabilidades encontradas")
            return resultado
            
        except Exception as e:
            self.logger.error(f"❌ Erro no scan web: {e}")
            return {'erro': str(e), 'url_base': url_base}
    
    def _spider_web(self, url_base):
        """Spider para descobrir URLs"""
        urls_para_visitar = {url_base}
        urls_visitadas = set()
        depth = 0
        
        while urls_para_visitar and depth < self.max_depth and len(self.urls_encontradas) < self.max_pages:
            proximas_urls = set()
            
            for url in list(urls_para_visitar):
                if url in urls_visitadas:
                    continue
                
                try:
                    resp = self.session.get(url, timeout=self.timeout, verify=False)
                    urls_visitadas.add(url)
                    self.urls_encontradas.add(url)
                    
                    # Extrair links da página
                    links = self._extrair_links(resp.text, url)
                    for link in links:
                        if self._is_same_domain(link, url_base):
                            proximas_urls.add(link)
                    
                    # Buscar formulários
                    formularios = self._extrair_formularios(resp.text, url)
                    self.formularios.extend(formularios)
                    
                except Exception as e:
                    self.logger.debug(f"Erro ao visitar {url}: {e}")
            
            urls_para_visitar = proximas_urls - urls_visitadas
            depth += 1
    
    def _extrair_links(self, html, base_url):
        """Extrai links da página HTML"""
        links = set()
        
        # Regex para encontrar links
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                link = match.group(1)
                if link.startswith(('http://', 'https://')):
                    links.add(link)
                elif link.startswith('/'):
                    parsed_base = urllib.parse.urlparse(base_url)
                    full_url = f"{parsed_base.scheme}://{parsed_base.netloc}{link}"
                    links.add(full_url)
                elif not link.startswith(('#', 'mailto:', 'javascript:', 'tel:')):
                    full_url = urllib.parse.urljoin(base_url, link)
                    links.add(full_url)
        
        return links
    
    def _extrair_formularios(self, html, url):
        """Extrai formulários da página"""
        formularios = []
        
        # Regex para encontrar formulários
        form_pattern = r'<form[^>]*>(.*?)</form>'
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            
            # Extrair atributos do form
            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            action_url = action.group(1) if action else url
            if not action_url.startswith(('http://', 'https://')):
                action_url = urllib.parse.urljoin(url, action_url)
            
            # Extrair inputs
            inputs = []
            input_pattern = r'<input[^>]*>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_html = input_match.group(0)
                
                name = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                type_attr = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                
                if name:
                    inputs.append({
                        'name': name.group(1),
                        'type': type_attr.group(1) if type_attr else 'text'
                    })
            
            if inputs:
                formularios.append({
                    'url': url,
                    'action': action_url,
                    'method': method.group(1) if method else 'GET',
                    'inputs': inputs
                })
        
        return formularios
    
    def _is_same_domain(self, url, base_url):
        """Verifica se URL está no mesmo domínio"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            parsed_base = urllib.parse.urlparse(base_url)
            return parsed_url.netloc == parsed_base.netloc
        except:
            return False
    
    def _detectar_tecnologias(self, url):
        """Detecta tecnologias usadas no site"""
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            
            # Headers reveladores
            tech_headers = {
                'Server': resp.headers.get('Server', ''),
                'X-Powered-By': resp.headers.get('X-Powered-By', ''),
                'X-Generator': resp.headers.get('X-Generator', ''),
                'X-Framework': resp.headers.get('X-Framework', '')
            }
            
            # Detectar por conteúdo
            content = resp.text.lower()
            
            # CMS Detection
            if 'wp-content' in content or 'wordpress' in content:
                self.tecnologias['CMS'] = 'WordPress'
            elif 'joomla' in content:
                self.tecnologias['CMS'] = 'Joomla'
            elif 'drupal' in content:
                self.tecnologias['CMS'] = 'Drupal'
            
            # Framework Detection
            if 'django' in content:
                self.tecnologias['Framework'] = 'Django'
            elif 'laravel' in content:
                self.tecnologias['Framework'] = 'Laravel'
            elif 'codeigniter' in content:
                self.tecnologias['Framework'] = 'CodeIgniter'
            
            # Server Detection
            server = tech_headers.get('Server', '').lower()
            if 'apache' in server:
                self.tecnologias['WebServer'] = 'Apache'
            elif 'nginx' in server:
                self.tecnologias['WebServer'] = 'Nginx'
            elif 'iis' in server:
                self.tecnologias['WebServer'] = 'IIS'
            
            # Language Detection
            if '.php' in resp.url or 'php' in tech_headers.get('X-Powered-By', '').lower():
                self.tecnologias['Language'] = 'PHP'
            elif '.asp' in resp.url or 'asp.net' in tech_headers.get('X-Powered-By', '').lower():
                self.tecnologias['Language'] = 'ASP.NET'
            elif '.jsp' in resp.url:
                self.tecnologias['Language'] = 'Java'
            
        except Exception as e:
            self.logger.debug(f"Erro ao detectar tecnologias: {e}")
    
    def _brute_force_diretorios(self, url_base):
        """Brute force de diretórios comuns"""
        def testar_diretorio(diretorio):
            test_url = f"{url_base.rstrip('/')}/{diretorio}"
            try:
                resp = self.session.get(test_url, timeout=5, verify=False)
                if resp.status_code in [200, 301, 302, 403]:
                    self.urls_encontradas.add(test_url)
                    
                    if resp.status_code == 200:
                        self._adicionar_vulnerabilidade(
                            'Diretório Interessante Encontrado',
                            f'Diretório acessível: {test_url}',
                            'BAIXA',
                            test_url
                        )
                    elif resp.status_code == 403:
                        self._adicionar_vulnerabilidade(
                            'Diretório Protegido Encontrado',
                            f'Diretório existe mas está protegido: {test_url}',
                            'BAIXA',
                            test_url
                        )
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(testar_diretorio, self.diretorios_comuns[:20])  # Limitar para performance
    
    def _buscar_arquivos_sensiveis(self, url_base):
        """Busca arquivos sensíveis"""
        def testar_arquivo(arquivo):
            test_url = f"{url_base.rstrip('/')}/{arquivo}"
            try:
                resp = self.session.get(test_url, timeout=5, verify=False)
                if resp.status_code == 200:
                    self.urls_encontradas.add(test_url)
                    
                    criticidade = 'ALTA' if arquivo in ['.env', 'config.php', 'wp-config.php'] else 'MÉDIA'
                    
                    self._adicionar_vulnerabilidade(
                        'Arquivo Sensível Exposto',
                        f'Arquivo sensível acessível: {test_url}',
                        criticidade,
                        test_url
                    )
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            executor.map(testar_arquivo, self.arquivos_sensiveis)
    
    def _analisar_formularios(self):
        """Analisa formulários encontrados"""
        for form in self.formularios:
            # Verificar se é login form
            is_login = any(
                input_field['name'].lower() in ['password', 'pass', 'pwd', 'senha'] 
                for input_field in form['inputs']
            )
            
            if is_login:
                # Verificar CSRF protection
                has_csrf = any(
                    input_field['name'].lower() in ['csrf', 'token', '_token', 'authenticity_token']
                    for input_field in form['inputs']
                )
                
                if not has_csrf:
                    self._adicionar_vulnerabilidade(
                        'Formulário de Login sem Proteção CSRF',
                        f'Formulário em {form["url"]} não possui token CSRF',
                        'MÉDIA',
                        form['url']
                    )
                
                # Verificar HTTPS
                if not form['action'].startswith('https://'):
                    self._adicionar_vulnerabilidade(
                        'Formulário de Login sem HTTPS',
                        f'Formulário em {form["url"]} não usa HTTPS',
                        'ALTA',
                        form['url']
                    )
    
    def _testar_vulnerabilidades(self):
        """Testa vulnerabilidades nos formulários"""
        for form in self.formularios[:5]:  # Limitar para performance
            self._testar_sql_injection(form)
            self._testar_xss(form)
            self._testar_lfi(form)
    
    def _testar_sql_injection(self, form):
        """Testa SQL Injection"""
        try:
            for payload in self.sql_payloads[:3]:  # Limitar testes
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] not in ['submit', 'button', 'hidden']:
                        data[input_field['name']] = payload
                
                if data:
                    resp = self.session.request(
                        form['method'], form['action'], 
                        data=data, timeout=self.timeout, verify=False
                    )
                    
                    # Verificar sinais de SQL error
                    error_patterns = [
                        r'mysql.*error', r'sql.*error', r'oracle.*error',
                        r'postgresql.*error', r'sqlite.*error', r'syntax.*error',
                        r'ORA-[0-9]+', r'ERROR.*[0-9]+.*mysql'
                    ]
                    
                    for pattern in error_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            self._adicionar_vulnerabilidade(
                                'Possível SQL Injection',
                                f'Formulário em {form["url"]} pode ser vulnerável a SQL Injection',
                                'ALTA',
                                form['url']
                            )
                            return
        except Exception as e:
            self.logger.debug(f"Erro teste SQL: {e}")
    
    def _testar_xss(self, form):
        """Testa XSS"""
        try:
            test_payload = "<script>alert('XSS')</script>"
            
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] not in ['submit', 'button', 'hidden', 'password']:
                    data[input_field['name']] = test_payload
            
            if data:
                resp = self.session.request(
                    form['method'], form['action'],
                    data=data, timeout=self.timeout, verify=False
                )
                
                if test_payload in resp.text:
                    self._adicionar_vulnerabilidade(
                        'Vulnerabilidade XSS Detectada',
                        f'Formulário em {form["url"]} reflete input sem sanitização',
                        'ALTA',
                        form['url']
                    )
        except Exception as e:
            self.logger.debug(f"Erro teste XSS: {e}")
    
    def _testar_lfi(self, form):
        """Testa Local File Inclusion"""
        try:
            for payload in self.lfi_payloads[:2]:  # Limitar testes
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] not in ['submit', 'button', 'hidden', 'password']:
                        data[input_field['name']] = payload
                
                if data:
                    resp = self.session.request(
                        form['method'], form['action'],
                        data=data, timeout=self.timeout, verify=False
                    )
                    
                    # Verificar sinais de LFI
                    if 'root:x:0:0:' in resp.text or '[boot loader]' in resp.text:
                        self._adicionar_vulnerabilidade(
                            'Local File Inclusion (LFI)',
                            f'Formulário em {form["url"]} permite leitura de arquivos do sistema',
                            'ALTA',
                            form['url']
                        )
                        return
        except Exception as e:
            self.logger.debug(f"Erro teste LFI: {e}")
    
    def _analisar_ssl(self, url):
        """Analisa configuração SSL/TLS"""
        if not url.startswith('https://'):
            return
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Conectar e verificar SSL
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Verificar protocolo SSL
                    if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self._adicionar_vulnerabilidade(
                            'Protocolo SSL/TLS Inseguro',
                            f'Site usa protocolo inseguro: {ssock.version()}',
                            'MÉDIA',
                            url
                        )
                    
                    # Verificar cipher suites fracas
                    if cipher and 'RC4' in cipher[0] or 'DES' in cipher[0]:
                        self._adicionar_vulnerabilidade(
                            'Cipher Suite Fraca',
                            f'Site usa cipher fraca: {cipher[0]}',
                            'MÉDIA',
                            url
                        )
                        
        except Exception as e:
            self.logger.debug(f"Erro análise SSL: {e}")
    
    def _verificar_headers_seguranca(self, url):
        """Verifica headers de segurança"""
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            
            headers_importantes = {
                'X-Frame-Options': 'Proteção contra clickjacking',
                'X-XSS-Protection': 'Proteção XSS do browser',
                'X-Content-Type-Options': 'Prevenção MIME sniffing',
                'Strict-Transport-Security': 'HSTS para HTTPS',
                'Content-Security-Policy': 'Política de segurança de conteúdo',
                'X-Content-Security-Policy': 'CSP para browsers antigos',
                'Referrer-Policy': 'Controle de referrer',
                'Feature-Policy': 'Controle de features do browser'
            }
            
            headers_ausentes = []
            for header, descricao in headers_importantes.items():
                if header not in resp.headers:
                    headers_ausentes.append(f"{header} ({descricao})")
            
            if headers_ausentes:
                self._adicionar_vulnerabilidade(
                    'Headers de Segurança Ausentes',
                    f'Headers importantes ausentes: {", ".join(headers_ausentes[:3])}',
                    'BAIXA',
                    url
                )
            
            # Verificar headers perigosos
            if 'Server' in resp.headers:
                server = resp.headers['Server']
                if re.search(r'(Apache|nginx|IIS)/[\d.]+', server):
                    self._adicionar_vulnerabilidade(
                        'Versão do Servidor Exposta',
                        f'Header Server revela versão: {server}',
                        'BAIXA',
                        url
                    )
                    
        except Exception as e:
            self.logger.debug(f"Erro verificação headers: {e}")
    
    def _adicionar_vulnerabilidade(self, titulo, descricao, criticidade, url):
        """Adiciona vulnerabilidade encontrada"""
        vuln = {
            'titulo': titulo,
            'descricao': descricao,
            'criticidade': criticidade,
            'url': url,
            'timestamp': datetime.now().isoformat()
        }
        
        self.vulnerabilidades.append(vuln)
        
        emoji = "🚨" if criticidade == 'ALTA' else "⚠️" if criticidade == 'MÉDIA' else "ℹ️"
        self.logger.info(f"{emoji} {titulo}: {descricao}")

# Funções de compatibilidade com o sistema existente
def spider_web(alvo, max_depth=2, max_pages=50):
    """Spider compatível com sistema existente"""
    scanner = ScannerWebAvancado()
    scanner.max_depth = max_depth
    scanner.max_pages = max_pages
    
    resultado = scanner.scan_completo(f"http://{alvo}")
    
    return {
        'urls_encontradas': resultado.get('urls_encontradas', []),
        'formularios': resultado.get('formularios', []),
        'total_urls': resultado.get('total_urls', 0)
    }

def varredura_ativa_basica(alvo, portas_web=[80, 443]):
    """Varredura ativa compatível com sistema existente"""
    scanner = ScannerWebAvancado()
    
    vulnerabilidades_todas = []
    
    for porta in portas_web:
        protocolo = 'https' if porta == 443 else 'http'
        url = f"{protocolo}://{alvo}:{porta}"
        
        resultado = scanner.scan_completo(url)
        if 'vulnerabilidades' in resultado:
            vulnerabilidades_todas.extend(resultado['vulnerabilidades'])
    
    return {
        'vulnerabilidades': vulnerabilidades_todas,
        'total_vulnerabilidades': len(vulnerabilidades_todas)
    }

def main():
    """Teste do scanner"""
    scanner = ScannerWebAvancado()
    resultado = scanner.scan_completo('http://127.0.0.1')
    print(json.dumps(resultado, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
