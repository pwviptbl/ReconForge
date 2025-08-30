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
        
        # Arquivos interessantes (inspirado no Nikto)
        self.arquivos_interessantes = [
            'admin.php', 'admin.asp', 'admin.aspx', 'admin.html',
            'administrator.php', 'administrator.asp', 'administrator.aspx',
            'login.php', 'login.asp', 'login.aspx', 'signin.php',
            'auth.php', 'authentication.php', 'session.php',
            'config.php', 'configuration.php', 'settings.php',
            'install.php', 'setup.php', 'upgrade.php',
            'backup.php', 'backups.php', 'restore.php',
            'test.php', 'testing.php', 'demo.php', 'example.php',
            'info.php', 'phpinfo.php', 'server-status', 'server-info',
            'status', 'phpmyadmin', 'pma', 'mysql', 'database',
            '.git', '.svn', '.DS_Store', 'Thumbs.db',
            'web.config', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'xmlrpc.php', 'readme.txt', 'changelog.txt', 'license.txt',
            'wp-admin', 'wp-login.php', 'wp-config.php', 'wp-content',
            'administrator', 'adminer.php', 'admin', 'cpanel',
            'plesk-stat', 'awstats', 'webalizer', 'stats'
        ]
        
        # CGI comuns
        self.cgi_comuns = [
            'cgi-bin/test-cgi', 'cgi-bin/printenv', 'cgi-bin/cgitest.exe',
            'cgi-bin/nph-test-cgi', 'cgi-bin/nph-publish', 'cgi-bin/php.cgi',
            'cgi-bin/handler', 'cgi-bin/webcgi.exe', 'cgi-bin/websendmail.exe',
            'cgi-bin/webdist.cgi', 'cgi-bin/faxsurvey', 'cgi-bin/htmlscript',
            'cgi-bin/pfdispaly.cgi', 'cgi-bin/perl.exe', 'cgi-bin/wwwboard.pl',
            'cgi-bin/www-sql.pl', 'cgi-bin/view-source', 'cgi-bin/campas',
            'cgi-bin/aglimpse', 'cgi-bin/man.sh', 'cgi-bin/AT-admin.cgi',
            'cgi-bin/filemail.pl', 'cgi-bin/maillist.pl', 'cgi-bin/jj',
            'cgi-bin/info2www', 'cgi-bin/files.pl', 'cgi-bin/finger',
            'cgi-bin/bnbform.cgi', 'cgi-bin/survey.cgi', 'cgi-bin/AnyForm2'
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
            
            # 4.1. Verificação de arquivos interessantes (Nikto-style)
            self.logger.info("🔍 Fase 4.1: Verificando arquivos interessantes...")
            self._verificar_arquivos_interessantes(url_base)
            
            # 4.2. Verificação CGI
            self.logger.info("🐚 Fase 4.2: Verificando CGI...")
            self._verificar_cgi(url_base)
            
            # 4.3. Verificação de configurações incorretas
            self.logger.info("⚙️ Fase 4.3: Verificando configurações incorretas...")
            self._verificar_configuracao_incorreta(url_base)
            
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
            
            # 9. Verificação de arquivos interessantes
            self.logger.info("📂 Fase 9: Verificando arquivos interessantes...")
            self._verificar_arquivos_interessantes(url_base)
            
            # 10. Verificação de CGI
            self.logger.info("🐞 Fase 10: Verificando vulnerabilidades em CGI...")
            self._verificar_cgi(url_base)
            
            # 11. Verificação de configurações incorretas
            self.logger.info("⚙️ Fase 11: Verificando configurações incorretas...")
            self._verificar_configuracao_incorreta(url_base)
            
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
    
    def _verificar_arquivos_interessantes(self, url_base):
        """Verifica arquivos interessantes (inspirado no Nikto)"""
        def testar_arquivo_interessante(arquivo):
            test_url = f"{url_base.rstrip('/')}/{arquivo}"
            try:
                resp = self.session.get(test_url, timeout=5, verify=False)
                if resp.status_code == 200:
                    self.urls_encontradas.add(test_url)
                    
                    # Categorizar criticidade baseada no tipo de arquivo
                    if arquivo in ['admin.php', 'administrator.php', 'login.php', 'wp-admin', 'admin']:
                        criticidade = 'ALTA'
                        tipo = 'Painel Administrativo'
                    elif arquivo in ['config.php', 'settings.php', 'wp-config.php', '.git']:
                        criticidade = 'ALTA'
                        tipo = 'Arquivo de Configuração'
                    elif arquivo in ['phpinfo.php', 'server-status', 'server-info']:
                        criticidade = 'MÉDIA'
                        tipo = 'Informação do Servidor'
                    elif arquivo in ['test.php', 'demo.php', 'readme.txt']:
                        criticidade = 'BAIXA'
                        tipo = 'Arquivo de Teste/Documentação'
                    else:
                        criticidade = 'BAIXA'
                        tipo = 'Arquivo Interessante'
                    
                    self._adicionar_vulnerabilidade(
                        f'{tipo} Encontrado',
                        f'Arquivo potencialmente interessante acessível: {test_url}',
                        criticidade,
                        test_url
                    )
                elif resp.status_code == 403:
                    # Arquivo existe mas está protegido
                    self._adicionar_vulnerabilidade(
                        'Arquivo Interessante Protegido',
                        f'Arquivo existe mas está protegido: {test_url}',
                        'BAIXA',
                        test_url
                    )
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(testar_arquivo_interessante, self.arquivos_interessantes[:30])  # Limitar para performance
    
    def _verificar_cgi(self, url_base):
        """Verifica vulnerabilidades em CGI (inspirado no Nikto)"""
        def testar_cgi(cgi_path):
            test_url = f"{url_base.rstrip('/')}/{cgi_path}"
            try:
                resp = self.session.get(test_url, timeout=5, verify=False)
                if resp.status_code == 200:
                    self.urls_encontradas.add(test_url)
                    
                    # Verificar se o CGI executa comandos ou revela informações
                    content = resp.text.lower()
                    
                    if 'server' in content or 'environment' in content or 'path' in content:
                        self._adicionar_vulnerabilidade(
                            'CGI Revelando Informações',
                            f'CGI revela informações do servidor: {test_url}',
                            'MÉDIA',
                            test_url
                        )
                    
                    # Verificar se aceita parâmetros perigosos
                    if '?' in test_url or resp.text.strip():
                        self._adicionar_vulnerabilidade(
                            'CGI Executável Encontrado',
                            f'CGI potencialmente executável: {test_url}',
                            'BAIXA',
                            test_url
                        )
                        
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            executor.map(testar_cgi, self.cgi_comuns[:20])  # Limitar para performance
    
    def _verificar_configuracao_incorreta(self, url_base):
        """Verifica configurações incorretas (inspirado no Nikto)"""
        try:
            # Verificar robots.txt
            robots_url = f"{url_base.rstrip('/')}/robots.txt"
            resp = self.session.get(robots_url, timeout=5, verify=False)
            if resp.status_code == 200:
                content = resp.text
                self.urls_encontradas.add(robots_url)
                
                # Verificar se revela diretórios sensíveis
                sensitive_paths = ['admin', 'backup', 'config', 'private', '.git']
                for path in sensitive_paths:
                    if path in content.lower():
                        self._adicionar_vulnerabilidade(
                            'Robots.txt Revela Caminhos Sensíveis',
                            f'robots.txt contém referência a caminho sensível: {path}',
                            'BAIXA',
                            robots_url
                        )
                        break
            
            # Verificar .htaccess
            htaccess_url = f"{url_base.rstrip('/')}/.htaccess"
            resp = self.session.get(htaccess_url, timeout=5, verify=False)
            if resp.status_code == 200:
                self._adicionar_vulnerabilidade(
                    '.htaccess Exposto',
                    f'Arquivo .htaccess está acessível publicamente: {htaccess_url}',
                    'MÉDIA',
                    htaccess_url
                )
            
            # Verificar crossdomain.xml
            crossdomain_url = f"{url_base.rstrip('/')}/crossdomain.xml"
            resp = self.session.get(crossdomain_url, timeout=5, verify=False)
            if resp.status_code == 200:
                content = resp.text
                if '<allow-access-from domain="*"' in content:
                    self._adicionar_vulnerabilidade(
                        'Crossdomain.xml Permissivo',
                        f'crossdomain.xml permite acesso de qualquer domínio: {crossdomain_url}',
                        'MÉDIA',
                        crossdomain_url
                    )
                    
        except Exception as e:
            self.logger.debug(f"Erro verificação configuração: {e}")
    
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
