"""
Plugin de varredura de diretórios web
Descobre diretórios e arquivos em aplicações web usando wordlists
"""

import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Set
from urllib.parse import urljoin, urlparse
import urllib3

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import WebPlugin, PluginResult

# Desabilitar warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DirectoryScannerPlugin(WebPlugin):
    """Plugin para varredura de diretórios e arquivos web"""
    
    def __init__(self):
        super().__init__()
        self.description = "Scanner de diretórios e arquivos web usando wordlists"
        self.version = "1.0.0"
        self.supported_targets = ["url", "domain"]
        self.timeout = 5
        self.max_workers = 20
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa varredura de diretórios"""
        start_time = time.time()
        
        try:
            # Preparar URLs base
            base_urls = self._prepare_base_urls(target, context)
            
            if not base_urls:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error="Não foi possível determinar URLs válidas para varredura"
                )
            
            # Executar varredura para cada URL base
            all_findings = []
            
            for base_url in base_urls:
                findings = self._scan_directories(base_url)
                if findings:
                    all_findings.extend(findings)
            
            # Processar resultados
            processed_results = self._process_findings(all_findings, target)
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data=processed_results
            )
            
        except Exception as e:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error=str(e)
            )
    
    def validate_target(self, target: str) -> bool:
        """Valida se é um alvo válido para varredura de diretórios"""
        return len(target.strip()) > 0
    
    def _prepare_base_urls(self, target: str, context: Dict[str, Any]) -> List[str]:
        """Prepara URLs base para varredura"""
        base_urls = []
        
        # Se já é uma URL
        if target.startswith('http'):
            base_urls.append(target.rstrip('/'))
        else:
            # Construir URLs baseado no contexto
            open_ports = context.get('discoveries', {}).get('open_ports', [])
            
            # HTTPS se porta 443 estiver aberta
            if 443 in open_ports:
                https_url = f"https://{target}"
                if self._test_url_accessibility(https_url):
                    base_urls.append(https_url)
            
            # HTTP se porta 80 estiver aberta ou como fallback
            if 80 in open_ports or not base_urls:
                http_url = f"http://{target}"
                if self._test_url_accessibility(http_url):
                    base_urls.append(http_url)
            
            # Portas web alternativas
            for port in [8080, 8443, 8000, 8008, 3000, 5000]:
                if port in open_ports:
                    protocol = 'https' if port in [8443] else 'http'
                    alt_url = f"{protocol}://{target}:{port}"
                    if self._test_url_accessibility(alt_url):
                        base_urls.append(alt_url)
        
        return base_urls
    
    def _test_url_accessibility(self, url: str) -> bool:
        """Testa se a URL é acessível"""
        try:
            response = requests.head(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'ReconForge/1.0'}
            )
            return response.status_code < 500
        except:
            return False
    
    def _scan_directories(self, base_url: str) -> List[Dict[str, Any]]:
        """Executa varredura de diretórios em uma URL base"""
        findings = []
        
        # Wordlist de diretórios e arquivos comuns
        wordlist = self._get_wordlist()
        
        def check_path(path):
            try:
                full_url = urljoin(base_url, path)
                response = requests.get(
                    full_url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                )
                
                # Considerar sucessos e redirecionamentos
                if response.status_code in [200, 201, 202, 301, 302, 307, 308, 403]:
                    return {
                        'url': full_url,
                        'path': path,
                        'status_code': response.status_code,
                        'content_length': len(response.content) if response.content else 0,
                        'content_type': response.headers.get('content-type', ''),
                        'server': response.headers.get('server', ''),
                        'last_modified': response.headers.get('last-modified', ''),
                        'response_time': response.elapsed.total_seconds()
                    }
            except:
                pass
            return None
        
        # Executar varredura com threads
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(check_path, path): path for path in wordlist}
            
            for future in as_completed(futures, timeout=120):
                try:
                    result = future.result(timeout=self.timeout)
                    if result:
                        findings.append(result)
                except:
                    continue
        
        return findings
    
    def _get_wordlist(self) -> List[str]:
        """Retorna wordlist de diretórios e arquivos comuns"""
        directories = [
            # Diretórios comuns
            'admin', 'administrator', 'test', 'testing', 'dev', 'development',
            'staging', 'stage', 'prod', 'production', 'backup', 'backups',
            'old', 'new', 'tmp', 'temp', 'cache', 'logs', 'log',
            'uploads', 'upload', 'files', 'file', 'downloads', 'download',
            'images', 'img', 'pics', 'pictures', 'media', 'assets',
            'css', 'js', 'javascript', 'scripts', 'includes', 'inc',
            'lib', 'libs', 'library', 'vendor', 'node_modules',
            'api', 'rest', 'webservice', 'service', 'services',
            'doc', 'docs', 'documentation', 'manual', 'help',
            'config', 'configuration', 'settings', 'setup',
            'database', 'db', 'data', 'sql', 'mysql',
            'private', 'secure', 'protected', 'restricted',
            'users', 'user', 'accounts', 'account', 'profiles', 'profile',
            'cms', 'wp-admin', 'wp-content', 'wp-includes',
            'admin', 'administrator', 'manager', 'management',
            'dashboard', 'panel', 'control', 'cp',
            'phpmyadmin', 'phpinfo', 'info', 'status', 'health',
            'blog', 'news', 'forum', 'shop', 'store', 'cart',
            'search', 'login', 'logout', 'auth', 'authentication',
            'register', 'signup', 'signin', 'session',
            'mail', 'email', 'contact', 'feedback',
            'about', 'home', 'index', 'main', 'default'
        ]
        
        files = [
            # Arquivos comuns
            'index.html', 'index.htm', 'index.php', 'index.jsp', 'index.asp',
            'default.html', 'default.htm', 'default.php', 'home.html',
            'robots.txt', 'sitemap.xml', 'sitemap.txt', 'humans.txt',
            'favicon.ico', 'favicon.png', 'apple-touch-icon.png',
            'web.config', '.htaccess', '.htpasswd', 'crossdomain.xml',
            'phpinfo.php', 'info.php', 'test.php', 'config.php',
            'readme.txt', 'readme.html', 'README.md', 'CHANGELOG.md',
            'license.txt', 'LICENSE', 'version.txt', 'VERSION',
            'admin.php', 'admin.html', 'login.php', 'login.html',
            'upload.php', 'uploads.php', 'file.php', 'files.php',
            'backup.zip', 'backup.sql', 'backup.tar.gz', 'database.sql',
            'config.json', 'config.xml', 'settings.json', 'package.json',
            'composer.json', 'bower.json', 'gulpfile.js', 'Gruntfile.js',
            'error.log', 'access.log', 'debug.log', 'app.log',
            '.env', '.env.local', '.env.production', '.git/config',
            'wp-config.php', 'configuration.php', 'settings.php'
        ]
        
        # Combinar diretórios e arquivos
        wordlist = []
        
        # Adicionar diretórios (com e sem barra final)
        for directory in directories:
            wordlist.append(directory)
            wordlist.append(f"{directory}/")
        
        # Adicionar arquivos
        wordlist.extend(files)
        
        # Adicionar variações com números
        for i in range(1, 6):
            wordlist.append(f"admin{i}")
            wordlist.append(f"test{i}")
            wordlist.append(f"backup{i}")
        
        return wordlist
    
    def _process_findings(self, findings: List[Dict[str, Any]], target: str) -> Dict[str, Any]:
        """Processa os achados da varredura"""
        processed = {
            'target': target,
            'total_findings': len(findings),
            'findings_by_status': {},
            'interesting_files': [],
            'potential_admin_panels': [],
            'backup_files': [],
            'config_files': [],
            'sensitive_files': [],
            'directories': [],
            'files': [],
            'all_findings': findings
        }
        
        # Categorizar achados
        for finding in findings:
            status_code = finding.get('status_code', 0)
            path = finding.get('path', '')
            url = finding.get('url', '')
            
            # Agrupar por status code
            if status_code not in processed['findings_by_status']:
                processed['findings_by_status'][status_code] = []
            processed['findings_by_status'][status_code].append(finding)
            
            # Categorizar por tipo
            path_lower = path.lower()
            
            # Diretórios vs arquivos
            if path.endswith('/'):
                processed['directories'].append(finding)
            else:
                processed['files'].append(finding)
            
            # Painéis administrativos
            if any(admin_term in path_lower for admin_term in ['admin', 'login', 'dashboard', 'panel', 'manager']):
                processed['potential_admin_panels'].append(finding)
            
            # Arquivos de backup
            if any(backup_ext in path_lower for backup_ext in ['.bak', '.backup', '.old', '.sql', '.zip', '.tar']):
                processed['backup_files'].append(finding)
            
            # Arquivos de configuração
            if any(config_term in path_lower for config_term in ['config', 'settings', '.env', 'web.config', '.htaccess']):
                processed['config_files'].append(finding)
            
            # Arquivos sensíveis
            if any(sens_term in path_lower for sens_term in ['passwd', 'password', 'secret', 'key', 'token', 'private']):
                processed['sensitive_files'].append(finding)
            
            # Arquivos interessantes (status 200 e tamanho relevante)
            if status_code == 200 and finding.get('content_length', 0) > 100:
                processed['interesting_files'].append(finding)
        
        return processed
