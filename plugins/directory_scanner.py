"""
Plugin de varredura de diretórios web - Estilo GoBuster/FFUF
Descobre diretórios e arquivos em aplicações web usando wordlists
Suporta fuzzing, recursão, filtros avançados e wordlists externas
"""

import requests
import time
import threading
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from pathlib import Path
import urllib3

import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import WebPlugin, PluginResult

# Desabilitar warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DirectoryScannerPlugin(WebPlugin):
    """
    Plugin avançado para varredura de diretórios e arquivos web
    
    Funcionalidades estilo GoBuster/FFUF:
    - Suporte a wordlists externas (SecLists, custom)
    - Modo fuzzing com pattern FUZZ
    - Filtros por tamanho, status, palavras
    - Recursão automática em diretórios
    - Rate limiting configurável
    """
    
    # Caminhos padrão para wordlists
    WORDLIST_PATHS = [
        '/usr/share/seclists/Discovery/Web-Content/',
        '/usr/share/wordlists/',
        '/usr/share/dirb/wordlists/',
    ]
    
    def __init__(self):
        super().__init__()
        self.description = "Scanner de diretórios estilo GoBuster/FFUF com fuzzing e recursão"
        self.version = "2.0.0"
        self.supported_targets = ["url", "domain"]
        
        # Configurações padrão
        self.timeout = 5
        self.max_workers = 20
        self.requests_per_second = 50  # Rate limiting
        self.max_retries = 2
        self.retry_delay = 0.5
        
        # Estatísticas em tempo real
        self._stats = {
            'requests_made': 0,
            'successful': 0,
            'errors': 0,
            'filtered': 0
        }
        self._stats_lock = threading.Lock()
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """
        Executa varredura de diretórios
        
        Args:
            target: URL ou domínio alvo
            context: Contexto da varredura
            **kwargs:
                wordlist: Caminho para wordlist customizada
                fuzz_mode: True para habilitar modo fuzzing
                fuzz_pattern: Pattern com FUZZ (ex: /api/FUZZ/data)
                recursive: Habilitar recursão (default: False)
                max_depth: Profundidade máxima de recursão (default: 3)
                size_filter: Tuple (min, max) para filtrar por tamanho
                exclude_codes: Lista de status codes a ignorar
                exclude_sizes: Lista de tamanhos a ignorar
                word_filter: Filtrar por quantidade de palavras
                line_filter: Filtrar por quantidade de linhas
                extensions: Lista de extensões para testar
                follow_redirects: Seguir redirects (default: False)
        """
        start_time = time.time()
        
        # Resetar estatísticas
        self._stats = {'requests_made': 0, 'successful': 0, 'errors': 0, 'filtered': 0}
        
        try:
            # Extrair opções
            options = self._parse_options(kwargs)
            
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
            
            # Carregar wordlist
            wordlist = self._load_wordlist(options.get('wordlist'))
            
            # Aplicar extensões se especificado (ou usar padrão)
            if options.get('extensions') and not options.get('no_extensions'):
                wordlist = self._apply_extensions(wordlist, options['extensions'])
            
            # Executar varredura
            all_findings = []
            
            for base_url in base_urls:
                if options.get('fuzz_mode') and options.get('fuzz_pattern'):
                    # Modo fuzzing
                    findings = self._fuzz_scan(
                        base_url, 
                        options['fuzz_pattern'], 
                        wordlist, 
                        options
                    )
                else:
                    # Modo normal de diretórios
                    findings = self._scan_directories(
                        base_url, 
                        wordlist, 
                        options,
                        current_depth=0,
                        max_depth=options.get('max_depth', 3) if options.get('recursive') else 0
                    )
                
                if findings:
                    all_findings.extend(findings)
            
            # Processar resultados
            processed_results = self._process_findings(all_findings, target)
            processed_results['statistics'] = self._stats.copy()
            processed_results['options_used'] = options
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data=processed_results,
                summary=f"Encontrados {len(all_findings)} recursos ({self._stats['requests_made']} requests)"
            )
            
        except Exception as e:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={'statistics': self._stats},
                error=str(e)
            )
    
    def _parse_options(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Parseia e valida opções de configuração"""
        # Extensões padrão se não especificadas
        default_extensions = ['php', 'html', 'htm', 'txt', 'json', 'js', 'xml', 'bak', 'old', 'zip', 'asp', 'aspx', 'jsp']
        
        return {
            'wordlist': kwargs.get('wordlist'),
            'fuzz_mode': kwargs.get('fuzz_mode', False),
            'fuzz_pattern': kwargs.get('fuzz_pattern'),
            'recursive': kwargs.get('recursive', False),
            'max_depth': kwargs.get('max_depth', 3),
            'size_filter': kwargs.get('size_filter'),  # (min, max)
            'exclude_codes': kwargs.get('exclude_codes', [404]),
            'exclude_sizes': kwargs.get('exclude_sizes', []),
            'word_filter': kwargs.get('word_filter'),  # (min, max)
            'line_filter': kwargs.get('line_filter'),  # (min, max)
            'extensions': kwargs.get('extensions', default_extensions),  # Extensões padrão
            'no_extensions': kwargs.get('no_extensions', False),  # Desativar extensões
            'follow_redirects': kwargs.get('follow_redirects', False),
            'headers': kwargs.get('headers', {}),
            'cookies': kwargs.get('cookies', {}),
        }
    
    def validate_target(self, target: str) -> bool:
        """Valida se é um alvo válido para varredura de diretórios"""
        return len(target.strip()) > 0
    
    def _load_wordlist(self, wordlist_path: Optional[str] = None) -> List[str]:
        """
        Carrega wordlist de arquivo externo ou usa a melhor disponível
        
        Ordem de busca (prioriza wordlists maiores):
        1. Caminho especificado pelo usuário
        2. SecLists big.txt (~20k palavras) se disponível
        3. DIRB common.txt (~4.6k palavras) se disponível
        4. Wordlists locais do projeto (wordlists/)
        5. Wordlist embutida como fallback (~334 palavras)
        """
        words = []
        
        # 1. Caminho específico fornecido pelo usuário
        if wordlist_path:
            # Caminho absoluto
            if os.path.isabs(wordlist_path) and os.path.exists(wordlist_path):
                words = self._read_wordlist_file(wordlist_path)
            else:
                # Caminho relativo ao projeto
                project_path = Path(__file__).parent.parent / 'wordlists' / wordlist_path
                if project_path.exists():
                    words = self._read_wordlist_file(str(project_path))
                else:
                    # Tentar em SecLists e outros paths do sistema
                    for base_path in self.WORDLIST_PATHS:
                        full_path = os.path.join(base_path, wordlist_path)
                        if os.path.exists(full_path):
                            words = self._read_wordlist_file(full_path)
                            break
        
        # 2. SecLists big.txt (~20k palavras) - padrão recomendado
        if not words:
            seclists_paths = [
                '/usr/share/seclists/Discovery/Web-Content/big.txt',
                '/usr/share/seclists/Discovery/Web-Content/common.txt',
                '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt',
            ]
            for path in seclists_paths:
                if os.path.exists(path):
                    words = self._read_wordlist_file(path)
                    break
        
        # 3. DIRB wordlists (~4.6k palavras)
        if not words:
            dirb_paths = [
                '/usr/share/dirb/wordlists/common.txt',
                '/usr/share/dirb/wordlists/big.txt',
            ]
            for path in dirb_paths:
                if os.path.exists(path):
                    words = self._read_wordlist_file(path)
                    break
        
        # 4. Wordlist local do projeto
        if not words:
            project_wordlist = Path(__file__).parent.parent / 'wordlists' / 'medium.txt'
            if project_wordlist.exists():
                words = self._read_wordlist_file(str(project_wordlist))
        
        # 5. Fallback para wordlist embutida
        if not words:
            words = self._get_builtin_wordlist()
        
        return words
    
    def _read_wordlist_file(self, filepath: str) -> List[str]:
        """Lê arquivo de wordlist"""
        words = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith('#'):
                        words.append(word)
        except Exception:
            pass
        return words
    
    def _apply_extensions(self, wordlist: List[str], extensions: List[str]) -> List[str]:
        """Aplica extensões às palavras da wordlist"""
        extended = []
        for word in wordlist:
            extended.append(word)  # Palavra original
            for ext in extensions:
                ext = ext.lstrip('.')
                extended.append(f"{word}.{ext}")
        return extended
    
    def _prepare_base_urls(self, target: str, context: Dict[str, Any]) -> List[str]:
        """
        Prepara URLs base para varredura
        
        Prioridades:
        1. URL original do contexto (preservada pelo orquestrador)
        2. Target como URL se começar com http
        3. Construção baseada em portas abertas descobertas
        4. Fallback testando portas web comuns
        """
        base_urls = []
        
        # 1. Tentar usar URL original do contexto (passada pelo orquestrador)
        original_target = context.get('original_target', '')
        if original_target and original_target.startswith('http'):
            if self._test_url_accessibility(original_target.rstrip('/')):
                base_urls.append(original_target.rstrip('/'))
        
        # 2. Se target já é uma URL
        if not base_urls and target.startswith('http'):
            if self._test_url_accessibility(target.rstrip('/')):
                base_urls.append(target.rstrip('/'))
        
        # 3. Construir URLs baseado no contexto de portas descobertas
        if not base_urls:
            open_ports = context.get('discoveries', {}).get('open_ports', [])
            
            # HTTPS se porta 443 estiver aberta
            if 443 in open_ports:
                https_url = f"https://{target}"
                if self._test_url_accessibility(https_url):
                    base_urls.append(https_url)
            
            # HTTP se porta 80 estiver aberta
            if 80 in open_ports:
                http_url = f"http://{target}"
                if self._test_url_accessibility(http_url):
                    base_urls.append(http_url)
            
            # Portas web alternativas (incluindo 5001)
            for port in [8080, 8443, 8000, 8008, 3000, 5000, 5001, 9000, 9090]:
                if port in open_ports:
                    protocol = 'https' if port in [8443, 9443] else 'http'
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
                headers={'User-Agent': 'ReconForge/2.0'}
            )
            return response.status_code < 500
        except:
            return False
    
    def _fuzz_scan(
        self, 
        base_url: str, 
        fuzz_pattern: str, 
        wordlist: List[str],
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Executa varredura em modo fuzzing
        
        Pattern FUZZ é substituído por cada palavra da wordlist
        Suporta múltiplos FUZZ no mesmo pattern
        """
        findings = []
        
        # Verificar se há FUZZ no pattern
        if 'FUZZ' not in fuzz_pattern:
            fuzz_pattern = fuzz_pattern.rstrip('/') + '/FUZZ'
        
        def fuzz_word(word):
            try:
                # Substituir FUZZ pelo word
                fuzzed_path = fuzz_pattern.replace('FUZZ', word)
                full_url = urljoin(base_url + '/', fuzzed_path.lstrip('/'))
                
                result = self._make_request(full_url, options)
                
                if result and self._should_include(result, options):
                    result['fuzz_word'] = word
                    result['fuzz_pattern'] = fuzz_pattern
                    return result
            except:
                pass
            return None
        
        # Rate limiting
        delay = 1.0 / self.requests_per_second if self.requests_per_second > 0 else 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for word in wordlist:
                futures[executor.submit(fuzz_word, word)] = word
                time.sleep(delay)
            
            for future in as_completed(futures, timeout=300):
                try:
                    result = future.result(timeout=self.timeout * 2)
                    if result:
                        findings.append(result)
                except:
                    continue
        
        return findings
    
    def _scan_directories(
        self, 
        base_url: str, 
        wordlist: List[str],
        options: Dict[str, Any],
        current_depth: int = 0,
        max_depth: int = 0,
        discovered_dirs: Set[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Executa varredura de diretórios com suporte a recursão
        """
        if discovered_dirs is None:
            discovered_dirs = set()
        
        findings = []
        new_dirs = []
        
        def check_path(path):
            try:
                full_url = urljoin(base_url + '/', path.lstrip('/'))
                
                result = self._make_request(full_url, options)
                
                if result and self._should_include(result, options):
                    # Verificar se é diretório para recursão
                    if (result.get('status_code') in [200, 301, 302, 307, 308] and 
                        (path.endswith('/') or result.get('content_type', '').startswith('text/html'))):
                        result['is_directory'] = True
                    return result
            except:
                pass
            return None
        
        # Rate limiting
        delay = 1.0 / self.requests_per_second if self.requests_per_second > 0 else 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for path in wordlist:
                futures[executor.submit(check_path, path)] = path
                time.sleep(delay)
            
            for future in as_completed(futures, timeout=300):
                try:
                    result = future.result(timeout=self.timeout * 2)
                    if result:
                        findings.append(result)
                        
                        # Coletar diretórios para recursão
                        if (result.get('is_directory') and 
                            current_depth < max_depth and
                            result['path'] not in discovered_dirs):
                            new_dirs.append(result['path'].rstrip('/'))
                            discovered_dirs.add(result['path'])
                except:
                    continue
        
        # Recursão em diretórios descobertos
        if new_dirs and current_depth < max_depth:
            for new_dir in new_dirs:
                new_base = urljoin(base_url + '/', new_dir.lstrip('/'))
                recursive_findings = self._scan_directories(
                    new_base,
                    wordlist,
                    options,
                    current_depth + 1,
                    max_depth,
                    discovered_dirs
                )
                findings.extend(recursive_findings)
        
        return findings
    
    def _make_request(
        self, 
        url: str, 
        options: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Faz requisição HTTP com retry e coleta métricas
        """
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        headers.update(options.get('headers', {}))
        
        for attempt in range(self.max_retries + 1):
            try:
                with self._stats_lock:
                    self._stats['requests_made'] += 1
                
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=options.get('follow_redirects', False),
                    headers=headers,
                    cookies=options.get('cookies', {})
                )
                
                content = response.content
                content_text = response.text if response.text else ''
                
                result = {
                    'url': url,
                    'path': urlparse(url).path,
                    'status_code': response.status_code,
                    'content_length': len(content) if content else 0,
                    'content_type': response.headers.get('content-type', ''),
                    'server': response.headers.get('server', ''),
                    'last_modified': response.headers.get('last-modified', ''),
                    'response_time': response.elapsed.total_seconds(),
                    'word_count': len(content_text.split()),
                    'line_count': len(content_text.splitlines()),
                    'redirect_url': response.headers.get('location', '') if response.is_redirect else ''
                }
                
                with self._stats_lock:
                    self._stats['successful'] += 1
                
                return result
                
            except requests.exceptions.Timeout:
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay * (attempt + 1))
                continue
            except Exception:
                with self._stats_lock:
                    self._stats['errors'] += 1
                break
        
        return None
    
    def _should_include(self, result: Dict[str, Any], options: Dict[str, Any]) -> bool:
        """
        Aplica filtros para determinar se o resultado deve ser incluído
        """
        status_code = result.get('status_code', 0)
        content_length = result.get('content_length', 0)
        word_count = result.get('word_count', 0)
        line_count = result.get('line_count', 0)
        
        # Filtro por status code
        exclude_codes = options.get('exclude_codes', [404])
        if status_code in exclude_codes:
            with self._stats_lock:
                self._stats['filtered'] += 1
            return False
        
        # Apenas status de sucesso ou redirect
        if status_code >= 400 and status_code != 403:
            with self._stats_lock:
                self._stats['filtered'] += 1
            return False
        
        # Filtro por tamanho
        size_filter = options.get('size_filter')
        if size_filter:
            min_size, max_size = size_filter
            if min_size is not None and content_length < min_size:
                with self._stats_lock:
                    self._stats['filtered'] += 1
                return False
            if max_size is not None and content_length > max_size:
                with self._stats_lock:
                    self._stats['filtered'] += 1
                return False
        
        # Filtro por tamanhos específicos a excluir
        exclude_sizes = options.get('exclude_sizes', [])
        if content_length in exclude_sizes:
            with self._stats_lock:
                self._stats['filtered'] += 1
            return False
        
        # Filtro por palavras
        word_filter = options.get('word_filter')
        if word_filter:
            min_words, max_words = word_filter
            if min_words is not None and word_count < min_words:
                with self._stats_lock:
                    self._stats['filtered'] += 1
                return False
            if max_words is not None and word_count > max_words:
                with self._stats_lock:
                    self._stats['filtered'] += 1
                return False
        
        # Filtro por linhas
        line_filter = options.get('line_filter')
        if line_filter:
            min_lines, max_lines = line_filter
            if min_lines is not None and line_count < min_lines:
                with self._stats_lock:
                    self._stats['filtered'] += 1
                return False
            if max_lines is not None and line_count > max_lines:
                with self._stats_lock:
                    self._stats['filtered'] += 1
                return False
        
        return True
    
    def _get_builtin_wordlist(self) -> List[str]:
        """
        Retorna wordlist embutida otimizada para pentest
        ~500 termos mais relevantes baseados em descobertas reais
        """
        directories = [
            # Painéis administrativos
            'admin', 'administrator', 'adm', 'admin1', 'admin2', 'admin_area',
            'admincp', 'admindashboard', 'adminlogin', 'adminpanel', 'admins',
            'cpanel', 'controlpanel', 'dashboard', 'panel', 'manage', 'manager',
            'management', 'moderator', 'webadmin', 'siteadmin', 'useradmin',
            'superadmin', 'root', 'sudo',
            
            # Autenticação e usuários
            'login', 'logout', 'signin', 'signout', 'signup', 'register',
            'auth', 'authentication', 'oauth', 'sso', 'session', 'sessions',
            'user', 'users', 'account', 'accounts', 'profile', 'profiles',
            'member', 'members', 'cliente', 'clientes', 'customer', 'customers',
            'password', 'passwords', 'forgot', 'reset', 'recover', 'recovery',
            
            # Desenvolvimento e debug
            'test', 'testing', 'tests', 'dev', 'devel', 'development',
            'staging', 'stage', 'demo', 'beta', 'alpha', 'sandbox',
            'debug', 'trace', 'error', 'errors', 'exception', 'exceptions',
            'qa', 'uat', 'preprod', 'pre-prod',
            
            # Backups e arquivos antigos
            'backup', 'backups', 'bak', 'old', 'old_site', 'old_files',
            'archive', 'archives', 'save', 'saved', 'copy', 'temp', 'tmp',
            'cache', 'cached', 'dump', 'dumps', 'export', 'exports',
            
            # Uploads e arquivos
            'upload', 'uploads', 'file', 'files', 'documents', 'docs',
            'download', 'downloads', 'attachment', 'attachments', 'media',
            'images', 'img', 'image', 'pics', 'pictures', 'photo', 'photos',
            'video', 'videos', 'audio', 'music', 'content', 'contents',
            
            # Assets e recursos estáticos
            'assets', 'static', 'public', 'resources', 'res', 'resource',
            'css', 'styles', 'style', 'js', 'javascript', 'scripts', 'script',
            'fonts', 'font', 'icons', 'icon', 'themes', 'theme', 'templates',
            
            # Bibliotecas e dependências
            'lib', 'libs', 'library', 'libraries', 'vendor', 'vendors',
            'node_modules', 'bower_components', 'packages', 'modules',
            'includes', 'include', 'inc', 'common', 'shared', 'core',
            
            # APIs e serviços
            'api', 'apis', 'rest', 'restapi', 'graphql', 'soap', 'wsdl',
            'v1', 'v2', 'v3', 'v4', 'api/v1', 'api/v2', 'api/v3',
            'webservice', 'webservices', 'service', 'services', 'endpoint',
            'swagger', 'openapi', 'api-docs', 'apidocs', 'docs/api',
            
            # Banco de dados
            'database', 'databases', 'db', 'dbs', 'sql', 'mysql', 'mssql',
            'postgres', 'postgresql', 'mongodb', 'redis', 'oracle', 'sqlite',
            'phpmyadmin', 'pma', 'adminer', 'dbadmin', 'sqladmin',
            
            # Logs e monitoramento
            'log', 'logs', 'logging', 'monitor', 'monitoring', 'metrics',
            'status', 'health', 'healthcheck', 'ping', 'heartbeat', 'stats',
            'analytics', 'statistics', 'report', 'reports', 'audit', 'audits',
            
            # Configurações
            'config', 'configs', 'configuration', 'configurations', 'conf',
            'settings', 'setting', 'setup', 'install', 'installer', 'wizard',
            'env', 'environment', 'environments',
            
            # WordPress
            'wp-admin', 'wp-content', 'wp-includes', 'wp-json', 'wordpress',
            'wp-login', 'wp-config', 'wp', 'blog', 'blogs',
            
            # Joomla
            'joomla', 'administrator', 'components', 'modules', 'plugins',
            
            # Drupal
            'drupal', 'sites', 'sites/all', 'sites/default',
            
            # Laravel/PHP
            'laravel', 'storage', 'storage/logs', 'artisan', 'telescope',
            'horizon', 'nova', 'bootstrap', 'app', 'application',
            
            # Node.js/Express
            'node', 'express', 'routes', 'controllers', 'models', 'views',
            
            # Django/Python
            'django', 'flask', 'python', '__pycache__', 'venv', 'virtualenv',
            
            # ASP.NET
            'aspnet', 'bin', 'App_Data', 'App_Code', 'App_Browsers',
            
            # Git e versionamento
            '.git', '.git/config', '.git/HEAD', '.gitignore', '.svn', '.hg',
            '.bzr', '.cvs', 'cvs', 'svn', 'git', 'repo', 'repository',
            
            # CI/CD e DevOps
            '.github', '.gitlab', '.jenkins', 'jenkins', 'docker', 'k8s',
            'kubernetes', 'ansible', 'terraform', 'ci', 'cd', 'deploy',
            'deployment', 'deployments', 'releases', 'release', 'build', 'builds',
            
            # Segurança
            'security', 'secure', 'ssl', 'tls', 'certs', 'certificates',
            'private', 'protected', 'restricted', 'internal', 'hidden',
            'secret', 'secrets', 'keys', 'key', 'token', 'tokens', 'credentials',
            
            # E-commerce
            'shop', 'store', 'cart', 'checkout', 'payment', 'payments',
            'order', 'orders', 'product', 'products', 'catalog', 'catalogue',
            
            # CMS genérico
            'cms', 'portal', 'intranet', 'extranet', 'backend', 'frontend',
            'home', 'index', 'main', 'default', 'start', 'landing',
            'about', 'contact', 'help', 'support', 'faq', 'terms', 'privacy',
            
            # Outros
            'cron', 'jobs', 'task', 'tasks', 'queue', 'queues', 'worker',
            'mail', 'email', 'smtp', 'newsletter', 'subscribe', 'unsubscribe',
            'forum', 'forums', 'community', 'social', 'share', 'feed', 'feeds',
            'rss', 'xml', 'json', 'ajax', 'async', 'websocket', 'socket',
            'proxy', 'gateway', 'redirect', 'callback', 'webhook', 'webhooks'
        ]
        
        files = [
            # Arquivos de índice
            'index', 'default', 'home', 'main', 'start', 'welcome',
            
            # Robots e SEO
            'robots.txt', 'sitemap.xml', 'sitemap.txt', 'sitemap_index.xml',
            'humans.txt', 'ads.txt', 'security.txt', '.well-known/security.txt',
            
            # Ícones e manifestos
            'favicon.ico', 'favicon.png', 'apple-touch-icon.png',
            'manifest.json', 'browserconfig.xml', 'site.webmanifest',
            
            # Configurações de servidor
            'web.config', '.htaccess', '.htpasswd', 'nginx.conf', 'httpd.conf',
            'crossdomain.xml', 'clientaccesspolicy.xml',
            
            # PHP
            'phpinfo.php', 'info.php', 'test.php', 'config.php', 'conn.php',
            'connection.php', 'db.php', 'database.php', 'admin.php', 'login.php',
            'upload.php', 'shell.php', 'cmd.php', 'c99.php', 'r57.php',
            
            # Configurações e ambiente
            '.env', '.env.local', '.env.production', '.env.staging', '.env.dev',
            '.env.example', '.env.backup', '.env.old', '.env.bak',
            'config.json', 'config.xml', 'config.yml', 'config.yaml',
            'settings.json', 'settings.xml', 'settings.yml', 'settings.yaml',
            'app.config', 'application.yml', 'application.properties',
            'database.yml', 'secrets.yml', 'credentials.json',
            
            # WordPress
            'wp-config.php', 'wp-config.php.bak', 'wp-config.php.old',
            'wp-config.php~', 'wp-config.php.save', 'wp-config.php.swp',
            'xmlrpc.php', 'wp-login.php', 'wp-cron.php',
            
            # Node.js/NPM
            'package.json', 'package-lock.json', 'yarn.lock', 'npm-debug.log',
            '.npmrc', '.yarnrc', 'node_modules/.package-lock.json',
            
            # PHP Composer
            'composer.json', 'composer.lock', 'auth.json',
            
            # Python
            'requirements.txt', 'Pipfile', 'Pipfile.lock', 'setup.py',
            
            # Ruby
            'Gemfile', 'Gemfile.lock', '.ruby-version',
            
            # Java/Maven
            'pom.xml', 'build.gradle', 'build.xml',
            
            # Docker
            'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
            '.dockerignore',
            
            # Git
            '.git/config', '.git/HEAD', '.git/index', '.gitignore',
            '.gitattributes', '.gitmodules',
            
            # Documentação
            'readme.txt', 'readme.html', 'readme.md', 'README.md', 'README.txt',
            'CHANGELOG.md', 'CHANGELOG.txt', 'HISTORY.md', 'CHANGES.txt',
            'license.txt', 'LICENSE', 'LICENSE.md', 'COPYING',
            'INSTALL.md', 'INSTALL.txt', 'CONTRIBUTING.md',
            
            # Backups
            'backup.zip', 'backup.tar.gz', 'backup.sql', 'backup.sql.gz',
            'database.sql', 'db.sql', 'dump.sql', 'export.sql',
            'site.zip', 'www.zip', 'html.zip', 'web.zip',
            'old.zip', 'backup.rar', 'archive.zip', 'files.zip',
            
            # Logs
            'error.log', 'errors.log', 'access.log', 'debug.log', 'app.log',
            'application.log', 'system.log', 'server.log', 'php_errors.log',
            'laravel.log', 'storage/logs/laravel.log',
            
            # API docs
            'swagger.json', 'swagger.yaml', 'openapi.json', 'openapi.yaml',
            'api.json', 'api.yaml', 'api/docs', 'docs/api',
            
            # Info/Debug
            'server-status', 'server-info', 'phpinfo', 'debug', 'trace',
            'elmah.axd', 'trace.axd', 'profiler',
            
            # Shells e backdoors (para detecção)
            'shell', 'cmd', 'c99', 'r57', 'wso', 'b374k', 'alfa',
            
            # Chaves e credenciais
            'id_rsa', 'id_rsa.pub', 'id_dsa', 'authorized_keys',
            'known_hosts', '.ssh/id_rsa', '.ssh/authorized_keys',
            'private.key', 'server.key', 'ssl.key', 'certificate.crt'
        ]
        
        # Combinar diretórios (com e sem barra)
        wordlist = []
        for directory in directories:
            wordlist.append(directory)
            wordlist.append(f"{directory}/")
        
        # Adicionar arquivos
        wordlist.extend(files)
        
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
            'api_endpoints': [],
            'directories': [],
            'files': [],
            'all_findings': findings
        }
        
        # Categorizar achados
        for finding in findings:
            status_code = finding.get('status_code', 0)
            path = finding.get('path', '')
            
            # Agrupar por status code
            if status_code not in processed['findings_by_status']:
                processed['findings_by_status'][status_code] = []
            processed['findings_by_status'][status_code].append(finding)
            
            # Categorizar por tipo
            path_lower = path.lower()
            
            # Diretórios vs arquivos
            if finding.get('is_directory') or path.endswith('/'):
                processed['directories'].append(finding)
            else:
                processed['files'].append(finding)
            
            # Painéis administrativos
            if any(admin_term in path_lower for admin_term in 
                   ['admin', 'login', 'dashboard', 'panel', 'manager', 'control']):
                processed['potential_admin_panels'].append(finding)
            
            # Arquivos de backup
            if any(backup_ext in path_lower for backup_ext in 
                   ['.bak', '.backup', '.old', '.sql', '.zip', '.tar', '.gz', '.rar']):
                processed['backup_files'].append(finding)
            
            # Arquivos de configuração
            if any(config_term in path_lower for config_term in 
                   ['config', 'settings', '.env', 'web.config', '.htaccess', 'application']):
                processed['config_files'].append(finding)
            
            # Arquivos sensíveis
            if any(sens_term in path_lower for sens_term in 
                   ['passwd', 'password', 'secret', 'key', 'token', 'private', 'credential']):
                processed['sensitive_files'].append(finding)
            
            # Endpoints de API
            if any(api_term in path_lower for api_term in 
                   ['api', 'rest', 'graphql', 'swagger', 'openapi', 'v1', 'v2', 'v3']):
                processed['api_endpoints'].append(finding)
            
            # Arquivos interessantes (status 200 e tamanho relevante)
            if status_code == 200 and finding.get('content_length', 0) > 100:
                processed['interesting_files'].append(finding)
        
        return processed
