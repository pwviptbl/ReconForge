"""
Plugin de Navegação Web Avançada com Selenium
Navega em sites automaticamente, analisa formulários, faz login e mapeia aplicações web
"""

import time
import json
import re
import os
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from typing import Dict, Any, List, Optional, Set, Tuple
from pathlib import Path
import base64

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

from core.plugin_base import WebPlugin, PluginResult


class WebCrawlerPlugin(WebPlugin):
    """Plugin avançado de navegação web com Selenium"""
    
    def __init__(self):
        super().__init__()
        self.description = "Navegação web avançada: análise de formulários, login automático, mapeamento"
        self.version = "1.0.0"
        self.supported_targets = ["url", "domain"]
        
        # Configurações padrão
        self.config = {
            'headless': True,
            'timeout': 30,
            'page_load_timeout': 60,
            'implicit_wait': 10,
            'max_depth': 3,
            'max_pages': 50,
            'screenshot_on_error': True,
            'follow_redirects': True,
            'analyze_forms': True,
            'attempt_login': True,
            'common_credentials': True,
            'javascript_enabled': True,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'window_size': (1920, 1080),
            'extract_apis': True,
            'analyze_cookies': True,
            'check_security_headers': True,
            'detect_frameworks': True
        }
        
        # Credenciais comuns para teste de login
        self.common_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('test', 'test'),
            ('demo', 'demo'),
            ('guest', 'guest'),
            ('user', 'user'),
            ('administrator', 'administrator'),
            ('admin', ''),
            ('', 'admin')
        ]
        
        # Seletores comuns para formulários de login
        self.login_selectors = {
            'username_fields': [
                'input[name*="user"]', 'input[name*="login"]', 'input[name*="email"]',
                'input[id*="user"]', 'input[id*="login"]', 'input[id*="email"]',
                'input[type="email"]', '#username', '#user', '#login', '#email'
            ],
            'password_fields': [
                'input[type="password"]', 'input[name*="pass"]', 'input[id*="pass"]',
                '#password', '#pass', '#pwd'
            ],
            'submit_buttons': [
                'input[type="submit"]', 'button[type="submit"]', 'button',
                '*[value*="login"]', '*[value*="sign"]', '*[value*="enter"]'
            ]
        }
        
        # Frameworks/tecnologias detectáveis
        self.framework_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin'],
            'Drupal': ['drupal', 'sites/default', 'modules'],
            'Joomla': ['joomla', 'components', 'templates'],
            'Laravel': ['laravel_session', '_token'],
            'Django': ['csrfmiddlewaretoken', 'django'],
            'React': ['react', '_react', 'react-dom'],
            'Angular': ['ng-', 'angular', '_angular'],
            'Vue.js': ['vue', '_vue', 'v-'],
            'Bootstrap': ['bootstrap', 'btn-', 'container-'],
            'jQuery': ['jquery', '$'],
            'ASP.NET': ['__VIEWSTATE', '__EVENTVALIDATION', 'aspx'],
            'PHP': ['.php', 'PHPSESSID'],
            'JSP': ['.jsp', 'JSESSIONID'],
            'Node.js': ['express', 'connect.sid']
        }
        
        self.driver = None
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa navegação web avançada"""
        start_time = time.time()
        
        if not SELENIUM_AVAILABLE:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error="Selenium não está disponível"
            )
        
        try:
            # Normalizar URL
            url = self._normalize_url(target)
            
            # Configurar WebDriver
            self._setup_driver()
            
            results = {
                'target': url,
                'timestamp': time.time(),
                'pages_crawled': [],
                'forms_found': [],
                'login_attempts': [],
                'apis_discovered': [],
                'cookies_analysis': {},
                'security_headers': {},
                'frameworks_detected': [],
                'errors': [],
                'screenshots': [],
                'navigation_map': {},
                'parameters_discovered': {},
                'endpoints_discovered': set(),
                'statistics': {}
            }
            
            # 1. Navegação inicial
            initial_page = self._crawl_page(url, depth=0)
            if initial_page:
                results['pages_crawled'].append(initial_page)
                results['navigation_map'][url] = initial_page
            
            # 2. Análise de formulários na página inicial
            if self.config.get('analyze_forms', True):
                forms = self._analyze_forms(url)
                results['forms_found'].extend(forms)
            
            # 3. Tentativa de login se houver formulário
            if self.config.get('attempt_login', True) and forms:
                login_results = self._attempt_login(url, forms)
                results['login_attempts'].extend(login_results)
            
            # 4. Crawling em profundidade
            visited_urls = {url}
            urls_to_visit = self._extract_links(url)
            current_depth = 1
            max_depth = self.config.get('max_depth', 3)
            max_pages = self.config.get('max_pages', 50)
            
            while (urls_to_visit and 
                   current_depth <= max_depth and 
                   len(results['pages_crawled']) < max_pages):
                
                next_urls = set()
                
                for next_url in urls_to_visit:
                    if next_url in visited_urls:
                        continue
                    
                    if len(results['pages_crawled']) >= max_pages:
                        break
                    
                    try:
                        page_data = self._crawl_page(next_url, current_depth)
                        if page_data:
                            results['pages_crawled'].append(page_data)
                            results['navigation_map'][next_url] = page_data
                            visited_urls.add(next_url)
                            
                            # Analisar formulários na página
                            page_forms = self._analyze_forms(next_url)
                            results['forms_found'].extend(page_forms)
                            
                            # Extrair novos links
                            if current_depth < max_depth:
                                new_links = self._extract_links(next_url)
                                next_urls.update(new_links - visited_urls)
                    
                    except Exception as e:
                        results['errors'].append({
                            'url': next_url,
                            'error': str(e),
                            'depth': current_depth
                        })
                
                urls_to_visit = next_urls
                current_depth += 1
            
            # 5. Análise de APIs descobertas
            if self.config.get('extract_apis', True):
                results['apis_discovered'] = self._extract_api_endpoints(results['pages_crawled'])
            
            # 6. Análise de cookies
            if self.config.get('analyze_cookies', True):
                results['cookies_analysis'] = self._analyze_cookies()
            
            # 7. Verificação de headers de segurança
            if self.config.get('check_security_headers', True):
                results['security_headers'] = self._check_security_headers(url)
            
            # 8. Detecção de frameworks
            if self.config.get('detect_frameworks', True):
                results['frameworks_detected'] = self._detect_frameworks(results['pages_crawled'])
            
            # 9. Extrair parâmetros únicos descobertos
            results['parameters_discovered'] = self._extract_parameters(results['pages_crawled'])
            
            # 10. Converter sets para listas (JSON serializable)
            results['endpoints_discovered'] = list(results['endpoints_discovered'])
            
            # Estatísticas finais
            results['statistics'] = {
                'total_pages': len(results['pages_crawled']),
                'total_forms': len(results['forms_found']),
                'total_parameters': len(results['parameters_discovered']),
                'total_endpoints': len(results['endpoints_discovered']),
                'login_attempts': len(results['login_attempts']),
                'frameworks_detected': len(results['frameworks_detected']),
                'max_depth_reached': current_depth - 1,
                'errors_encountered': len(results['errors'])
            }
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    'web_crawling': results,
                    'technologies': results['frameworks_detected'],
                    'forms': results['forms_found'],
                    'endpoints': results['endpoints_discovered']
                }
            )
            
        except Exception as e:
            error_msg = str(e)
            
            # Tirar screenshot em caso de erro se configurado
            if self.config.get('screenshot_on_error', True) and self.driver:
                try:
                    screenshot = self._take_screenshot()
                    error_msg += f" (Screenshot saved: {screenshot})"
                except:
                    pass
            
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error=error_msg
            )
        
        finally:
            self._cleanup_driver()
    
    def validate_target(self, target: str) -> bool:
        """Valida se é uma URL válida"""
        try:
            result = urlparse(target)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _normalize_url(self, target: str) -> str:
        """Normaliza URL adicionando esquema se necessário"""
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        return target
    
    def _setup_driver(self):
        """Configura o WebDriver Chrome"""
        try:
            chrome_options = Options()
            
            if self.config.get('headless', True):
                chrome_options.add_argument('--headless')
            
            # Configurações básicas
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-images')  # Faster loading
            
            # User Agent
            user_agent = self.config.get('user_agent')
            if user_agent:
                chrome_options.add_argument(f'--user-agent={user_agent}')
            
            # Tamanho da janela
            window_size = self.config.get('window_size', (1920, 1080))
            chrome_options.add_argument(f'--window-size={window_size[0]},{window_size[1]}')
            
            # Configurar service
            service = Service(ChromeDriverManager().install())
            
            # Criar driver
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Configurar timeouts
            self.driver.set_page_load_timeout(self.config.get('page_load_timeout', 60))
            self.driver.implicitly_wait(self.config.get('implicit_wait', 10))
            
        except Exception as e:
            raise Exception(f"Falha ao configurar WebDriver: {e}")
    
    def _cleanup_driver(self):
        """Limpa o WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None
    
    def _crawl_page(self, url: str, depth: int) -> Optional[Dict[str, Any]]:
        """Navega para uma página e extrai informações"""
        try:
            # Navegar para a página
            self.driver.get(url)
            
            # Aguardar carregamento
            WebDriverWait(self.driver, self.config.get('timeout', 30)).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            
            # Extrair informações da página
            page_data = {
                'url': url,
                'title': self.driver.title,
                'depth': depth,
                'timestamp': time.time(),
                'status_code': None,  # Selenium não fornece status code diretamente
                'content_length': len(self.driver.page_source),
                'forms': [],
                'links': [],
                'inputs': [],
                'javascript_errors': [],
                'technologies': [],
                'cookies': [],
                'local_storage': {},
                'session_storage': {}
            }
            
            # Executar JavaScript para obter mais informações
            try:
                # Verificar erros JavaScript
                js_errors = self.driver.get_log('browser')
                page_data['javascript_errors'] = [
                    {'level': error['level'], 'message': error['message']} 
                    for error in js_errors if error['level'] in ['SEVERE', 'WARNING']
                ]
            except:
                pass
            
            # Extrair localStorage e sessionStorage
            try:
                page_data['local_storage'] = self.driver.execute_script(
                    "return Object.assign({}, localStorage);"
                )
                page_data['session_storage'] = self.driver.execute_script(
                    "return Object.assign({}, sessionStorage);"
                )
            except:
                pass
            
            # Extrair links
            try:
                links = self.driver.find_elements(By.TAG_NAME, "a")
                for link in links:
                    href = link.get_attribute("href")
                    if href and self._is_valid_link(href, url):
                        page_data['links'].append({
                            'href': href,
                            'text': link.text.strip()[:100],  # Limitar texto
                            'title': link.get_attribute("title")
                        })
            except:
                pass
            
            # Extrair todos os inputs
            try:
                inputs = self.driver.find_elements(By.TAG_NAME, "input")
                for input_elem in inputs:
                    input_data = {
                        'type': input_elem.get_attribute("type"),
                        'name': input_elem.get_attribute("name"),
                        'id': input_elem.get_attribute("id"),
                        'value': input_elem.get_attribute("value"),
                        'placeholder': input_elem.get_attribute("placeholder"),
                        'required': input_elem.get_attribute("required") is not None,
                        'class': input_elem.get_attribute("class")
                    }
                    page_data['inputs'].append(input_data)
            except:
                pass
            
            # Extrair cookies da página atual
            try:
                cookies = self.driver.get_cookies()
                page_data['cookies'] = cookies
            except:
                pass
            
            return page_data
            
        except TimeoutException:
            return None
        except Exception as e:
            return None
    
    def _is_valid_link(self, href: str, base_url: str) -> bool:
        """Verifica se um link é válido para crawling"""
        if not href:
            return False
        
        # Pular links javascript, mailto, tel, etc.
        if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
            return False
        
        # Pular arquivos não HTML
        excluded_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz']
        if any(href.lower().endswith(ext) for ext in excluded_extensions):
            return False
        
        # Verificar se é do mesmo domínio
        parsed_base = urlparse(base_url)
        parsed_href = urlparse(href)
        
        # Link relativo ou mesmo domínio
        return not parsed_href.netloc or parsed_href.netloc == parsed_base.netloc
    
    def _extract_links(self, url: str) -> Set[str]:
        """Extrai todos os links válidos de uma página"""
        try:
            self.driver.get(url)
            links = set()
            
            link_elements = self.driver.find_elements(By.TAG_NAME, "a")
            for link in link_elements:
                href = link.get_attribute("href")
                if href and self._is_valid_link(href, url):
                    # Converter para URL absoluta
                    absolute_url = urljoin(url, href)
                    links.add(absolute_url)
            
            return links
            
        except Exception:
            return set()
    
    def _analyze_forms(self, url: str) -> List[Dict[str, Any]]:
        """Analisa todos os formulários de uma página"""
        try:
            self.driver.get(url)
            forms_data = []
            
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            
            for i, form in enumerate(forms):
                form_data = {
                    'url': url,
                    'form_index': i,
                    'action': form.get_attribute("action") or url,
                    'method': form.get_attribute("method") or "get",
                    'enctype': form.get_attribute("enctype"),
                    'inputs': [],
                    'is_login_form': False,
                    'csrf_tokens': []
                }
                
                # Analisar inputs do formulário
                inputs = form.find_elements(By.TAG_NAME, "input")
                textareas = form.find_elements(By.TAG_NAME, "textarea")
                selects = form.find_elements(By.TAG_NAME, "select")
                
                all_fields = inputs + textareas + selects
                
                for field in all_fields:
                    field_data = {
                        'tag': field.tag_name,
                        'type': field.get_attribute("type"),
                        'name': field.get_attribute("name"),
                        'id': field.get_attribute("id"),
                        'value': field.get_attribute("value"),
                        'placeholder': field.get_attribute("placeholder"),
                        'required': field.get_attribute("required") is not None,
                        'class': field.get_attribute("class"),
                        'maxlength': field.get_attribute("maxlength"),
                        'pattern': field.get_attribute("pattern")
                    }
                    
                    # Detectar tokens CSRF
                    if (field.get_attribute("name") and 
                        any(token in field.get_attribute("name").lower() 
                            for token in ['csrf', 'token', '_token', 'authenticity_token'])):
                        form_data['csrf_tokens'].append(field_data)
                    
                    form_data['inputs'].append(field_data)
                
                # Detectar se é formulário de login
                form_data['is_login_form'] = self._is_login_form(form_data)
                
                forms_data.append(form_data)
            
            return forms_data
            
        except Exception as e:
            return []
    
    def _is_login_form(self, form_data: Dict[str, Any]) -> bool:
        """Determina se um formulário é de login"""
        has_password = False
        has_username = False
        
        for input_field in form_data['inputs']:
            field_type = input_field.get('type', '').lower()
            field_name = (input_field.get('name') or '').lower()
            field_id = (input_field.get('id') or '').lower()
            
            # Verificar campo de senha
            if field_type == 'password':
                has_password = True
            
            # Verificar campo de usuário/email
            if (field_type in ['text', 'email'] and 
                any(term in field_name + field_id 
                    for term in ['user', 'login', 'email', 'username'])):
                has_username = True
        
        return has_password and has_username
    
    def _attempt_login(self, url: str, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Tenta fazer login com credenciais comuns"""
        login_attempts = []
        
        if not self.config.get('common_credentials', True):
            return login_attempts
        
        for form in forms:
            if not form['is_login_form']:
                continue
            
            # Encontrar campos de usuário e senha
            username_field = None
            password_field = None
            
            for input_field in form['inputs']:
                field_type = input_field.get('type', '').lower()
                field_name = (input_field.get('name') or '').lower()
                
                if field_type == 'password' and not password_field:
                    password_field = input_field
                elif (field_type in ['text', 'email'] and 
                      any(term in field_name for term in ['user', 'login', 'email']) and 
                      not username_field):
                    username_field = input_field
            
            if not (username_field and password_field):
                continue
            
            # Tentar credenciais comuns
            for username, password in self.common_credentials[:5]:  # Limitar tentativas
                try:
                    attempt = self._try_login(url, form, username_field, password_field, username, password)
                    login_attempts.append(attempt)
                    
                    # Se login for bem-sucedido, parar tentativas
                    if attempt.get('success', False):
                        break
                        
                except Exception as e:
                    login_attempts.append({
                        'url': url,
                        'form_index': form['form_index'],
                        'username': username,
                        'success': False,
                        'error': str(e)
                    })
        
        return login_attempts
    
    def _try_login(self, url: str, form: Dict[str, Any], username_field: Dict[str, Any], 
                   password_field: Dict[str, Any], username: str, password: str) -> Dict[str, Any]:
        """Tenta fazer login com credenciais específicas"""
        try:
            # Navegar para a página
            self.driver.get(url)
            
            # Encontrar elementos do formulário
            username_elem = None
            password_elem = None
            
            # Tentar diferentes seletores
            for selector_type in ['name', 'id']:
                if not username_elem and username_field.get(selector_type):
                    try:
                        username_elem = self.driver.find_element(
                            By.CSS_SELECTOR, f'[{selector_type}="{username_field[selector_type]}"]'
                        )
                    except:
                        pass
                
                if not password_elem and password_field.get(selector_type):
                    try:
                        password_elem = self.driver.find_element(
                            By.CSS_SELECTOR, f'[{selector_type}="{password_field[selector_type]}"]'
                        )
                    except:
                        pass
            
            if not (username_elem and password_elem):
                return {
                    'url': url,
                    'form_index': form['form_index'],
                    'username': username,
                    'success': False,
                    'error': 'Não foi possível encontrar campos de login'
                }
            
            # Limpar campos e inserir credenciais
            username_elem.clear()
            username_elem.send_keys(username)
            
            password_elem.clear()
            password_elem.send_keys(password)
            
            # Submeter formulário
            password_elem.send_keys(Keys.RETURN)
            
            # Aguardar resposta
            time.sleep(3)
            
            # Verificar se login foi bem-sucedido
            current_url = self.driver.current_url
            page_source = self.driver.page_source.lower()
            
            # Indicadores de sucesso
            success_indicators = ['dashboard', 'welcome', 'logout', 'profile', 'settings']
            failure_indicators = ['error', 'invalid', 'incorrect', 'failed', 'wrong']
            
            has_success = any(indicator in page_source for indicator in success_indicators)
            has_failure = any(indicator in page_source for indicator in failure_indicators)
            url_changed = current_url != url
            
            success = (has_success or url_changed) and not has_failure
            
            return {
                'url': url,
                'form_index': form['form_index'],
                'username': username,
                'password': password,
                'success': success,
                'final_url': current_url,
                'url_changed': url_changed,
                'response_indicators': {
                    'success_found': has_success,
                    'failure_found': has_failure
                }
            }
            
        except Exception as e:
            return {
                'url': url,
                'form_index': form['form_index'],
                'username': username,
                'success': False,
                'error': str(e)
            }
    
    def _extract_api_endpoints(self, pages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extrai endpoints de API das páginas analisadas"""
        api_endpoints = []
        api_patterns = [
            r'/api/[^"\s<>]+',
            r'/rest/[^"\s<>]+',
            r'/graphql[^"\s<>]*',
            r'/v\d+/[^"\s<>]+',
            r'\.json[^"\s<>]*',
            r'\.xml[^"\s<>]*'
        ]
        
        for page in pages:
            try:
                self.driver.get(page['url'])
                page_source = self.driver.page_source
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, page_source, re.IGNORECASE)
                    for match in matches:
                        absolute_url = urljoin(page['url'], match)
                        api_endpoints.append({
                            'endpoint': absolute_url,
                            'found_on': page['url'],
                            'pattern': pattern,
                            'method': 'unknown'
                        })
            except:
                continue
        
        # Remover duplicatas
        seen = set()
        unique_endpoints = []
        for endpoint in api_endpoints:
            if endpoint['endpoint'] not in seen:
                seen.add(endpoint['endpoint'])
                unique_endpoints.append(endpoint)
        
        return unique_endpoints
    
    def _analyze_cookies(self) -> Dict[str, Any]:
        """Analisa cookies da sessão atual"""
        try:
            cookies = self.driver.get_cookies()
            
            analysis = {
                'total_cookies': len(cookies),
                'session_cookies': 0,
                'persistent_cookies': 0,
                'secure_cookies': 0,
                'httponly_cookies': 0,
                'samesite_cookies': 0,
                'cookies_details': []
            }
            
            for cookie in cookies:
                # Classificar cookie
                if not cookie.get('expiry'):
                    analysis['session_cookies'] += 1
                else:
                    analysis['persistent_cookies'] += 1
                
                if cookie.get('secure'):
                    analysis['secure_cookies'] += 1
                
                if cookie.get('httpOnly'):
                    analysis['httponly_cookies'] += 1
                
                if cookie.get('sameSite'):
                    analysis['samesite_cookies'] += 1
                
                analysis['cookies_details'].append({
                    'name': cookie['name'],
                    'domain': cookie['domain'],
                    'path': cookie['path'],
                    'secure': cookie.get('secure', False),
                    'httpOnly': cookie.get('httpOnly', False),
                    'sameSite': cookie.get('sameSite'),
                    'has_expiry': 'expiry' in cookie
                })
            
            return analysis
            
        except Exception:
            return {}
    
    def _check_security_headers(self, url: str) -> Dict[str, Any]:
        """Verifica headers de segurança usando JavaScript"""
        try:
            self.driver.get(url)
            
            # Usar fetch API para obter headers
            headers_script = """
            return fetch(window.location.href, {method: 'HEAD'})
                .then(response => {
                    const headers = {};
                    for (let [key, value] of response.headers.entries()) {
                        headers[key] = value;
                    }
                    return headers;
                })
                .catch(() => ({}));
            """
            
            headers = self.driver.execute_async_script(f"""
                const callback = arguments[0];
                {headers_script}.then(callback);
            """)
            
            security_headers = {
                'X-Frame-Options': headers.get('x-frame-options'),
                'X-Content-Type-Options': headers.get('x-content-type-options'),
                'X-XSS-Protection': headers.get('x-xss-protection'),
                'Strict-Transport-Security': headers.get('strict-transport-security'),
                'Content-Security-Policy': headers.get('content-security-policy'),
                'Referrer-Policy': headers.get('referrer-policy'),
                'Feature-Policy': headers.get('feature-policy'),
                'Permissions-Policy': headers.get('permissions-policy')
            }
            
            return {
                'headers_found': {k: v for k, v in security_headers.items() if v},
                'missing_headers': [k for k, v in security_headers.items() if not v],
                'security_score': len([v for v in security_headers.values() if v]) / len(security_headers)
            }
            
        except Exception:
            return {}
    
    def _detect_frameworks(self, pages: List[Dict[str, Any]]) -> List[str]:
        """Detecta frameworks e tecnologias nas páginas"""
        detected = set()
        
        for page in pages:
            try:
                self.driver.get(page['url'])
                page_source = self.driver.page_source.lower()
                
                # Verificar assinaturas de frameworks
                for framework, signatures in self.framework_signatures.items():
                    if any(sig.lower() in page_source for sig in signatures):
                        detected.add(framework)
                
                # Verificar JavaScript global objects
                js_globals = self.driver.execute_script("""
                    const globals = [];
                    if (typeof jQuery !== 'undefined') globals.push('jQuery');
                    if (typeof $ !== 'undefined' && $.fn) globals.push('jQuery');
                    if (typeof React !== 'undefined') globals.push('React');
                    if (typeof Vue !== 'undefined') globals.push('Vue.js');
                    if (typeof angular !== 'undefined') globals.push('Angular');
                    return globals;
                """)
                
                detected.update(js_globals)
                
            except Exception:
                continue
        
        return list(detected)
    
    def _extract_parameters(self, pages: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Extrai parâmetros únicos descobertos nas páginas"""
        parameters = {
            'get_params': set(),
            'form_params': set(),
            'json_keys': set(),
            'cookie_names': set()
        }
        
        for page in pages:
            # Parâmetros GET da URL
            parsed_url = urlparse(page['url'])
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                parameters['get_params'].update(query_params.keys())
            
            # Parâmetros de formulários
            for form in page.get('forms', []):
                for input_field in form.get('inputs', []):
                    if input_field.get('name'):
                        parameters['form_params'].add(input_field['name'])
            
            # Cookies
            for cookie in page.get('cookies', []):
                parameters['cookie_names'].add(cookie['name'])
        
        # Converter sets para listas
        return {k: list(v) for k, v in parameters.items()}
    
    def _take_screenshot(self) -> str:
        """Tira screenshot da página atual"""
        try:
            timestamp = int(time.time())
            screenshot_dir = Path("data/screenshots")
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            
            screenshot_path = screenshot_dir / f"error_{timestamp}.png"
            self.driver.save_screenshot(str(screenshot_path))
            
            return str(screenshot_path)
        except Exception:
            return None
    
    def get_info(self) -> Dict[str, Any]:
        """Informações detalhadas sobre o plugin"""
        info = super().get_info()
        info['dependencies'] = {'selenium': SELENIUM_AVAILABLE}
        info['features'] = [
            'Navegação web automatizada com Selenium',
            'Análise completa de formulários',
            'Tentativas de login automático',
            'Mapeamento de aplicações web',
            'Extração de parâmetros e endpoints',
            'Detecção de frameworks/tecnologias',
            'Análise de cookies e segurança',
            'Screenshots automáticos em erros',
            'Suporte a JavaScript',
            'Crawling em profundidade'
        ]
        return info
