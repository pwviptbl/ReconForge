#!/usr/bin/env python3
"""
Módulo de Scraping Web Auxiliar
Realiza scraping de páginas web com suporte a autenticação para descoberta de:
- URLs e estrutura do site
- Formulários e campos de entrada
- Endpoints de API
- Tecnologias utilizadas

Nota: Este módulo é auxiliar e não realiza testes de vulnerabilidades.
Para testes de segurança, use scanner_web_avancado.py
"""

import requests
import urllib.parse
import re
import time
import json
import base64
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import obter_logger


class VarreduraScraperAuth:
    """Módulo de scraping web com autenticação e descoberta avançada"""

    def __init__(self):
        self.logger = obter_logger("ScraperAuth")
        self.session = requests.Session()

        # Configurações
        self.timeout = 10
        self.max_pages = 200
        self.max_depth = 4
        self.max_workers = 8

        # Resultados
        self.urls_descobertas = set()
        self.formularios = []
        self.endpoints_api = []
        self.parametros_encontrados = set()
        self.tecnologias = {}
        self.estrutura_site = {}

                # Configuração da sessão
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Cache-Control': 'max-age=0'
        })

        # Estado da autenticação
        self.autenticado = False
        self.tokens_auth = {}
        self.cookies_auth = {}

    def executar(self, alvo: str, credenciais: Optional[Dict] = None,
                tipo_scan: str = "completo") -> Dict[str, any]:
        """
        Executa scraping com autenticação

        Args:
            alvo: URL base ou domínio
            credenciais: Dict com 'usuario' e 'senha' para login
            tipo_scan: 'basico', 'autenticado', 'completo'

        Returns:
            Dict com resultados do scraping
        """
        self.logger.info(f"🕷️ Iniciando scraping para: {alvo}")

        inicio = time.time()

        try:
            # Normalizar URL
            url_base = self._normalizar_url(alvo)

            # Inicializar resultados
            self._reset_resultados()

            # Fase 1: Spider básico (sempre executado)
            self.logger.info("🔍 Fase 1: Spider básico...")
            self._spider_basico(url_base)

            # Fase 2: Detecção de tecnologias
            self.logger.info("🔧 Fase 2: Detectando tecnologias...")
            self._detectar_tecnologias(url_base)

            # Fase 3: Análise de formulários
            self.logger.info("📝 Fase 3: Analisando formulários...")
            self._analisar_formularios()

            # Fase 4: Descoberta de APIs
            self.logger.info("🔗 Fase 4: Descobrindo APIs...")
            self._descobrir_apis()

            # Fase 5: Autenticação (se credenciais fornecidas)
            if credenciais and tipo_scan in ['autenticado', 'completo']:
                self.logger.info(f"🔐 Fase 5: Tentando autenticação...")
                self.logger.info(f"   Credenciais: {bool(credenciais)}")
                self.logger.info(f"   Tipo scan: {tipo_scan}")
                sucesso_auth = self._tentar_autenticacao(url_base, credenciais)

                if sucesso_auth:
                    self.logger.info("✅ Autenticação bem-sucedida!")
                    # Spider autenticado
                    self.logger.info("🔍 Fase 6: Spider autenticado...")
                    self._spider_autenticado(url_base)
                else:
                    self.logger.warning("❌ Falha na autenticação")
            else:
                self.logger.info(f"🔐 Autenticação pulada - Credenciais: {bool(credenciais)}, Tipo: {tipo_scan}")

            # Fase 6: Análise final
            self.logger.info("📊 Fase 7: Análise final...")
            analise_final = self._analise_final()

            duracao = time.time() - inicio

            resultado = {
                'url_base': url_base,
                'tipo_scan': tipo_scan,
                'timestamp': datetime.now().isoformat(),
                'duracao_segundos': round(duracao, 2),
                'autenticacao': credenciais is not None,
                'urls_descobertas': list(self.urls_descobertas),
                'total_urls': len(self.urls_descobertas),
                'formularios': self.formularios,
                'total_formularios': len(self.formularios),
                'endpoints_api': self.endpoints_api,
                'total_apis': len(self.endpoints_api),
                'parametros_encontrados': list(self.parametros_encontrados),
                'total_parametros': len(self.parametros_encontrados),
                'tecnologias': self.tecnologias,
                'estrutura_site': self.estrutura_site,
                'vulnerabilidades': self.vulnerabilidades,
                'total_endpoints': len(self.endpoints_api),
                'analise_final': analise_final
            }

            self.logger.info(f"✅ Scraping concluído: {len(self.urls_descobertas)} URLs encontradas")
            return resultado

        except Exception as e:
            self.logger.error(f"❌ Erro no scraping: {e}")
            return {'erro': str(e), 'url_base': alvo}

    def _normalizar_url(self, alvo: str) -> str:
        """Normaliza URL para formato padrão"""
        if not alvo.startswith(('http://', 'https://')):
            alvo = f"https://{alvo}"

        # Remover barra final se existir
        return alvo.rstrip('/')

    def _reset_resultados(self):
        """Reseta resultados para nova execução"""
        self.urls_descobertas = set()
        self.formularios = []
        self.endpoints_api = []
        self.parametros_encontrados = set()
        self.tecnologias = {}
        self.estrutura_site = {}

    def _spider_basico(self, url_base: str):
        """Spider básico sem autenticação"""
        urls_para_visitar = {url_base}
        urls_visitadas = set()
        depth = 0

        while urls_para_visitar and depth < self.max_depth and len(self.urls_descobertas) < self.max_pages:
            proximas_urls = set()

            for url in list(urls_para_visitar):
                if url in urls_visitadas:
                    continue

                try:
                    resp = self.session.get(url, timeout=self.timeout, verify=False,
                                          allow_redirects=True)

                    if resp.status_code == 200:
                        urls_visitadas.add(url)
                        self.urls_descobertas.add(url)

                        # Extrair links
                        links = self._extrair_links(resp.text, url)
                        for link in links:
                            if self._is_same_domain(link, url_base) and link not in urls_visitadas:
                                proximas_urls.add(link)

                        # Extrair formulários
                        forms = self._extrair_formularios(resp.text, url)
                        self.formularios.extend(forms)

                        # Extrair parâmetros de URLs
                        self._extrair_parametros_url(url)

                except Exception as e:
                    self.logger.debug(f"Erro ao visitar {url}: {e}")

            urls_para_visitar = proximas_urls - urls_visitadas
            depth += 1

    def _extrair_links(self, html: str, base_url: str) -> Set[str]:
        """Extrai links do HTML"""
        links = set()

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Links de âncoras
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = urllib.parse.urljoin(base_url, href)
                if self._is_valid_url(full_url):
                    links.add(full_url)

            # Links de formulários
            for form in soup.find_all('form', action=True):
                action = form['action']
                full_url = urllib.parse.urljoin(base_url, action)
                if self._is_valid_url(full_url):
                    links.add(full_url)

            # Scripts externos
            for script in soup.find_all('script', src=True):
                src = script['src']
                if not src.startswith(('http://', 'https://', '//')):
                    continue
                full_url = urllib.parse.urljoin(base_url, src)
                if self._is_valid_url(full_url):
                    links.add(full_url)

            # CSS externos
            for link in soup.find_all('link', href=True):
                if link.get('rel', [''])[0] == 'stylesheet':
                    href = link['href']
                    full_url = urllib.parse.urljoin(base_url, href)
                    if self._is_valid_url(full_url):
                        links.add(full_url)

        except Exception as e:
            self.logger.debug(f"Erro ao extrair links: {e}")

        return links

    def _extrair_formularios(self, html: str, url: str) -> List[Dict]:
        """Extrai formulários do HTML"""
        formularios = []

        try:
            soup = BeautifulSoup(html, 'html.parser')

            for form in soup.find_all('form'):
                form_data = {
                    'url': url,
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }

                # Extrair inputs
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'required': input_tag.has_attr('required')
                    }
                    form_data['inputs'].append(input_info)

                if form_data['inputs']:
                    formularios.append(form_data)

        except Exception as e:
            self.logger.debug(f"Erro ao extrair formulários: {e}")

        return formularios

    def _extrair_parametros_url(self, url: str):
        """Extrai parâmetros de URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                for param in params.keys():
                    self.parametros_encontrados.add(param)
        except Exception as e:
            self.logger.debug(f"Erro ao extrair parâmetros: {e}")

    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Verifica se URLs são do mesmo domínio"""
        try:
            parsed1 = urllib.parse.urlparse(url1)
            parsed2 = urllib.parse.urlparse(url2)
            return parsed1.netloc == parsed2.netloc
        except:
            return False

    def _is_valid_url(self, url: str) -> bool:
        """Verifica se URL é válida e não é externa"""
        try:
            parsed = urllib.parse.urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False

    def _detectar_tecnologias(self, url_base: str):
        """Detecta tecnologias usadas no site"""
        try:
            resp = self.session.get(url_base, timeout=self.timeout, verify=False)

            # Detectar por headers
            server = resp.headers.get('Server', '')
            if server:
                if 'apache' in server.lower():
                    self.tecnologias['web_server'] = 'Apache'
                elif 'nginx' in server.lower():
                    self.tecnologias['web_server'] = 'Nginx'
                elif 'iis' in server.lower():
                    self.tecnologias['web_server'] = 'IIS'

            # Detectar por conteúdo
            content = resp.text.lower()

            # CMS
            if 'wordpress' in content:
                self.tecnologias['cms'] = 'WordPress'
            elif 'joomla' in content:
                self.tecnologias['cms'] = 'Joomla'
            elif 'drupal' in content:
                self.tecnologias['cms'] = 'Drupal'

            # Frameworks
            if 'laravel' in content:
                self.tecnologias['framework'] = 'Laravel'
            elif 'django' in content:
                self.tecnologias['framework'] = 'Django'
            elif 'react' in content:
                self.tecnologias['frontend'] = 'React'
            elif 'vue' in content:
                self.tecnologias['frontend'] = 'Vue.js'

            # Linguagens
            if '.php' in url_base or 'php' in content:
                self.tecnologias['language'] = 'PHP'
            elif '.jsp' in url_base:
                self.tecnologias['language'] = 'Java'
            elif '.asp' in url_base:
                self.tecnologias['language'] = 'ASP.NET'

        except Exception as e:
            self.logger.debug(f"Erro ao detectar tecnologias: {e}")

    def _analisar_formularios(self):
        """Analisa formulários encontrados"""
        for form in self.formularios:
            # Verificar se é formulário de login
            is_login = any(
                input_field['name'].lower() in ['password', 'pass', 'pwd', 'senha', 'login']
                for input_field in form['inputs']
            )

            if is_login:
                form['tipo'] = 'login'
                # Verificar proteções
                self._verificar_protecoes_login(form)
            else:
                form['tipo'] = 'generico'
                # Verificar outras vulnerabilidades
                self._verificar_protecoes_geral(form)

    def _verificar_protecoes_login(self, form: Dict):
        """Verifica proteções em formulário de login"""
        # Verificar HTTPS
        if not form['url'].startswith('https://'):
            self._adicionar_vulnerabilidade(
                'Login sem HTTPS',
                f'Formulário de login em {form["url"]} não usa HTTPS',
                'ALTA',
                form['url']
            )

        # Verificar CSRF token
        has_csrf = any(
            input_field['name'].lower() in ['csrf', 'token', '_token', 'authenticity_token']
            for input_field in form['inputs']
        )

        if not has_csrf:
            self._adicionar_vulnerabilidade(
                'Login sem proteção CSRF',
                f'Formulário de login em {form["url"]} não possui token CSRF',
                'MÉDIA',
                form['url']
            )

    def _verificar_protecoes_geral(self, form: Dict):
        """Verifica proteções gerais em formulários"""
        # Verificar campos sem validação aparente
        for input_field in form['inputs']:
            if input_field['type'] in ['text', 'email', 'url'] and not input_field['required']:
                # Campo opcional - verificar se pode ser usado para injeção
                pass

    def _descobrir_apis(self):
        """Descobre endpoints de API"""
        for url in self.urls_descobertas:
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False)

                # Procurar por endpoints em JavaScript
                js_endpoints = self._extrair_endpoints_js(resp.text, url)
                self.endpoints_api.extend(js_endpoints)

                # Procurar por padrões de API comuns
                api_patterns = [
                    r'/api/v\d+/[^\'"\s]+',
                    r'/rest/[^\'"\s]+',
                    r'/graphql',
                    r'/swagger',
                    r'/docs/api'
                ]

                for pattern in api_patterns:
                    matches = re.findall(pattern, resp.text)
                    for match in matches:
                        full_url = urllib.parse.urljoin(url, match)
                        if full_url not in [api['url'] for api in self.endpoints_api]:
                            self.endpoints_api.append({
                                'url': full_url,
                                'tipo': 'descoberto',
                                'fonte': url
                            })

            except Exception as e:
                self.logger.debug(f"Erro ao analisar {url}: {e}")

    def _extrair_endpoints_js(self, html: str, base_url: str) -> List[Dict]:
        """Extrai endpoints de API de código JavaScript"""
        endpoints = []

        try:
            # Padrões comuns de endpoints em JS
            patterns = [
                r'["\'](/api/[^"\']+)["\']',
                r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
                r'\$\.(get|post|ajax)\(["\']([^"\']+)["\']'
            ]

            for pattern in patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        endpoint = match[1] if len(match) > 1 else match[0]
                    else:
                        endpoint = match

                    if endpoint.startswith('/'):
                        full_url = urllib.parse.urljoin(base_url, endpoint)
                    elif endpoint.startswith(('http://', 'https://')):
                        full_url = endpoint
                    else:
                        continue

                    if full_url not in [api['url'] for api in endpoints]:
                        endpoints.append({
                            'url': full_url,
                            'tipo': 'javascript',
                            'fonte': base_url
                        })

        except Exception as e:
            self.logger.debug(f"Erro ao extrair endpoints JS: {e}")

        return endpoints

    def _tentar_autenticacao(self, url_base: str, credenciais: Dict) -> bool:
        """Tenta fazer login no site com captura avançada de tokens"""
        try:
            # Procurar formulário de login
            login_form = None
            for form in self.formularios:
                if form.get('tipo') == 'login':
                    login_form = form
                    break

            if not login_form:
                self.logger.warning("Nenhum formulário de login encontrado")
                return False

            self.logger.info(f"📝 Formulário de login encontrado: {login_form['url']}")
            self.logger.info(f"   Action: {login_form['action']}")
            self.logger.info(f"   Method: {login_form['method']}")

            # Preparar dados do login
            login_data = {}
            for input_field in login_form['inputs']:
                name = input_field['name'].lower()
                if name in ['username', 'user', 'login', 'email']:
                    login_data[input_field['name']] = credenciais.get('usuario', '')
                    self.logger.info(f"   Campo usuário: {input_field['name']} = {credenciais.get('usuario', '')}")
                elif name in ['password', 'pass', 'pwd', 'senha']:
                    login_data[input_field['name']] = credenciais.get('senha', '')
                    self.logger.info(f"   Campo senha: {input_field['name']} = {'*' * len(credenciais.get('senha', ''))}")
                elif name in ['captcha', 'ct_captcha'] and input_field.get('value'):
                    # Manter valor padrão do captcha se existir
                    login_data[input_field['name']] = input_field['value']
                    self.logger.info(f"   Campo captcha: {input_field['name']} = {input_field['value']}")
                elif input_field.get('value') and input_field['type'] != 'password':
                    # Incluir outros campos com valores padrão
                    login_data[input_field['name']] = input_field['value']
                    self.logger.info(f"   Campo adicional: {input_field['name']} = {input_field['value']}")

            self.logger.info(f"📝 Tentando login com usuário: {credenciais.get('usuario', 'N/A')}")
            self.logger.info(f"   Dados do login: {list(login_data.keys())}")

            # Fazer login
            action_url = urllib.parse.urljoin(login_form['url'], login_form['action'])
            self.logger.info(f"   URL do login: {action_url}")

            resp = self.session.post(
                action_url,
                data=login_data,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )

            self.logger.info(f"   Status da resposta: {resp.status_code}")
            self.logger.info(f"   URL final: {resp.url}")
            self.logger.info(f"   Histórico de redirecionamentos: {len(resp.history)}")

            # Capturar tokens e cookies de autenticação
            self._capturar_tokens_autenticacao(resp)

            # Verificar se login foi bem-sucedido
            sucesso = self._verificar_sucesso_login(resp, login_form['url'])

            if sucesso:
                self.autenticado = True
                self.logger.info("✅ Login bem-sucedido!")
                self._log_tokens_capturados()
                return True
            else:
                self.logger.warning("❌ Falha no login")
                # Log detalhado do porquê falhou
                self._debug_falha_login(resp, login_form['url'])
                return False

        except Exception as e:
            self.logger.error(f"Erro na autenticação: {e}")
            return False

    def _capturar_tokens_autenticacao(self, response: requests.Response):
        """Captura tokens de autenticação da resposta"""
        try:
            # Capturar Authorization header
            auth_header = response.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                self.tokens_auth['bearer'] = auth_header.replace('Bearer ', '')
                self.session.headers.update({'Authorization': auth_header})

            # Capturar cookies de sessão
            for cookie in self.session.cookies:
                if any(keyword in cookie.name.lower() for keyword in ['session', 'auth', 'token', 'jwt']):
                    self.cookies_auth[cookie.name] = cookie.value

            # Procurar tokens JWT no conteúdo da resposta
            if response.text:
                # Padrões de JWT
                jwt_patterns = [
                    r'["\']token["\']\s*:\s*["\']([A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*)["\']',
                    r'["\']jwt["\']\s*:\s*["\']([A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*)["\']',
                    r'["\']access_token["\']\s*:\s*["\']([A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*)["\']'
                ]

                for pattern in jwt_patterns:
                    matches = re.findall(pattern, response.text)
                    for match in matches:
                        if self._validar_jwt(match):
                            self.tokens_auth['jwt'] = match
                            self.session.headers.update({
                                'Authorization': f'Bearer {match}'
                            })
                            break

            # Procurar tokens em localStorage/sessionStorage simulado
            storage_patterns = [
                r'localStorage\.setItem\(["\']([^"\']+)["\'],\s*["\']([^"\']+)["\']',
                r'sessionStorage\.setItem\(["\']([^"\']+)["\'],\s*["\']([^"\']+)["\']'
            ]

            for pattern in storage_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for key, value in matches:
                    if 'token' in key.lower():
                        self.tokens_auth[f'storage_{key}'] = value

        except Exception as e:
            self.logger.debug(f"Erro ao capturar tokens: {e}")

    def _validar_jwt(self, token: str) -> bool:
        """Valida se é um token JWT válido"""
        try:
            parts = token.split('.')
            return len(parts) == 3 and all(parts)
        except:
            return False

    def _verificar_sucesso_login(self, response: requests.Response, login_url: str) -> bool:
        """Verifica se o login foi bem-sucedido"""
        try:
            # Verificar código de status
            if response.status_code not in [200, 302, 301]:
                return False

            # Verificar se não voltou para página de login
            current_url = response.url.lower()
            if any(keyword in current_url for keyword in ['login', 'auth', 'signin']):
                return False

            # Verificar presença de elementos de dashboard/menu
            content = response.text.lower()
            dashboard_indicators = [
                'dashboard', 'menu', 'logout', 'sair', 'perfil', 'profile',
                'admin', 'painel', 'sistema', 'home', 'inicio'
            ]

            if any(indicator in content for indicator in dashboard_indicators):
                return True

            # Verificar se tem cookies de sessão
            session_cookies = [c for c in self.session.cookies if 'session' in c.name.lower()]
            if session_cookies:
                return True

            # Verificar se tem tokens de auth
            if self.tokens_auth:
                return True

            # Verificar redirecionamento para área protegida
            if len(response.history) > 0:
                final_url = response.url
                if final_url != login_url and 'login' not in final_url.lower():
                    return True

            return False

        except Exception as e:
            self.logger.debug(f"Erro ao verificar sucesso do login: {e}")
            return False

    def _log_tokens_capturados(self):
        """Log dos tokens capturados para debug"""
        if self.tokens_auth:
            self.logger.info("🔑 Tokens de autenticação capturados:")
            for tipo, token in self.tokens_auth.items():
                if 'bearer' in tipo.lower() or 'jwt' in tipo.lower():
                    # Máscara o token para log
                    masked = token[:10] + "..." + token[-5:] if len(token) > 15 else token
                    self.logger.info(f"   {tipo}: {masked}")
                else:
                    self.logger.info(f"   {tipo}: {token}")

        if self.cookies_auth:
            self.logger.info("🍪 Cookies de autenticação capturados:")
            for name, value in self.cookies_auth.items():
                masked_value = value[:5] + "..." if len(value) > 5 else value
                self.logger.info(f"   {name}: {masked_value}")

    def _spider_autenticado(self, url_base: str):
        """Spider avançado com sessão autenticada"""
        if not self.autenticado:
            self.logger.warning("Spider autenticado chamado sem autenticação")
            return

        self.logger.info("🔍 Iniciando spider autenticado...")

        # URLs para explorar após login
        urls_autenticadas = set()

        # Adicionar URLs comuns de sistemas web
        base_parsed = urllib.parse.urlparse(url_base)
        caminhos_comuns = [
            '/admin', '/dashboard', '/painel', '/sistema', '/home',
            '/usuario', '/profile', '/config', '/settings',
            '/api', '/rest', '/graphql', '/swagger',
            '/extension', '/desktop', '/menu', '/principal'
        ]

        for caminho in caminhos_comuns:
            url_teste = f"{base_parsed.scheme}://{base_parsed.netloc}{caminho}"
            urls_autenticadas.add(url_teste)

        # Adicionar URLs descobertas que parecem ser protegidas
        for url in self.urls_descobertas.copy():
            url_lower = url.lower()
            if any(keyword in url_lower for keyword in [
                'admin', 'dashboard', 'panel', 'user', 'profile',
                'config', 'settings', 'system', 'api', 'extension'
            ]):
                urls_autenticadas.add(url)

        # Explorar URLs autenticadas
        urls_visitadas = set()

        for url in urls_autenticadas:
            if url in urls_visitadas:
                continue

            try:
                self.logger.debug(f"🌐 Explorando: {url}")

                # Fazer requisição com headers de autenticação
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )

                urls_visitadas.add(url)

                if resp.status_code == 200:
                    # Verificar se realmente estamos autenticados
                    if self._verificar_autenticacao_ativa(resp):
                        self.urls_descobertas.add(url)

                        # Extrair novos links da página autenticada
                        novos_links = self._extrair_links(resp.text, url)
                        for link in novos_links:
                            if (self._is_same_domain(link, url_base) and
                                link not in self.urls_descobertas and
                                link not in urls_visitadas):
                                urls_autenticadas.add(link)

                        # Extrair novos formulários
                        novos_forms = self._extrair_formularios(resp.text, url)
                        for form in novos_forms:
                            if form not in self.formularios:
                                self.formularios.append(form)

                        # Procurar por APIs e endpoints
                        self._extrair_endpoints_pagina(resp.text, url)

                        # Capturar mais tokens se encontrados
                        self._capturar_tokens_autenticacao(resp)

                        self.logger.debug(f"✅ Explorado com sucesso: {url}")
                    else:
                        self.logger.debug(f"❌ Página não acessível (não autenticado): {url}")
                else:
                    self.logger.debug(f"❌ Status {resp.status_code}: {url}")

            except Exception as e:
                self.logger.debug(f"Erro ao explorar {url}: {e}")

        self.logger.info(f"🔍 Spider autenticado concluído: {len(urls_visitadas)} URLs exploradas")

    def _verificar_autenticacao_ativa(self, response: requests.Response) -> bool:
        """Verifica se a autenticação ainda está ativa"""
        try:
            content = response.text.lower()
            url = response.url.lower()

            # Verificar se foi redirecionado para login
            if any(keyword in url for keyword in ['login', 'auth', 'signin']):
                return False

            # Verificar presença de elementos de sistema autenticado
            auth_indicators = [
                'logout', 'sair', 'dashboard', 'menu', 'admin',
                'perfil', 'profile', 'config', 'settings',
                'sistema', 'painel', 'desktop', 'extension'
            ]

            if any(indicator in content for indicator in auth_indicators):
                return True

            # Verificar se tem cookies de sessão ativos
            session_cookies = [c for c in self.session.cookies if not c.is_expired()]
            if session_cookies:
                return True

            return False

        except Exception as e:
            self.logger.debug(f"Erro ao verificar autenticação: {e}")
            return False

    def _extrair_endpoints_pagina(self, html: str, base_url: str):
        """Extrai endpoints de API da página"""
        try:
            # Padrões de endpoints em HTML/JS
            endpoint_patterns = [
                r'["\']/api/[^"\']+["\']',
                r'["\']/rest/[^"\']+["\']',
                r'["\']/graphql[^"\']*["\']',
                r'["\']/extension/[^"\']+["\']',
                r'["\']/desktop/[^"\']+["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
                r'\$\.(get|post|ajax)\(["\']([^"\']+)["\']'
            ]

            for pattern in endpoint_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        endpoint = match[1] if len(match) > 1 else match[0]
                    else:
                        endpoint = match

                    if endpoint.startswith('/'):
                        full_url = urllib.parse.urljoin(base_url, endpoint)
                    elif endpoint.startswith(('http://', 'https://')):
                        full_url = endpoint
                    else:
                        continue

                    # Verificar se já existe
                    if not any(api['url'] == full_url for api in self.endpoints_api):
                        self.endpoints_api.append({
                            'url': full_url,
                            'tipo': 'descoberto_autenticado',
                            'fonte': base_url
                        })

        except Exception as e:
            self.logger.debug(f"Erro ao extrair endpoints: {e}")

    def _analise_final(self) -> Dict[str, any]:
        """Realiza análise final dos resultados"""
        analise = {
            'total_urls': len(self.urls_descobertas),
            'total_formularios': len(self.formularios),
            'total_apis': len(self.endpoints_api),
            'total_parametros': len(self.parametros_encontrados),
            'total_vulnerabilidades': len(self.vulnerabilidades),
            'autenticacao': {
                'status': self.autenticado,
                'tokens_capturados': len(self.tokens_auth),
                'cookies_autenticacao': len(self.cookies_auth),
                'tipos_token': list(self.tokens_auth.keys())
            },
            'por_criticidade': {},
            'tipos_formulario': {},
            'tecnologias_principais': self.tecnologias
        }

        # Contar por criticidade
        for vuln in self.vulnerabilidades:
            crit = vuln.get('criticidade', 'BAIXA')
            analise['por_criticidade'][crit] = analise['por_criticidade'].get(crit, 0) + 1

        # Contar tipos de formulário
        for form in self.formularios:
            tipo = form.get('tipo', 'generico')
            analise['tipos_formulario'][tipo] = analise['tipos_formulario'].get(tipo, 0) + 1

        return analise


# Funções de compatibilidade
def executar_scraper_web(alvo: str, credenciais: Optional[Dict] = None,
                        tipo_scan: str = "completo") -> Dict[str, any]:
    """Função compatível com sistema existente"""
    scraper = VarreduraScraperAuth()
    return scraper.executar(alvo, credenciais, tipo_scan)


def scraper_web_basico(alvo: str) -> Dict[str, any]:
    """Spider básico sem autenticação"""
    return executar_scraper_web(alvo, tipo_scan="basico")


def scraper_web_autenticado(alvo: str, usuario: str, senha: str) -> Dict[str, any]:
    """Spider com autenticação"""
    credenciais = {'usuario': usuario, 'senha': senha}
    return executar_scraper_web(alvo, credenciais, tipo_scan="autenticado")


def main():
    """Teste do módulo"""
    import sys

    if len(sys.argv) < 2:
        print("Uso: python varredura_scraper_auth.py <url> [usuario] [senha]")
        return

    url = sys.argv[1]
    credenciais = None

    if len(sys.argv) >= 4:
        credenciais = {
            'usuario': sys.argv[2],
            'senha': sys.argv[3]
        }

    scraper = VarreduraScraperAuth()
    resultado = scraper.executar(url, credenciais)

    print(json.dumps(resultado, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
