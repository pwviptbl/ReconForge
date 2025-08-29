#!/usr/bin/env python3
"""
Módulo avançado de web scraping com múltiplas engines de navegador
Integração com VarreduraIA
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import re

# Selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager

# Playwright
from playwright.async_api import async_playwright

# MechanicalSoup
import mechanicalsoup

# Requests-HTML
import requests_html

# Utilitários
from utils.logger import obter_logger


class EngineNavegador(Enum):
    """Engines de navegador disponíveis"""
    SELENIUM_CHROME = "selenium_chrome"
    SELENIUM_FIREFOX = "selenium_firefox"
    PLAYWRIGHT_CHROMIUM = "playwright_chromium"
    PLAYWRIGHT_FIREFOX = "playwright_firefox"
    MECHANICALSOUP = "mechanicalsoup"
    REQUESTS_HTML = "requests_html"


@dataclass
class ConfiguracaoNavegador:
    """Configuração para engines de navegador"""
    engine: EngineNavegador
    headless: bool = True
    timeout: int = 30
    user_agent: Optional[str] = None
    viewport_width: int = 1920
    viewport_height: int = 1080
    wait_for_network: bool = True


@dataclass
class ResultadoScraping:
    """Resultado do scraping"""
    url: str
    titulo: str
    status_code: int
    formularios: List[Dict]
    links: List[str]
    tecnologias: Dict[str, str]
    cookies: List[Dict]
    screenshot_path: Optional[str]
    tempo_execucao: float
    engine_usado: str
    sucesso: bool
    erro: Optional[str] = None


class VarreduraScraperMultiEngine:
    """Scraper avançado com múltiplas engines de navegador"""

    def __init__(self, config: ConfiguracaoNavegador):
        self.config = config
        self.logger = obter_logger("ScraperMultiEngine")
        self.session_cookies = []

    def executar_scraping(self, url: str, credenciais: Optional[Dict] = None) -> ResultadoScraping:
        """Executa scraping usando a engine configurada"""
        inicio = time.time()

        try:
            if self.config.engine == EngineNavegador.SELENIUM_CHROME:
                resultado = self._scraping_selenium_chrome(url, credenciais)
            elif self.config.engine == EngineNavegador.SELENIUM_FIREFOX:
                resultado = self._scraping_selenium_firefox(url, credenciais)
            elif self.config.engine in [EngineNavegador.PLAYWRIGHT_CHROMIUM, EngineNavegador.PLAYWRIGHT_FIREFOX]:
                resultado = asyncio.run(self._scraping_playwright(url, credenciais))
            elif self.config.engine == EngineNavegador.MECHANICALSOUP:
                resultado = self._scraping_mechanicalsoup(url, credenciais)
            elif self.config.engine == EngineNavegador.REQUESTS_HTML:
                resultado = self._scraping_requests_html(url, credenciais)
            else:
                raise ValueError(f"Engine não suportada: {self.config.engine}")

            tempo_total = time.time() - inicio
            resultado.tempo_execucao = tempo_total
            resultado.engine_usado = self.config.engine.value
            resultado.sucesso = True

            return resultado

        except Exception as e:
            tempo_total = time.time() - inicio
            self.logger.error(f"Erro no scraping: {e}")
            return ResultadoScraping(
                url=url,
                titulo="",
                status_code=0,
                formularios=[],
                links=[],
                tecnologias={},
                cookies=[],
                screenshot_path=None,
                tempo_execucao=tempo_total,
                engine_usado=self.config.engine.value,
                sucesso=False,
                erro=str(e)
            )

    def _scraping_selenium_chrome(self, url: str, credenciais: Optional[Dict]) -> ResultadoScraping:
        """Scraping com Selenium Chrome"""
        self.logger.info("🚀 Iniciando scraping com Selenium Chrome")

        chrome_options = Options()
        if self.config.headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument(f"--window-size={self.config.viewport_width},{self.config.viewport_height}")
        if self.config.user_agent:
            chrome_options.add_argument(f"--user-agent={self.config.user_agent}")

        driver = webdriver.Chrome(ChromeDriverManager().install(), options=chrome_options)

        try:
            driver.get(url)
            WebDriverWait(driver, self.config.timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )

            # Extrair dados
            titulo = driver.title
            formularios = self._extrair_formularios_selenium(driver)
            links = self._extrair_links_selenium(driver)
            tecnologias = self._detectar_tecnologias_selenium(driver)
            cookies = self._extrair_cookies_selenium(driver)

            # Autenticação se fornecida
            if credenciais:
                self._autenticar_selenium(driver, credenciais)

            # Screenshot
            screenshot_path = f"screenshot_selenium_{int(time.time())}.png"
            driver.save_screenshot(screenshot_path)

            return ResultadoScraping(
                url=driver.current_url,
                titulo=titulo,
                status_code=200,  # Selenium não retorna status code diretamente
                formularios=formularios,
                links=links,
                tecnologias=tecnologias,
                cookies=cookies,
                screenshot_path=screenshot_path,
                tempo_execucao=0,  # Será definido no método principal
                engine_usado="",
                sucesso=True
            )

        finally:
            driver.quit()

    async def _scraping_playwright(self, url: str, credenciais: Optional[Dict]) -> ResultadoScraping:
        """Scraping com Playwright"""
        self.logger.info("🎭 Iniciando scraping com Playwright")

        async with async_playwright() as p:
            # Escolher navegador
            if self.config.engine == EngineNavegador.PLAYWRIGHT_CHROMIUM:
                browser = await p.chromium.launch(headless=self.config.headless)
            else:
                browser = await p.firefox.launch(headless=self.config.headless)

            context = await browser.new_context(
                viewport={'width': self.config.viewport_width, 'height': self.config.viewport_height},
                user_agent=self.config.user_agent
            )
            page = await context.new_page()
            # Ajustar timeout padrão para todas as operações na página
            try:
                page.set_default_timeout(self.config.timeout * 1000)
            except Exception:
                # versões antigas podem não suportar set_default_timeout sincrono; usar async
                try:
                    await page.set_default_timeout(self.config.timeout * 1000)  # type: ignore
                except Exception:
                    pass

            try:
                await page.goto(url, wait_until='networkidle' if self.config.wait_for_network else 'load')

                # Autenticação se fornecida (antes da extração para refletir pós-login)
                if credenciais:
                    await self._autenticar_playwright(page, credenciais)

                # Extrair dados (pós-login ou estado atual)
                titulo = await page.title()
                formularios = await self._extrair_formularios_playwright(page)
                links = await self._extrair_links_playwright(page)
                tecnologias = await self._detectar_tecnologias_playwright(page)
                cookies = await self._extrair_cookies_playwright(context)

                # Screenshot
                screenshot_path = f"screenshot_playwright_{int(time.time())}.png"
                await page.screenshot(path=screenshot_path)

                return ResultadoScraping(
                    url=page.url,
                    titulo=titulo,
                    status_code=200,  # Playwright não retorna status code diretamente
                    formularios=formularios,
                    links=links,
                    tecnologias=tecnologias,
                    cookies=cookies,
                    screenshot_path=screenshot_path,
                    tempo_execucao=0,
                    engine_usado="",
                    sucesso=True
                )

            finally:
                await browser.close()

    def _scraping_mechanicalsoup(self, url: str, credenciais: Optional[Dict]) -> ResultadoScraping:
        """Scraping com MechanicalSoup"""
        self.logger.info("🤖 Iniciando scraping com MechanicalSoup")

        browser = mechanicalsoup.StatefulBrowser(
            user_agent=self.config.user_agent or 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        )

        try:
            response = browser.open(url)

            # Extrair dados
            titulo = browser.get_title() or ""
            formularios = self._extrair_formularios_mechanicalsoup(browser)
            links = self._extrair_links_mechanicalsoup(browser)
            tecnologias = self._detectar_tecnologias_mechanicalsoup(response)
            cookies = self._extrair_cookies_mechanicalsoup(browser)

            # Autenticação se fornecida
            if credenciais:
                self._autenticar_mechanicalsoup(browser, credenciais)

            return ResultadoScraping(
                url=browser.get_url(),
                titulo=titulo,
                status_code=response.status_code,
                formularios=formularios,
                links=links,
                tecnologias=tecnologias,
                cookies=cookies,
                screenshot_path=None,  # MechanicalSoup não suporta screenshots
                tempo_execucao=0,
                engine_usado="",
                sucesso=True
            )

        finally:
            browser.close()

    def _scraping_requests_html(self, url: str, credenciais: Optional[Dict]) -> ResultadoScraping:
        """Scraping com Requests-HTML"""
        self.logger.info("🌐 Iniciando scraping com Requests-HTML")

        session = requests_html.HTMLSession()

        try:
            response = session.get(url)

            # Renderizar JavaScript se necessário
            if self.config.wait_for_network:
                response.html.render(timeout=self.config.timeout)

            # Extrair dados
            titulo = response.html.find('title', first=True).text if response.html.find('title') else ""
            formularios = self._extrair_formularios_requests_html(response)
            links = self._extrair_links_requests_html(response)
            tecnologias = self._detectar_tecnologias_requests_html(response)
            cookies = self._extrair_cookies_requests_html(session)

            # Autenticação se fornecida
            if credenciais:
                self._autenticar_requests_html(session, url, credenciais)

            return ResultadoScraping(
                url=response.url,
                titulo=titulo,
                status_code=response.status_code,
                formularios=formularios,
                links=links,
                tecnologias=tecnologias,
                cookies=cookies,
                screenshot_path=None,  # Requests-HTML não suporta screenshots
                tempo_execucao=0,
                engine_usado="",
                sucesso=True
            )

        finally:
            session.close()

    # Métodos auxiliares para extração de dados
    def _extrair_formularios_selenium(self, driver) -> List[Dict]:
        """Extrai formulários com Selenium"""
        forms = []
        try:
            form_elements = driver.find_elements(By.TAG_NAME, "form")
            for form in form_elements:
                form_data = {
                    'action': form.get_attribute('action') or '',
                    'method': form.get_attribute('method') or 'GET',
                    'inputs': []
                }

                inputs = form.find_elements(By.TAG_NAME, "input")
                for input_elem in inputs:
                    form_data['inputs'].append({
                        'name': input_elem.get_attribute('name') or '',
                        'type': input_elem.get_attribute('type') or 'text',
                        'value': input_elem.get_attribute('value') or ''
                    })

                forms.append(form_data)
        except Exception as e:
            self.logger.debug(f"Erro extraindo formulários Selenium: {e}")
        return forms

    async def _extrair_formularios_playwright(self, page) -> List[Dict]:
        """Extrai formulários com Playwright"""
        forms = []
        try:
            form_elements = await page.query_selector_all('form')
            for form in form_elements:
                action = await form.get_attribute('action') or ''
                method = await form.get_attribute('method') or 'GET'

                form_data = {
                    'action': action,
                    'method': method,
                    'inputs': []
                }

                inputs = await form.query_selector_all('input')
                for input_elem in inputs:
                    name = await input_elem.get_attribute('name') or ''
                    type_attr = await input_elem.get_attribute('type') or 'text'
                    value = await input_elem.get_attribute('value') or ''

                    form_data['inputs'].append({
                        'name': name,
                        'type': type_attr,
                        'value': value
                    })

                forms.append(form_data)
        except Exception as e:
            self.logger.debug(f"Erro extraindo formulários Playwright: {e}")
        return forms

    def _extrair_formularios_mechanicalsoup(self, browser) -> List[Dict]:
        """Extrai formulários com MechanicalSoup"""
        forms = []
        try:
            page = browser.get_current_page()
            form_elements = page.find_all('form')

            for form in form_elements:
                form_data = {
                    'action': form.get('action') or '',
                    'method': form.get('method') or 'GET',
                    'inputs': []
                }

                inputs = form.find_all('input')
                for input_elem in inputs:
                    form_data['inputs'].append({
                        'name': input_elem.get('name') or '',
                        'type': input_elem.get('type') or 'text',
                        'value': input_elem.get('value') or ''
                    })

                forms.append(form_data)
        except Exception as e:
            self.logger.debug(f"Erro extraindo formulários MechanicalSoup: {e}")
        return forms

    def _extrair_formularios_requests_html(self, response) -> List[Dict]:
        """Extrai formulários com Requests-HTML"""
        forms = []
        try:
            form_elements = response.html.find('form')

            for form in form_elements:
                form_data = {
                    'action': form.attrs.get('action') or '',
                    'method': form.attrs.get('method') or 'GET',
                    'inputs': []
                }

                inputs = form.find('input')
                for input_elem in inputs:
                    form_data['inputs'].append({
                        'name': input_elem.attrs.get('name') or '',
                        'type': input_elem.attrs.get('type') or 'text',
                        'value': input_elem.attrs.get('value') or ''
                    })

                forms.append(form_data)
        except Exception as e:
            self.logger.debug(f"Erro extraindo formulários Requests-HTML: {e}")
        return forms

    # Métodos de extração de links (simplificados)
    def _extrair_links_selenium(self, driver) -> List[str]:
        """Extrai links com Selenium"""
        links = []
        try:
            link_elements = driver.find_elements(By.TAG_NAME, "a")
            for link in link_elements:
                href = link.get_attribute('href')
                if href:
                    links.append(href)
        except Exception as e:
            self.logger.debug(f"Erro extraindo links Selenium: {e}")
        return links

    async def _extrair_links_playwright(self, page) -> List[str]:
        """Extrai links com Playwright"""
        links = []
        try:
            link_elements = await page.query_selector_all('a')
            for link in link_elements:
                href = await link.get_attribute('href')
                if href:
                    links.append(href)
        except Exception as e:
            self.logger.debug(f"Erro extraindo links Playwright: {e}")
        return links

    def _extrair_links_mechanicalsoup(self, browser) -> List[str]:
        """Extrai links com MechanicalSoup"""
        links = []
        try:
            page = browser.get_current_page()
            link_elements = page.find_all('a')
            for link in link_elements:
                href = link.get('href')
                if href:
                    links.append(href)
        except Exception as e:
            self.logger.debug(f"Erro extraindo links MechanicalSoup: {e}")
        return links

    def _extrair_links_requests_html(self, response) -> List[str]:
        """Extrai links com Requests-HTML"""
        links = []
        try:
            link_elements = response.html.find('a')
            for link in link_elements:
                href = link.attrs.get('href')
                if href:
                    links.append(href)
        except Exception as e:
            self.logger.debug(f"Erro extraindo links Requests-HTML: {e}")
        return links

    # Métodos de detecção de tecnologias (simplificados)
    def _detectar_tecnologias_selenium(self, driver) -> Dict[str, str]:
        """Detecta tecnologias com Selenium"""
        tech = {}
        try:
            user_agent = driver.execute_script("return navigator.userAgent")
            if "Chrome" in user_agent:
                tech['browser'] = 'Chrome'
            elif "Firefox" in user_agent:
                tech['browser'] = 'Firefox'
        except:
            pass
        return tech

    async def _detectar_tecnologias_playwright(self, page) -> Dict[str, str]:
        """Detecta tecnologias com Playwright"""
        tech = {}
        try:
            user_agent = await page.evaluate("navigator.userAgent")
            if "Chrome" in user_agent:
                tech['browser'] = 'Chrome'
            elif "Firefox" in user_agent:
                tech['browser'] = 'Firefox'
        except:
            pass
        return tech

    def _detectar_tecnologias_mechanicalsoup(self, response) -> Dict[str, str]:
        """Detecta tecnologias com MechanicalSoup"""
        tech = {}
        try:
            content = str(response.content)
            if "Apache" in content:
                tech['server'] = 'Apache'
            if "PHP" in content:
                tech['language'] = 'PHP'
        except:
            pass
        return tech

    def _detectar_tecnologias_requests_html(self, response) -> Dict[str, str]:
        """Detecta tecnologias com Requests-HTML"""
        tech = {}
        try:
            content = response.text
            if "Apache" in content:
                tech['server'] = 'Apache'
            if "PHP" in content:
                tech['language'] = 'PHP'
        except:
            pass
        return tech

    # Métodos de extração de cookies
    def _extrair_cookies_selenium(self, driver) -> List[Dict]:
        """Extrai cookies com Selenium"""
        cookies = []
        try:
            selenium_cookies = driver.get_cookies()
            for cookie in selenium_cookies:
                cookies.append({
                    'name': cookie['name'],
                    'value': cookie['value'],
                    'domain': cookie.get('domain', ''),
                    'path': cookie.get('path', '/')
                })
        except Exception as e:
            self.logger.debug(f"Erro extraindo cookies Selenium: {e}")
        return cookies

    async def _extrair_cookies_playwright(self, context) -> List[Dict]:
        """Extrai cookies com Playwright"""
        cookies = []
        try:
            playwright_cookies = await context.cookies()
            for cookie in playwright_cookies:
                cookies.append({
                    'name': cookie['name'],
                    'value': cookie['value'],
                    'domain': cookie.get('domain', ''),
                    'path': cookie.get('path', '/')
                })
        except Exception as e:
            self.logger.debug(f"Erro extraindo cookies Playwright: {e}")
        return cookies

    def _extrair_cookies_mechanicalsoup(self, browser) -> List[Dict]:
        """Extrai cookies com MechanicalSoup"""
        cookies = []
        try:
            for cookie in browser.session.cookies:
                cookies.append({
                    'name': cookie.name,
                    'value': cookie.value,
                    'domain': cookie.domain or '',
                    'path': cookie.path or '/'
                })
        except Exception as e:
            self.logger.debug(f"Erro extraindo cookies MechanicalSoup: {e}")
        return cookies

    def _extrair_cookies_requests_html(self, session) -> List[Dict]:
        """Extrai cookies com Requests-HTML"""
        cookies = []
        try:
            for cookie in session.cookies:
                cookies.append({
                    'name': cookie.name,
                    'value': cookie.value,
                    'domain': cookie.domain or '',
                    'path': cookie.path or '/'
                })
        except Exception as e:
            self.logger.debug(f"Erro extraindo cookies Requests-HTML: {e}")
        return cookies

    # Métodos de autenticação (básicos)
    def _autenticar_selenium(self, driver, credenciais: Dict):
        """Autenticação básica com Selenium"""
        try:
            # Implementação básica - pode ser expandida
            usuario_field = driver.find_element(By.NAME, "login")
            senha_field = driver.find_element(By.NAME, "senha")
            submit_button = driver.find_element(By.CSS_SELECTOR, "input[type='submit'], button[type='submit']")

            usuario_field.send_keys(credenciais.get('usuario', ''))
            senha_field.send_keys(credenciais.get('senha', ''))
            submit_button.click()

            WebDriverWait(driver, 10).until(
                lambda d: d.current_url != driver.current_url or "login" not in d.current_url.lower()
            )
        except Exception as e:
            self.logger.debug(f"Erro na autenticação Selenium: {e}")

    async def _autenticar_playwright(self, page, credenciais: Dict):
        """Autenticação robusta com Playwright com múltiplos seletores e fallbacks extras (inclui e-cidade)"""
        try:
            usuario = credenciais.get('usuario', '')
            senha = credenciais.get('senha', '')
            pre_url = page.url
            max_timeout_ms = max(self.config.timeout, 45) * 1000  # elevar timeout efetivo

            # Variantes comuns e específicas (e-cidade e legados)
            user_selectors = [
                'input[name="login"]',
                'input[name="usuario"]',
                'input[name="username"]',
                'input[name="txtlogin"]',
                'input[name="txt_login"]',
                'input[name="LOGIN"]',
                'input#login',
                'input#usuario',
                'input#username',
                'input[type="text"]'
            ]
            pass_selectors = [
                'input[name="senha"]',
                'input[name="password"]',
                'input[name="txtsenha"]',
                'input[name="txt_senha"]',
                'input[name="SENHA"]',
                'input#senha',
                'input#password',
                'input[type="password"]'
            ]
            submit_selectors = [
                'input[type="submit"]',
                'button[type="submit"]',
                'input[type="image"]',
                'button:has-text("Entrar")',
                'button:has-text("Acessar")',
                'button:has-text("Login")',
                'button:has-text("OK")',
                'button:has-text("Enviar")',
                'button:has-text("Continuar")',
                'input[name="entrar"]',
                'input[name="submit"]',
                'a[onclick*="submit"]',
                'a:has-text("Entrar")',
                'a:has-text("Acessar")'
            ]

            async def find_first(ctx, selectors):
                for sel in selectors:
                    loc = ctx.locator(sel)
                    try:
                        if await loc.count() > 0:
                            first = loc.first
                            try:
                                await first.wait_for(state="visible", timeout=5000)
                            except Exception:
                                # mesmo que não fique visível, tente prosseguir
                                pass
                            return first
                    except Exception:
                        continue
                return None

            async def wait_login_transition():
                # Aguarda mudança de URL ou saída de 'login' na URL
                try:
                    await page.wait_for_load_state('domcontentloaded', timeout=max_timeout_ms)
                except Exception:
                    pass
                try:
                    await page.wait_for_function(
                        """(prev) => {
                            try { return window.location.href !== prev && !/login/i.test(window.location.href); }
                            catch(e) { return false; }
                        }""",
                        pre_url,
                        timeout=max_timeout_ms
                    )
                except Exception:
                    # fallback de pequena espera
                    await asyncio.sleep(2)

            # Considerar página e iframes
            contexts = [page] + page.frames

            for ctx in contexts:
                try:
                    user_loc = await find_first(ctx, user_selectors)
                    pass_loc = await find_first(ctx, pass_selectors)

                    if user_loc and pass_loc:
                        self.logger.info("🔐 Localizados campos de usuário e senha. Preenchendo credenciais...")
                        await user_loc.fill(usuario)
                        await pass_loc.fill(senha)

                        # Estratégia 1: clicar no botão de submit
                        submit_loc = await find_first(ctx, submit_selectors)
                        if submit_loc:
                            self.logger.info("🖱️ Botão de envio localizado. Tentando clique para autenticar...")
                            try:
                                await submit_loc.click()
                                await wait_login_transition()
                                if ("login" not in page.url.lower()) or (page.url != pre_url):
                                    return
                            except Exception as e1:
                                self.logger.debug(f"Falha ao clicar no submit: {e1}")

                        # Estratégia 2: pressionar ENTER no campo de senha
                        self.logger.info("↵ Tentando submit via ENTER no campo de senha...")
                        try:
                            await pass_loc.press("Enter")
                            await wait_login_transition()
                            if ("login" not in page.url.lower()) or (page.url != pre_url):
                                return
                        except Exception as e2:
                            self.logger.debug(f"Falha ao enviar ENTER: {e2}")

                        # Estratégia 3: submit por JavaScript no primeiro formulário do contexto
                        self.logger.info("📜 Tentando submit via JavaScript do primeiro formulário...")
                        try:
                            js_ok = await ctx.evaluate("""() => {
                                try {
                                    const forms = document.getElementsByTagName('form');
                                    if (forms && forms.length > 0) {
                                        const f = forms[0];
                                        // Disparar evento 'submit' e chamar submit nativo
                                        const evt = new Event('submit', {bubbles: true, cancelable: true});
                                        f.dispatchEvent(evt);
                                        if (typeof f.submit === 'function') f.submit();
                                        return true;
                                    }
                                } catch(e) {}
                                return false;
                            }""")
                            if js_ok:
                                await wait_login_transition()
                                if ("login" not in page.url.lower()) or (page.url != pre_url):
                                    return
                        except Exception as e3:
                            self.logger.debug(f"Falha no submit JS: {e3}")

                        # Estratégia 4: clique genérico no primeiro botão/submit visível
                        self.logger.info("🧪 Tentando clique genérico no primeiro botão/submit visível...")
                        try:
                            generic = ctx.locator('button, input[type="submit"], input[type="image"]').first
                            await generic.wait_for(state="attached", timeout=3000)
                            await generic.click()
                            await wait_login_transition()
                            if ("login" not in page.url.lower()) or (page.url != pre_url):
                                return
                        except Exception as e4:
                            self.logger.debug(f"Falha no clique genérico: {e4}")

                        # Se chegou aqui, tentou todas as estratégias neste contexto
                        self.logger.debug("Todas as estratégias de submit falharam neste contexto; tentando próximo (se houver).")
                except Exception as inner_e:
                    self.logger.debug(f"Tentativa de autenticação em contexto falhou: {inner_e}")
                    continue

            self.logger.warning("⚠️ Não foi possível autenticar: campos/submit não encontrados ou sem efeito.")
        except Exception as e:
            self.logger.debug(f"Erro na autenticação Playwright: {e}")

    def _autenticar_mechanicalsoup(self, browser, credenciais: Dict):
        """Autenticação básica com MechanicalSoup"""
        try:
            browser.select_form()
            browser['login'] = credenciais.get('usuario', '')
            browser['senha'] = credenciais.get('senha', '')
            browser.submit_selected()
        except Exception as e:
            self.logger.debug(f"Erro na autenticação MechanicalSoup: {e}")

    def _autenticar_requests_html(self, session, url: str, credenciais: Dict):
        """Autenticação básica com Requests-HTML"""
        try:
            data = {
                'login': credenciais.get('usuario', ''),
                'senha': credenciais.get('senha', '')
            }
            session.post(url, data=data)
        except Exception as e:
            self.logger.debug(f"Erro na autenticação Requests-HTML: {e}")


# Função de compatibilidade
def executar_scraping_multi_engine(url: str, engine: EngineNavegador = EngineNavegador.PLAYWRIGHT_CHROMIUM,
                                  credenciais: Optional[Dict] = None) -> ResultadoScraping:
    """Função de compatibilidade para executar scraping com múltiplas engines"""
    config = ConfiguracaoNavegador(engine=engine)
    scraper = VarreduraScraperMultiEngine(config)
    return scraper.executar_scraping(url, credenciais)


if __name__ == "__main__":
    # Exemplo de uso
    print("🧪 Testando VarreduraScraperMultiEngine")

    # Teste com Playwright
    resultado = executar_scraping_multi_engine(
        "http://localhost:8080/e-cidade/login.php",
        EngineNavegador.PLAYWRIGHT_CHROMIUM,
        {"usuario": "dbseller", "senha": ""}
    )

    print(f"✅ Resultado: {resultado.sucesso}")
    print(f"📄 Título: {resultado.titulo}")
    print(f"📝 Formulários: {len(resultado.formularios)}")
    print(f"🔗 Links: {len(resultado.links)}")
    print(f"🍪 Cookies: {len(resultado.cookies)}")
    print(f"⏱️ Tempo: {resultado.tempo_execucao:.2f}s")
