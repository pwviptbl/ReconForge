#!/usr/bin/env python3
"""
Módulo de Testes de Segurança de API
Testa vulnerabilidades em APIs REST, GraphQL, SOAP
"""

import json
import time
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
from utils.logger import obter_logger


class TestadorSegurancaAPI:
    """Classe para testar segurança de APIs"""

    def __init__(self):
        self.logger = obter_logger("TestadorAPI")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Content-Type': 'application/json'
        })

        # Payloads para testes de API
        self.payloads_injection = [
            {"username": "' OR '1'='1", "password": "admin"},
            {"username": "admin' --", "password": ""},
            {"username": "admin", "password": "' OR '1'='1' --"},
            {"username": "../../etc/passwd", "password": ""},
            {"username": "<script>alert(1)</script>", "password": ""}
        ]

        self.payloads_broken_auth = [
            {"username": "admin", "password": "wrong"},
            {"username": "", "password": "admin"},
            {"username": "admin", "password": ""},
            {"username": "Admin", "password": "admin"},  # Case sensitivity
            {"username": "admin ", "password": "admin"}  # Trailing space
        ]

        self.payloads_idor = [
            {"user_id": "1"},
            {"user_id": "2"},
            {"user_id": "999"},  # Non-existent
            {"user_id": "-1"},   # Negative
            {"user_id": "0"}     # Zero
        ]

        self.payloads_rate_limit = [
            {"test": "data1"},
            {"test": "data2"},
            {"test": "data3"}
        ]

    def testar_autenticacao_quebrada(self, base_url: str, endpoints: List[str]) -> Dict[str, Any]:
        """Testa vulnerabilidades de autenticação quebrada"""
        self.logger.info(f"🔐 Testando autenticação quebrada em: {base_url}")

        resultados = {
            'base_url': base_url,
            'tipo_teste': 'broken_authentication',
            'vulnerabilidades': [],
            'endpoints_testados': len(endpoints),
            'tempo_execucao': 0
        }

        inicio = time.time()

        for endpoint in endpoints:
            url_completa = urljoin(base_url, endpoint)

            for payload in self.payloads_broken_auth:
                try:
                    resposta = self.session.post(url_completa, json=payload, timeout=10)

                    # Verificar se conseguiu autenticar com credenciais incorretas
                    if resposta.status_code == 200:
                        conteudo = resposta.text.lower()

                        # Verificar sinais de autenticação bem-sucedida
                        sinais_sucesso = [
                            'welcome', 'dashboard', 'logged in', 'success',
                            'token', 'session', 'authenticated', 'login successful'
                        ]

                        if any(sinal in conteudo for sinal in sinais_sucesso):
                            resultados['vulnerabilidades'].append({
                                'endpoint': endpoint,
                                'payload': payload,
                                'tipo': 'weak_authentication',
                                'severidade': 'alta',
                                'evidencia': f'Autenticação fraca detectada com payload: {payload}'
                            })
                            self.logger.warning(f"🚨 Autenticação fraca em {endpoint}")

                except Exception as e:
                    self.logger.debug(f"Erro testando {endpoint}: {e}")

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_injection_api(self, base_url: str, endpoints: List[str]) -> Dict[str, Any]:
        """Testa vulnerabilidades de injeção em APIs"""
        self.logger.info(f"💉 Testando injeção em APIs: {base_url}")

        resultados = {
            'base_url': base_url,
            'tipo_teste': 'api_injection',
            'vulnerabilidades': [],
            'endpoints_testados': len(endpoints),
            'tempo_execucao': 0
        }

        inicio = time.time()

        for endpoint in endpoints:
            url_completa = urljoin(base_url, endpoint)

            for payload in self.payloads_injection:
                try:
                    resposta = self.session.post(url_completa, json=payload, timeout=10)

                    # Verificar sinais de injeção bem-sucedida
                    if resposta.status_code in [200, 500]:
                        conteudo = resposta.text.lower()

                        sinais_injection = [
                            'sql', 'syntax', 'error', 'mysql', 'oracle',
                            'root:', 'daemon:', 'script', 'alert'
                        ]

                        if any(sinal in conteudo for sinal in sinais_injection):
                            resultados['vulnerabilidades'].append({
                                'endpoint': endpoint,
                                'payload': payload,
                                'tipo': 'api_injection',
                                'severidade': 'critica',
                                'evidencia': f'Injeção detectada: {conteudo[:100]}...'
                            })
                            self.logger.warning(f"🚨 Injeção em API detectada em {endpoint}")

                except Exception as e:
                    self.logger.debug(f"Erro testando {endpoint}: {e}")

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_idor(self, base_url: str, endpoints: List[str]) -> Dict[str, Any]:
        """Testa vulnerabilidades IDOR (Insecure Direct Object References)"""
        self.logger.info(f"🎯 Testando IDOR em: {base_url}")

        resultados = {
            'base_url': base_url,
            'tipo_teste': 'idor',
            'vulnerabilidades': [],
            'endpoints_testados': len(endpoints),
            'tempo_execucao': 0
        }

        inicio = time.time()

        for endpoint in endpoints:
            url_completa = urljoin(base_url, endpoint)

            for payload in self.payloads_idor:
                try:
                    resposta = self.session.get(url_completa, params=payload, timeout=10)

                    # Verificar se consegue acessar recursos de outros usuários
                    if resposta.status_code == 200:
                        conteudo = resposta.text.lower()

                        # Verificar se retornou dados sensíveis
                        sinais_dados = [
                            'email', 'password', 'ssn', 'credit', 'card',
                            'user_id', 'account', 'balance', 'personal'
                        ]

                        if any(sinal in conteudo for sinal in sinais_dados):
                            resultados['vulnerabilidades'].append({
                                'endpoint': endpoint,
                                'payload': payload,
                                'tipo': 'idor',
                                'severidade': 'alta',
                                'evidencia': f'Acesso não autorizado a dados: {payload}'
                            })
                            self.logger.warning(f"🚨 IDOR detectado em {endpoint}")

                except Exception as e:
                    self.logger.debug(f"Erro testando {endpoint}: {e}")

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_rate_limiting(self, base_url: str, endpoints: List[str]) -> Dict[str, Any]:
        """Testa limitações de taxa (Rate Limiting)"""
        self.logger.info(f"⏱️ Testando rate limiting em: {base_url}")

        resultados = {
            'base_url': base_url,
            'tipo_teste': 'rate_limiting',
            'vulnerabilidades': [],
            'endpoints_testados': len(endpoints),
            'tempo_execucao': 0
        }

        inicio = time.time()

        for endpoint in endpoints:
            url_completa = urljoin(base_url, endpoint)

            # Fazer múltiplas requisições rápidas
            respostas = []
            for i in range(10):  # 10 requisições rápidas
                try:
                    resposta = self.session.post(url_completa,
                                               json=self.payloads_rate_limit[i % len(self.payloads_rate_limit)],
                                               timeout=5)
                    respostas.append(resposta.status_code)
                    time.sleep(0.1)  # Pequena pausa
                except Exception as e:
                    respostas.append(0)  # Erro de conexão

            # Verificar se não há bloqueio por rate limiting
            status_codes = [code for code in respostas if code != 0]

            if len(status_codes) >= 8:  # Pelo menos 8 requisições bem-sucedidas
                if 429 not in status_codes:  # 429 = Too Many Requests
                    resultados['vulnerabilidades'].append({
                        'endpoint': endpoint,
                        'tipo': 'missing_rate_limiting',
                        'severidade': 'media',
                        'evidencia': f'Sem rate limiting detectado: {len(status_codes)} requisições permitidas'
                    })
                    self.logger.warning(f"🚨 Falta rate limiting em {endpoint}")

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_cors(self, base_url: str, endpoints: List[str]) -> Dict[str, Any]:
        """Testa configurações CORS"""
        self.logger.info(f"🌐 Testando CORS em: {base_url}")

        resultados = {
            'base_url': base_url,
            'tipo_teste': 'cors',
            'vulnerabilidades': [],
            'endpoints_testados': len(endpoints),
            'tempo_execucao': 0
        }

        inicio = time.time()

        for endpoint in endpoints:
            url_completa = urljoin(base_url, endpoint)

            # Testar com Origin malicioso
            headers_cors = {
                'Origin': 'https://evil.com'
            }

            try:
                resposta = self.session.options(url_completa, headers=headers_cors, timeout=10)

                cors_allow_origin = resposta.headers.get('Access-Control-Allow-Origin', '')
                cors_allow_credentials = resposta.headers.get('Access-Control-Allow-Credentials', '')

                # Verificar configurações inseguras
                if cors_allow_origin == '*' and cors_allow_credentials == 'true':
                    resultados['vulnerabilidades'].append({
                        'endpoint': endpoint,
                        'tipo': 'cors_misconfiguration',
                        'severidade': 'alta',
                        'evidencia': 'CORS permite qualquer origem com credenciais'
                    })
                    self.logger.warning(f"🚨 CORS inseguro em {endpoint}")

                elif cors_allow_origin == 'https://evil.com':
                    resultados['vulnerabilidades'].append({
                        'endpoint': endpoint,
                        'tipo': 'cors_reflection',
                        'severidade': 'media',
                        'evidencia': f'CORS reflete origem: {cors_allow_origin}'
                    })
                    self.logger.warning(f"🚨 CORS reflete origem em {endpoint}")

            except Exception as e:
                self.logger.debug(f"Erro testando CORS em {endpoint}: {e}")

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_graphql(self, base_url: str) -> Dict[str, Any]:
        """Testa vulnerabilidades específicas do GraphQL"""
        self.logger.info(f"🔺 Testando GraphQL em: {base_url}")

        resultados = {
            'base_url': base_url,
            'tipo_teste': 'graphql',
            'vulnerabilidades': [],
            'tempo_execucao': 0
        }

        inicio = time.time()

        # Endpoint comum do GraphQL
        graphql_endpoint = urljoin(base_url, '/graphql')

        # Queries de teste
        queries_teste = [
            # Introspection query
            {"query": "{__schema{types{name}}}"},
            # Query maliciosa
            {"query": "{users{id,email,password}}"},
            # Query com injeção
            {"query": "{users(id:\"1' OR '1'='1\"){id,email}}"}
        ]

        for query in queries_teste:
            try:
                resposta = self.session.post(graphql_endpoint, json=query, timeout=10)

                if resposta.status_code == 200:
                    dados = resposta.json()

                    # Verificar se introspection está habilitada
                    if '__schema' in str(dados):
                        resultados['vulnerabilidades'].append({
                            'endpoint': graphql_endpoint,
                            'tipo': 'graphql_introspection',
                            'severidade': 'baixa',
                            'evidencia': 'Introspection habilitada'
                        })
                        self.logger.warning(f"🚨 GraphQL introspection habilitada")

                    # Verificar se retornou dados sensíveis
                    if 'password' in str(dados).lower():
                        resultados['vulnerabilidades'].append({
                            'endpoint': graphql_endpoint,
                            'tipo': 'graphql_data_exposure',
                            'severidade': 'alta',
                            'evidencia': 'Dados sensíveis expostos via GraphQL'
                        })
                        self.logger.warning(f"🚨 Dados sensíveis expostos no GraphQL")

            except Exception as e:
                self.logger.debug(f"Erro testando GraphQL: {e}")

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def descobrir_endpoints_api(self, base_url: str) -> List[str]:
        """Descobre endpoints de API automaticamente"""
        endpoints = []

        # Endpoints comuns para testar
        endpoints_comuns = [
            '/api/login',
            '/api/auth',
            '/api/users',
            '/api/user',
            '/api/profile',
            '/api/admin',
            '/api/data',
            '/api/search',
            '/login',
            '/auth',
            '/users',
            '/user'
        ]

        # Testar endpoints comuns
        for endpoint in endpoints_comuns:
            url_teste = urljoin(base_url, endpoint)
            try:
                resposta = self.session.get(url_teste, timeout=5)
                if resposta.status_code != 404:
                    endpoints.append(endpoint)
                    self.logger.debug(f"Endpoint encontrado: {endpoint}")
            except:
                pass

        return endpoints

    def executar_teste_completo_api(self, base_url: str) -> Dict[str, Any]:
        """Executa todos os testes de segurança de API"""
        self.logger.info(f"🔬 Iniciando teste completo de segurança de API: {base_url}")

        resultados_completos = {
            'base_url': base_url,
            'timestamp': time.time(),
            'testes_executados': [],
            'vulnerabilidades_totais': 0,
            'tempo_total': 0
        }

        inicio_total = time.time()

        # Descobrir endpoints
        endpoints = self.descobrir_endpoints_api(base_url)
        self.logger.info(f"📋 Endpoints descobertos: {len(endpoints)}")

        # Lista de testes a executar
        testes = [
            ('broken_auth', self.testar_autenticacao_quebrada),
            ('api_injection', self.testar_injection_api),
            ('idor', self.testar_idor),
            ('rate_limiting', self.testar_rate_limiting),
            ('cors', self.testar_cors),
            ('graphql', self.testar_graphql)
        ]

        for nome_teste, funcao_teste in testes:
            try:
                self.logger.info(f"Executando teste: {nome_teste}")

                if nome_teste == 'graphql':
                    # GraphQL não precisa de lista de endpoints
                    resultado = funcao_teste(base_url)
                else:
                    resultado = funcao_teste(base_url, endpoints)

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

        self.logger.info(f"✅ Teste de API finalizado: {resultados_completos['vulnerabilidades_totais']} vulnerabilidades encontradas")
        return resultados_completos


# Funções de compatibilidade para o sistema
def testar_seguranca_api(base_url: str) -> Dict[str, Any]:
    """Função de compatibilidade para testar segurança de API"""
    testador = TestadorSegurancaAPI()
    return testador.executar_teste_completo_api(base_url)


def testar_autenticacao_api(base_url: str, endpoints: List[str]) -> Dict[str, Any]:
    """Testa apenas autenticação de API"""
    testador = TestadorSegurancaAPI()
    return testador.testar_autenticacao_quebrada(base_url, endpoints)


def testar_injection_api(base_url: str, endpoints: List[str]) -> Dict[str, Any]:
    """Testa apenas injeção em API"""
    testador = TestadorSegurancaAPI()
    return testador.testar_injection_api(base_url, endpoints)


if __name__ == "__main__":
    # Exemplo de uso
    testador = TestadorSegurancaAPI()

    # URL base da API
    base_url = "http://localhost:8080/api"

    print("🧪 Testando segurança de API...")

    # Teste completo
    resultado_completo = testador.executar_teste_completo_api(base_url)
    print(f"Teste completo - Total vulnerabilidades: {resultado_completo['vulnerabilidades_totais']}")
    print(f"Tempo total: {resultado_completo['tempo_total']:.2f}s")

    # Mostrar vulnerabilidades encontradas
    for teste in resultado_completo['testes_executados']:
        if 'resultado' in teste and 'vulnerabilidades' in teste['resultado']:
            vulns = teste['resultado']['vulnerabilidades']
            if vulns:
                print(f"\n🔍 {teste['teste'].upper()}:")
                for vuln in vulns:
                    print(f"  - {vuln['tipo']}: {vuln['evidencia']}")
