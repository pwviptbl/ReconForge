#!/usr/bin/env python3
"""
Analisador de Vulnerabilidades Web em Python
Substituto para Nikto/SQLMap - Analisador de vulnerabilidades web eficiente em Python puro
"""

import requests
import re
import time
import json
from typing import List, Dict, Optional, Set
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import obter_logger


class AnalisadorVulnerabilidadesWeb:
    """Analisador de vulnerabilidades web eficiente em Python puro"""

    def __init__(self):
        self.logger = obter_logger("WebVulnAnalyzer")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.timeout = 10
        self.max_workers = 10

        # Assinaturas de vulnerabilidades
        self.assinaturas = {
            'sql_injection': {
                'padroes': [
                    r"('|\")?\s*(AND|OR)\s+\d+\s*=\s*\d+\s*('|\")?",
                    r"('|\")?\s*;\s*(DROP|DELETE|UPDATE|INSERT)\s+",
                    r"('|\")?\s*UNION\s+(ALL\s+)?SELECT\s+",
                    r"('|\")?\s*ORDER\s+BY\s+\d+\s*--",
                    r"('|\")?\s*GROUP\s+BY\s+\d+\s*HAVING\s+\d+\s*=\s*\d+"
                ],
                'severidade': 'alta',
                'tipo': 'SQL Injection'
            },
            'xss': {
                'padroes': [
                    r"<script[^>]*>.*?</script>",
                    r"javascript:",
                    r"on\w+\s*=",
                    r"<iframe[^>]*src\s*=\s*[\"']javascript:",
                    r"<img[^>]*src\s*=\s*[\"']javascript:"
                ],
                'severidade': 'media',
                'tipo': 'Cross-Site Scripting (XSS)'
            },
            'lfi_rfi': {
                'padroes': [
                    r"\.\./\.\./",
                    r"\.\.\\",
                    r"etc/passwd",
                    r"boot\.ini",
                    r"file://",
                    r"http://",
                    r"ftp://",
                    r"php://",
                    r"data://"
                ],
                'severidade': 'alta',
                'tipo': 'Local/Remote File Inclusion'
            },
            'command_injection': {
                'padroes': [
                    r";\s*(ls|cat|pwd|whoami|id)\s",
                    r"\|\s*(ls|cat|pwd|whoami|id)\s",
                    r"`\s*(ls|cat|pwd|whoami|id)\s`",
                    r"\$\(.*\)",
                    r"system\s*\(",
                    r"exec\s*\(",
                    r"shell_exec\s*\("
                ],
                'severidade': 'alta',
                'tipo': 'Command Injection'
            },
            'open_redirect': {
                'padroes': [
                    r"redirect\s*=\s*http",
                    r"url\s*=\s*http",
                    r"return\s*=\s*http",
                    r"next\s*=\s*http"
                ],
                'severidade': 'media',
                'tipo': 'Open Redirect'
            },
            'directory_traversal': {
                'padroes': [
                    r"\.\./",
                    r"\.\.\\",
                    r"%2e%2e%2f",
                    r"%2e%2e%5c"
                ],
                'severidade': 'alta',
                'tipo': 'Directory Traversal'
            }
        }

        # Headers de segurança para verificar
        self.headers_seguranca = {
            'X-Frame-Options': 'Proteção contra clickjacking',
            'X-Content-Type-Options': 'Proteção contra MIME sniffing',
            'X-XSS-Protection': 'Proteção contra XSS',
            'Content-Security-Policy': 'Política de segurança de conteúdo',
            'Strict-Transport-Security': 'Força HTTPS',
            'Referrer-Policy': 'Política de referrer',
            'Permissions-Policy': 'Controle de permissões',
            'Server': 'Informação do servidor (deve ser oculta)',
            'X-Powered-By': 'Tecnologia usada (deve ser oculta)'
        }

        # Payloads para testes
        self.payloads_sql = [
            "'", "\"", "'; --", "\"; --", "1' OR '1'='1", "1\" OR \"1\"=\"1",
            "1' OR 1=1 --", "1\" OR 1=1 --", "' OR ''='", "\" OR \"\"=\"",
            "1' UNION SELECT NULL --", "1\" UNION SELECT NULL --"
        ]

        self.payloads_xss = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>"
        ]

    def analisar_url(self, url: str, testes_completos: bool = True,
                    testar_payloads: bool = True) -> Dict:
        """
        Analisa vulnerabilidades em uma URL específica

        Args:
            url: URL para analisar
            testes_completos: Executar testes completos
            testar_payloads: Testar payloads de injeção

        Returns:
            Dict com resultados da análise
        """
        self.logger.info(f"🔍 Analisando vulnerabilidades em: {url}")

        inicio = time.time()

        try:
            # Normalizar URL
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'

            # Resultados da análise
            resultados = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'vulnerabilidades': [],
                'headers_seguranca': {},
                'informacoes_servidor': {},
                'testes_realizados': [],
                'recomendacoes': []
            }

            # 1. Análise básica da página
            self.logger.debug("📄 Analisando página principal...")
            response = self.session.get(url, timeout=self.timeout, verify=False)

            # Verificar headers de segurança
            self._analisar_headers_seguranca(response.headers, resultados)

            # Analisar conteúdo da página
            if response.text:
                self._analisar_conteudo(response.text, url, resultados)

            # 2. Testes de injeção se solicitado
            if testar_payloads:
                self.logger.debug("💉 Testando payloads de injeção...")
                self._testar_payloads(url, resultados)

            # 3. Testes completos se solicitado
            if testes_completos:
                self.logger.debug("🔬 Executando testes completos...")
                self._testes_completos(url, resultados)

            # Analisar resultados
            self._analisar_resultados(resultados)

            duracao = time.time() - inicio
            resultados['duracao_segundos'] = round(duracao, 2)

            self.logger.info(f"✅ Análise concluída: {len(resultados['vulnerabilidades'])} vulnerabilidades encontradas")
            return resultados

        except Exception as e:
            self.logger.error(f"❌ Erro na análise: {e}")
            return {
                'url': url,
                'erro': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def _analisar_headers_seguranca(self, headers: Dict, resultados: Dict):
        """Analisa headers de segurança"""
        headers_seguranca = {}

        for header, descricao in self.headers_seguranca.items():
            presente = header in headers
            valor = headers.get(header, '')

            status = 'presente' if presente else 'ausente'

            # Avaliar criticidade
            if header in ['Server', 'X-Powered-By']:
                criticidade = 'baixa' if presente else 'baixa'  # Headers informativos
            elif header in ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']:
                criticidade = 'media' if not presente else 'baixa'
            elif header in ['Content-Security-Policy', 'Strict-Transport-Security']:
                criticidade = 'alta' if not presente else 'baixa'
            else:
                criticidade = 'baixa'

            headers_seguranca[header] = {
                'status': status,
                'valor': valor,
                'descricao': descricao,
                'criticidade': criticidade
            }

        resultados['headers_seguranca'] = headers_seguranca

    def _analisar_conteudo(self, conteudo: str, url: str, resultados: Dict):
        """Analisa conteúdo da página em busca de vulnerabilidades"""
        for vuln_type, config in self.assinaturas.items():
            for padrao in config['padroes']:
                matches = re.findall(padrao, conteudo, re.IGNORECASE | re.MULTILINE)
                if matches:
                    vulnerabilidade = {
                        'tipo': config['tipo'],
                        'severidade': config['severidade'],
                        'url': url,
                        'padrao_detectado': padrao,
                        'ocorrencias': len(matches),
                        'exemplos': matches[:3],  # Primeiros 3 exemplos
                        'categoria': vuln_type,
                        'evidencia': 'Conteúdo da página contém padrões suspeitos'
                    }

                    resultados['vulnerabilidades'].append(vulnerabilidade)

    def _testar_payloads(self, url: str, resultados: Dict):
        """Testa payloads de injeção em parâmetros da URL"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        if not params:
            return

        resultados['testes_realizados'].append('payload_injection')

        # Testar cada parâmetro
        for param_name, param_values in params.items():
            for param_value in param_values:
                # Testar SQL injection
                for payload in self.payloads_sql[:3]:  # Limitar para não ser muito agressivo
                    test_url = self._construir_url_com_payload(url, param_name, payload)
                    try:
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)

                        # Verificar se o payload foi refletido ou causou erro SQL
                        if self._detectar_sql_injection(response.text, payload):
                            vulnerabilidade = {
                                'tipo': 'SQL Injection',
                                'severidade': 'alta',
                                'url': test_url,
                                'parametro': param_name,
                                'payload': payload,
                                'evidencia': 'Payload SQL refletido ou erro de banco detectado',
                                'categoria': 'sql_injection'
                            }
                            resultados['vulnerabilidades'].append(vulnerabilidade)
                            break
                    except:
                        continue

                # Testar XSS
                for payload in self.payloads_xss[:3]:
                    test_url = self._construir_url_com_payload(url, param_name, payload)
                    try:
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)

                        if payload in response.text:
                            vulnerabilidade = {
                                'tipo': 'Cross-Site Scripting (XSS)',
                                'severidade': 'media',
                                'url': test_url,
                                'parametro': param_name,
                                'payload': payload,
                                'evidencia': 'Payload XSS refletido na resposta',
                                'categoria': 'xss'
                            }
                            resultados['vulnerabilidades'].append(vulnerabilidade)
                            break
                    except:
                        continue

    def _construir_url_com_payload(self, url: str, param: str, payload: str) -> str:
        """Constrói URL com payload injetado"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Substituir valor do parâmetro
        params[param] = [payload]

        # Reconstruir query string
        new_query = urlencode(params, doseq=True)

        # Reconstruir URL
        new_url = parsed._replace(query=new_query).geturl()
        return new_url

    def _detectar_sql_injection(self, response_text: str, payload: str) -> bool:
        """Detecta se resposta indica SQL injection"""
        indicadores_sql = [
            'sql syntax', 'mysql error', 'postgresql error', 'sqlite error',
            'oracle error', 'mssql error', 'syntax error', 'database error',
            'you have an error in your sql syntax'
        ]

        response_lower = response_text.lower()

        # Verificar erros de SQL
        for indicador in indicadores_sql:
            if indicador in response_lower:
                return True

        # Verificar se payload foi refletido
        if payload in response_text:
            return True

        return False

    def _testes_completos(self, url: str, resultados: Dict):
        """Executa testes completos de vulnerabilidades"""
        testes = [
            self._teste_open_redirect,
            self._teste_directory_traversal,
            self._teste_http_methods,
            self._teste_cors,
            self._teste_robots_txt
        ]

        for teste_func in testes:
            try:
                teste_func(url, resultados)
            except Exception as e:
                self.logger.debug(f"Erro no teste {teste_func.__name__}: {e}")

    def _teste_open_redirect(self, url: str, resultados: Dict):
        """Testa vulnerabilidades de open redirect"""
        payloads_redirect = [
            'http://evil.com',
            '//evil.com',
            'https://evil.com',
            'http://127.0.0.1'
        ]

        resultados['testes_realizados'].append('open_redirect')

        parsed = urlparse(url)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name in params.keys():
            for payload in payloads_redirect:
                test_url = self._construir_url_com_payload(url, param_name, payload)

                try:
                    response = self.session.get(test_url, timeout=self.timeout,
                                              verify=False, allow_redirects=False)

                    # Verificar se houve redirect para domínio malicioso
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if any(evil in location for evil in ['evil.com', '127.0.0.1']):
                            vulnerabilidade = {
                                'tipo': 'Open Redirect',
                                'severidade': 'media',
                                'url': test_url,
                                'parametro': param_name,
                                'payload': payload,
                                'evidencia': f'Redirect para {location}',
                                'categoria': 'open_redirect'
                            }
                            resultados['vulnerabilidades'].append(vulnerabilidade)

                except:
                    continue

    def _teste_directory_traversal(self, url: str, resultados: Dict):
        """Testa vulnerabilidades de directory traversal"""
        payloads_traversal = [
            '../../../etc/passwd',
            '..\\..\\..\\boot.ini',
            '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '....//....//....//etc/passwd'
        ]

        resultados['testes_realizados'].append('directory_traversal')

        parsed = urlparse(url)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name in params.keys():
            for payload in payloads_traversal:
                test_url = self._construir_url_com_payload(url, param_name, payload)

                try:
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)

                    # Verificar se conseguiu acessar arquivo do sistema
                    if response.status_code == 200:
                        content_lower = response.text.lower()
                        if any(indicator in content_lower for indicator in [
                            'root:', 'daemon:', '[boot loader]', 'system32'
                        ]):
                            vulnerabilidade = {
                                'tipo': 'Directory Traversal',
                                'severidade': 'alta',
                                'url': test_url,
                                'parametro': param_name,
                                'payload': payload,
                                'evidencia': 'Acesso a arquivo do sistema detectado',
                                'categoria': 'directory_traversal'
                            }
                            resultados['vulnerabilidades'].append(vulnerabilidade)
                            break

                except:
                    continue

    def _teste_http_methods(self, url: str, resultados: Dict):
        """Testa métodos HTTP perigosos"""
        metodos_perigosos = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']

        resultados['testes_realizados'].append('http_methods')

        for metodo in metodos_perigosos:
            try:
                response = self.session.request(metodo, url, timeout=self.timeout, verify=False)

                if response.status_code not in [405, 501]:  # Método não permitido
                    vulnerabilidade = {
                        'tipo': 'Método HTTP Perigoso Habilitado',
                        'severidade': 'baixa',
                        'url': url,
                        'metodo': metodo,
                        'status_code': response.status_code,
                        'evidencia': f'Método {metodo} habilitado',
                        'categoria': 'http_methods'
                    }
                    resultados['vulnerabilidades'].append(vulnerabilidade)

            except:
                continue

    def _teste_cors(self, url: str, resultados: Dict):
        """Testa configuração CORS"""
        resultados['testes_realizados'].append('cors')

        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)

            cors_header = response.headers.get('Access-Control-Allow-Origin', '')

            if cors_header == '*' or 'evil.com' in cors_header:
                vulnerabilidade = {
                    'tipo': 'CORS Mal Configurado',
                    'severidade': 'media',
                    'url': url,
                    'cors_header': cors_header,
                    'evidencia': 'CORS permite origens não confiáveis',
                    'categoria': 'cors'
                }
                resultados['vulnerabilidades'].append(vulnerabilidade)

        except:
            pass

    def _teste_robots_txt(self, url: str, resultados: Dict):
        """Testa exposição do robots.txt"""
        resultados['testes_realizados'].append('robots_txt')

        robots_url = urljoin(url, '/robots.txt')

        try:
            response = self.session.get(robots_url, timeout=self.timeout, verify=False)

            if response.status_code == 200:
                # Verificar se expõe caminhos sensíveis
                conteudo = response.text.lower()
                caminhos_sensiveis = ['admin', 'backup', 'config', 'private', 'secret']

                caminhos_expostos = []
                for linha in conteudo.split('\n'):
                    if linha.startswith('disallow:'):
                        caminho = linha.split(':', 1)[1].strip().lower()
                        for sensivel in caminhos_sensiveis:
                            if sensivel in caminho:
                                caminhos_expostos.append(caminho)
                                break

                if caminhos_expostos:
                    vulnerabilidade = {
                        'tipo': 'Informações Sensíveis em robots.txt',
                        'severidade': 'baixa',
                        'url': robots_url,
                        'caminhos_expostos': caminhos_expostos,
                        'evidencia': 'robots.txt expõe caminhos sensíveis',
                        'categoria': 'information_disclosure'
                    }
                    resultados['vulnerabilidades'].append(vulnerabilidade)

        except:
            pass

    def _analisar_resultados(self, resultados: Dict):
        """Analisa resultados e gera recomendações"""
        vulnerabilidades = resultados['vulnerabilidades']

        # Estatísticas
        severidades = {'alta': 0, 'media': 0, 'baixa': 0}
        tipos = {}

        for vuln in vulnerabilidades:
            sev = vuln.get('severidade', 'baixa')
            severidades[sev] += 1

            tipo = vuln.get('tipo', 'unknown')
            tipos[tipo] = tipos.get(tipo, 0) + 1

        resultados['estatisticas'] = {
            'total_vulnerabilidades': len(vulnerabilidades),
            'por_severidade': severidades,
            'por_tipo': tipos
        }

        # Recomendações baseadas nas vulnerabilidades encontradas
        recomendacoes = []

        if severidades['alta'] > 0:
            recomendacoes.append("🔴 CORREÇÃO IMEDIATA: Vulnerabilidades de alta severidade detectadas")
            recomendacoes.append("   - Implementar validação de entrada rigorosa")
            recomendacoes.append("   - Usar prepared statements para queries SQL")
            recomendacoes.append("   - Sanitizar todas as entradas do usuário")

        if severidades['media'] > 0:
            recomendacoes.append("🟡 CORREÇÃO RECOMENDADA: Vulnerabilidades de média severidade")
            recomendacoes.append("   - Implementar Content Security Policy (CSP)")
            recomendacoes.append("   - Configurar headers de segurança apropriados")
            recomendacoes.append("   - Validar redirects e includes")

        # Headers de segurança ausentes
        headers_ausentes = []
        for header, info in resultados['headers_seguranca'].items():
            if info['status'] == 'ausente' and info['criticidade'] in ['alta', 'media']:
                headers_ausentes.append(header)

        if headers_ausentes:
            recomendacoes.append("🛡️ Headers de Segurança Ausentes:")
            for header in headers_ausentes:
                recomendacoes.append(f"   - Adicionar header: {header}")

        resultados['recomendacoes'] = recomendacoes

    def salvar_resultados(self, resultado: Dict, formato: str = 'json', arquivo: str = None):
        """Salva resultados da análise em arquivo"""
        if not arquivo:
            parsed_url = urlparse(resultado['url'])
            dominio = parsed_url.netloc.replace('.', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            arquivo = f"analise_vuln_{dominio}_{timestamp}.{formato}"

        if formato == 'json':
            with open(arquivo, 'w', encoding='utf-8') as f:
                json.dump(resultado, f, indent=2, ensure_ascii=False)

        elif formato == 'txt':
            with open(arquivo, 'w', encoding='utf-8') as f:
                f.write(f"Análise de Vulnerabilidades Web - {resultado['url']}\\n")
                f.write(f"Total vulnerabilidades: {len(resultado['vulnerabilidades'])}\\n")
                f.write(f"Data: {resultado['timestamp']}\\n\\n")

                if resultado['vulnerabilidades']:
                    f.write("VULNERABILIDADES ENCONTRADAS:\\n")
                    for vuln in resultado['vulnerabilidades']:
                        sev_emoji = "🔴" if vuln['severidade'] == 'alta' else "🟡" if vuln['severidade'] == 'media' else "🟢"
                        f.write(f"{sev_emoji} [{vuln['severidade'].upper()}] {vuln['tipo']}\\n")
                        f.write(f"    URL: {vuln['url']}\\n")
                        if 'parametro' in vuln:
                            f.write(f"    Parâmetro: {vuln['parametro']}\\n")
                        if 'payload' in vuln:
                            f.write(f"    Payload: {vuln['payload']}\\n")
                        f.write(f"    Evidência: {vuln['evidencia']}\\n")
                        f.write("\\n")

                if resultado.get('recomendacoes'):
                    f.write("RECOMENDAÇÕES:\\n")
                    for rec in resultado['recomendacoes']:
                        f.write(f"• {rec}\\n")
                    f.write("\\n")

        self.logger.info(f"💾 Resultados salvos em: {arquivo}")


# Funções de compatibilidade
def analisar_vulnerabilidades(url: str) -> Dict:
    """Função de compatibilidade para análise básica"""
    analisador = AnalisadorVulnerabilidadesWeb()
    return analisador.analisar_url(url)

def analisar_vulnerabilidades_completo(url: str) -> Dict:
    """Função de compatibilidade para análise completa"""
    analisador = AnalisadorVulnerabilidadesWeb()
    return analisador.analisar_url(url, testes_completos=True, testar_payloads=True)


if __name__ == "__main__":
    # Teste do analisador
    analisador = AnalisadorVulnerabilidadesWeb()

    # Teste com URL de exemplo
    url_teste = "https://httpbin.org"

    print(f"🔍 Testando análise de vulnerabilidades em: {url_teste}")
    resultado = analisador.analisar_url(url_teste, testes_completos=False, testar_payloads=False)

    if 'erro' not in resultado:
        print(f"✅ Análise concluída: {len(resultado['vulnerabilidades'])} vulnerabilidades encontradas")
        print("\\n📋 Headers de segurança:")

        for header, info in resultado['headers_seguranca'].items():
            status_emoji = "✅" if info['status'] == 'presente' else "❌"
            print(f"  {status_emoji} {header}: {info['status']}")

        if resultado['vulnerabilidades']:
            print("\\n🚨 Vulnerabilidades encontradas:")
            for vuln in resultado['vulnerabilidades'][:3]:
                sev_emoji = "🔴" if vuln['severidade'] == 'alta' else "🟡" if vuln['severidade'] == 'media' else "🟢"
                print(f"  {sev_emoji} {vuln['tipo']} ({vuln['severidade']})")
    else:
        print(f"❌ Erro: {resultado['erro']}")
