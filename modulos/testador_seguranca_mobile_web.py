#!/usr/bin/env python3
"""
Módulo de Testes de Segurança de Aplicações Móveis/Web
Testa PWAs, configurações de segurança, certificados SSL, etc.
"""

import json
import time
import ssl
import socket
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
from utils.logger import obter_logger


class TestadorSegurancaMobileWeb:
    """Classe para testar segurança de aplicações móveis e web modernas"""

    def __init__(self):
        self.logger = obter_logger("TestadorMobileWeb")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36'
        })

    def testar_ssl_tls(self, url: str) -> Dict[str, Any]:
        """Testa configurações SSL/TLS"""
        self.logger.info(f"🔒 Testando SSL/TLS em: {url}")

        resultados = {
            'url': url,
            'tipo_teste': 'ssl_tls',
            'vulnerabilidades': [],
            'tempo_execucao': 0
        }

        inicio = time.time()

        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)

            # Testar certificado SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    if cert:
                        # Verificar validade do certificado
                        import datetime
                        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        now = datetime.datetime.now()

                        if now > not_after:
                            resultados['vulnerabilidades'].append({
                                'tipo': 'ssl_certificate_expired',
                                'severidade': 'alta',
                                'evidencia': f'Certificado expirado em: {cert["notAfter"]}'
                            })

                        # Verificar força da criptografia
                        cipher = ssock.cipher()
                        if cipher:
                            cipher_name = cipher[0]
                            if 'RC4' in cipher_name or 'DES' in cipher_name or '3DES' in cipher_name:
                                resultados['vulnerabilidades'].append({
                                    'tipo': 'weak_cipher_suite',
                                    'severidade': 'media',
                                    'evidencia': f'Cifra fraca detectada: {cipher_name}'
                                })

                        # Verificar se suporta TLS 1.2+
                        if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
                            try:
                                context_tls12 = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                                with socket.create_connection((hostname, port), timeout=5) as sock2:
                                    with context_tls12.wrap_socket(sock2, server_hostname=hostname):
                                        pass
                            except:
                                resultados['vulnerabilidades'].append({
                                    'tipo': 'outdated_tls_version',
                                    'severidade': 'media',
                                    'evidencia': 'Não suporta TLS 1.2 ou superior'
                                })

        except Exception as e:
            self.logger.error(f"Erro no teste SSL/TLS: {e}")
            resultados['erro'] = str(e)

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_pwa_manifest(self, url: str) -> Dict[str, Any]:
        """Testa configurações do manifest de PWA"""
        self.logger.info(f"📱 Testando PWA Manifest em: {url}")

        resultados = {
            'url': url,
            'tipo_teste': 'pwa_manifest',
            'vulnerabilidades': [],
            'tempo_execucao': 0
        }

        inicio = time.time()

        try:
            # Procurar manifest.json
            manifest_urls = [
                urljoin(url, 'manifest.json'),
                urljoin(url, 'site.webmanifest'),
                urljoin(url, 'app/manifest.json')
            ]

            manifest_encontrado = None

            for manifest_url in manifest_urls:
                try:
                    resposta = self.session.get(manifest_url, timeout=10)
                    if resposta.status_code == 200:
                        manifest_encontrado = resposta.json()
                        break
                except:
                    continue

            if manifest_encontrado:
                # Verificar configurações de segurança
                if 'scope' not in manifest_encontrado:
                    resultados['vulnerabilidades'].append({
                        'tipo': 'missing_scope',
                        'severidade': 'baixa',
                        'evidencia': 'PWA sem escopo definido'
                    })

                if 'start_url' not in manifest_encontrado:
                    resultados['vulnerabilidades'].append({
                        'tipo': 'missing_start_url',
                        'severidade': 'baixa',
                        'evidencia': 'PWA sem URL inicial definida'
                    })

                # Verificar permissões excessivas
                if 'permissions' in manifest_encontrado:
                    permissoes = manifest_encontrado['permissions']
                    permissoes_risco = ['geolocation', 'camera', 'microphone', 'notifications']

                    for perm in permissoes_risco:
                        if perm in permissoes:
                            resultados['vulnerabilidades'].append({
                                'tipo': 'excessive_permissions',
                                'severidade': 'media',
                                'evidencia': f'Permissão potencialmente arriscada: {perm}'
                            })

            else:
                resultados['vulnerabilidades'].append({
                    'tipo': 'missing_manifest',
                    'severidade': 'baixa',
                    'evidencia': 'PWA sem manifest.json'
                })

        except Exception as e:
            self.logger.error(f"Erro no teste PWA Manifest: {e}")
            resultados['erro'] = str(e)

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_service_worker(self, url: str) -> Dict[str, Any]:
        """Testa configurações do Service Worker"""
        self.logger.info(f"⚙️ Testando Service Worker em: {url}")

        resultados = {
            'url': url,
            'tipo_teste': 'service_worker',
            'vulnerabilidades': [],
            'tempo_execucao': 0
        }

        inicio = time.time()

        try:
            # Procurar service worker
            sw_urls = [
                urljoin(url, 'sw.js'),
                urljoin(url, 'service-worker.js'),
                urljoin(url, 'worker.js'),
                urljoin(url, 'js/sw.js')
            ]

            sw_encontrado = None

            for sw_url in sw_urls:
                try:
                    resposta = self.session.get(sw_url, timeout=10)
                    if resposta.status_code == 200:
                        sw_encontrado = resposta.text
                        break
                except:
                    continue

            if sw_encontrado:
                # Analisar código do service worker
                codigo_sw = sw_encontrado.lower()

                # Verificar se usa HTTPS
                if 'http:' in codigo_sw and 'https:' not in codigo_sw:
                    resultados['vulnerabilidades'].append({
                        'tipo': 'sw_insecure_requests',
                        'severidade': 'media',
                        'evidencia': 'Service Worker faz requisições HTTP inseguras'
                    })

                # Verificar se tem controle de cache excessivo
                if 'cache' in codigo_sw and 'unlimited' in codigo_sw:
                    resultados['vulnerabilidades'].append({
                        'tipo': 'excessive_caching',
                        'severidade': 'baixa',
                        'evidencia': 'Cache ilimitado no Service Worker'
                    })

                # Verificar se intercepta todas as requisições
                if 'fetch' in codigo_sw and 'event.respondwith' in codigo_sw:
                    if '*' in codigo_sw or 'all' in codigo_sw:
                        resultados['vulnerabilidades'].append({
                            'tipo': 'overbroad_interception',
                            'severidade': 'media',
                            'evidencia': 'Service Worker intercepta todas as requisições'
                        })

            else:
                resultados['vulnerabilidades'].append({
                    'tipo': 'missing_service_worker',
                    'severidade': 'baixa',
                    'evidencia': 'Aplicação sem Service Worker'
                })

        except Exception as e:
            self.logger.error(f"Erro no teste Service Worker: {e}")
            resultados['erro'] = str(e)

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_seguranca_mobile(self, url: str) -> Dict[str, Any]:
        """Testa configurações específicas para aplicações móveis"""
        self.logger.info(f"📱 Testando segurança mobile em: {url}")

        resultados = {
            'url': url,
            'tipo_teste': 'mobile_security',
            'vulnerabilidades': [],
            'tempo_execucao': 0
        }

        inicio = time.time()

        try:
            resposta = self.session.get(url, timeout=10)
            html = resposta.text.lower()

            # Verificar meta tags de segurança
            meta_tags_seguranca = [
                ('viewport', 'width=device-width'),
                ('x-ua-compatible', 'ie=edge'),
                ('referrer', 'strict-origin-when-cross-origin'),
                ('content-security-policy', ''),
                ('x-frame-options', 'deny'),
                ('x-content-type-options', 'nosniff')
            ]

            for meta_name, expected_value in meta_tags_seguranca:
                if expected_value:
                    if expected_value not in html:
                        resultados['vulnerabilidades'].append({
                            'tipo': 'missing_security_meta',
                            'severidade': 'baixa',
                            'evidencia': f'Meta tag de segurança ausente: {meta_name}'
                        })
                else:
                    # Para CSP, verificar se existe
                    if f'name="{meta_name}"' not in html and f'http-equiv="{meta_name}"' not in html:
                        resultados['vulnerabilidades'].append({
                            'tipo': 'missing_security_meta',
                            'severidade': 'media',
                            'evidencia': f'Cabeçalho de segurança ausente: {meta_name}'
                        })

            # Verificar se usa Web App Manifest
            if 'manifest' not in html:
                resultados['vulnerabilidades'].append({
                    'tipo': 'missing_web_app_manifest',
                    'severidade': 'baixa',
                    'evidencia': 'Aplicação sem Web App Manifest'
                })

            # Verificar se tem tema para mobile
            if 'theme-color' not in html:
                resultados['vulnerabilidades'].append({
                    'tipo': 'missing_theme_color',
                    'severidade': 'baixa',
                    'evidencia': 'Aplicação sem cor de tema definida'
                })

            # Verificar se tem apple-touch-icon
            if 'apple-touch-icon' not in html:
                resultados['vulnerabilidades'].append({
                    'tipo': 'missing_touch_icon',
                    'severidade': 'baixa',
                    'evidencia': 'Aplicação sem ícone de toque'
                })

        except Exception as e:
            self.logger.error(f"Erro no teste segurança mobile: {e}")
            resultados['erro'] = str(e)

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_seguranca_pwa(self, url: str) -> Dict[str, Any]:
        """Testa configurações específicas de PWA"""
        self.logger.info(f"🔄 Testando segurança PWA em: {url}")

        resultados = {
            'url': url,
            'tipo_teste': 'pwa_security',
            'vulnerabilidades': [],
            'tempo_execucao': 0
        }

        inicio = time.time()

        try:
            resposta = self.session.get(url, timeout=10)
            html = resposta.text.lower()

            # Verificar se está servindo sobre HTTPS
            if not url.startswith('https://'):
                resultados['vulnerabilidades'].append({
                    'tipo': 'pwa_not_https',
                    'severidade': 'alta',
                    'evidencia': 'PWA não está servindo sobre HTTPS'
                })

            # Verificar se tem service worker registrado
            if 'navigator.serviceworker' not in html and 'serviceworker' not in html:
                resultados['vulnerabilidades'].append({
                    'tipo': 'pwa_no_service_worker',
                    'severidade': 'media',
                    'evidencia': 'PWA sem registro de Service Worker'
                })

            # Verificar se tem tratamento de offline
            if 'fetch' not in html or 'cache' not in html:
                resultados['vulnerabilidades'].append({
                    'tipo': 'pwa_no_offline_support',
                    'severidade': 'baixa',
                    'evidencia': 'PWA sem suporte offline adequado'
                })

            # Verificar se tem push notifications seguras
            if 'push' in html and 'vapid' not in html:
                resultados['vulnerabilidades'].append({
                    'tipo': 'pwa_insecure_push',
                    'severidade': 'media',
                    'evidencia': 'Push notifications sem VAPID keys'
                })

        except Exception as e:
            self.logger.error(f"Erro no teste segurança PWA: {e}")
            resultados['erro'] = str(e)

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def testar_seguranca_hibrida(self, url: str) -> Dict[str, Any]:
        """Testa configurações para aplicações híbridas (Cordova/PhoneGap)"""
        self.logger.info(f"🔗 Testando segurança híbrida em: {url}")

        resultados = {
            'url': url,
            'tipo_teste': 'hybrid_security',
            'vulnerabilidades': [],
            'tempo_execucao': 0
        }

        inicio = time.time()

        try:
            resposta = self.session.get(url, timeout=10)
            html = resposta.text.lower()

            # Verificar se tem config.xml (Cordova/PhoneGap)
            config_urls = [
                urljoin(url, 'config.xml'),
                urljoin(url, 'res/config.xml')
            ]

            config_encontrado = False
            for config_url in config_urls:
                try:
                    resposta_config = self.session.get(config_url, timeout=5)
                    if resposta_config.status_code == 200:
                        config_encontrado = True
                        config_xml = resposta_config.text.lower()

                        # Verificar configurações de segurança no config.xml
                        if 'allow-navigation' in config_xml and '*' in config_xml:
                            resultados['vulnerabilidades'].append({
                                'tipo': 'cordova_allow_all_navigation',
                                'severidade': 'alta',
                                'evidencia': 'Cordova permite navegação para qualquer URL'
                            })

                        if 'allow-intent' in config_xml and '*' in config_xml:
                            resultados['vulnerabilidades'].append({
                                'tipo': 'cordova_allow_all_intents',
                                'severidade': 'alta',
                                'evidencia': 'Cordova permite todos os intents'
                            })

                        break
                except:
                    continue

            if not config_encontrado:
                # Verificar se usa APIs nativas inseguras
                if 'cordova.js' in html or 'phonegap.js' in html:
                    resultados['vulnerabilidades'].append({
                        'tipo': 'hybrid_without_config',
                        'severidade': 'media',
                        'evidencia': 'Aplicação híbrida sem config.xml adequado'
                    })

        except Exception as e:
            self.logger.error(f"Erro no teste segurança híbrida: {e}")
            resultados['erro'] = str(e)

        resultados['tempo_execucao'] = time.time() - inicio
        return resultados

    def executar_teste_completo_mobile_web(self, url: str) -> Dict[str, Any]:
        """Executa todos os testes de segurança mobile/web"""
        self.logger.info(f"🔬 Iniciando teste completo de segurança mobile/web: {url}")

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
            ('ssl_tls', self.testar_ssl_tls),
            ('pwa_manifest', self.testar_pwa_manifest),
            ('service_worker', self.testar_service_worker),
            ('mobile_security', self.testar_seguranca_mobile),
            ('pwa_security', self.testar_seguranca_pwa),
            ('hybrid_security', self.testar_seguranca_hibrida)
        ]

        for nome_teste, funcao_teste in testes:
            try:
                self.logger.info(f"Executando teste: {nome_teste}")
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

        self.logger.info(f"✅ Teste mobile/web finalizado: {resultados_completos['vulnerabilidades_totais']} vulnerabilidades encontradas")
        return resultados_completos


# Funções de compatibilidade para o sistema
def testar_seguranca_mobile_web(url: str) -> Dict[str, Any]:
    """Função de compatibilidade para testar segurança mobile/web"""
    testador = TestadorSegurancaMobileWeb()
    return testador.executar_teste_completo_mobile_web(url)


def testar_ssl_url(url: str) -> Dict[str, Any]:
    """Testa apenas SSL/TLS"""
    testador = TestadorSegurancaMobileWeb()
    return testador.testar_ssl_tls(url)


def testar_pwa_url(url: str) -> Dict[str, Any]:
    """Testa apenas configurações PWA"""
    testador = TestadorSegurancaMobileWeb()
    return testador.testar_pwa_manifest(url)


if __name__ == "__main__":
    # Exemplo de uso
    testador = TestadorSegurancaMobileWeb()

    # URL para teste
    url_teste = "https://localhost:8080"

    print("🧪 Testando segurança mobile/web...")

    # Teste completo
    resultado_completo = testador.executar_teste_completo_mobile_web(url_teste)
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
