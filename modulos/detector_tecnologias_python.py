#!/usr/bin/env python3
"""
Detector de Tecnologias Web em Python
Substituto para WhatWeb - Detector de tecnologias web eficiente em Python puro
"""

import requests
import re
import hashlib
import time
from typing import Dict, List, Optional, Set
from datetime import datetime
from urllib.parse import urlparse, urljoin
import json

from utils.logger import obter_logger


class DetectorTecnologiasPython:
    """Detector de tecnologias web eficiente em Python puro"""

    def __init__(self):
        self.logger = obter_logger("TechDetector")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.timeout = 10

        # Assinaturas de tecnologias
        self.assinaturas = self._carregar_assinaturas()

    def _carregar_assinaturas(self) -> Dict:
        """Carrega assinaturas para detecção de tecnologias"""
        return {
            'cms': {
                'WordPress': [
                    r'wp-content|wp-includes|wp-admin',
                    r'WordPress [0-9]+\.[0-9]+',
                    r'generator.*WordPress'
                ],
                'Joomla': [
                    r'Joomla! [0-9]+\.[0-9]+',
                    r'com_content|com_users',
                    r'option=com_'
                ],
                'Drupal': [
                    r'Drupal [0-9]+',
                    r'node/[0-9]+',
                    r'drupal\.js|drupal\.css'
                ],
                'Magento': [
                    r'Magento [0-9]+\.[0-9]+',
                    r'var FORM_KEY',
                    r'skin/frontend'
                ],
                'PrestaShop': [
                    r'PrestaShop [0-9]+\.[0-9]+',
                    r'id_product=|id_category=',
                    r'prestashop\.css'
                ]
            },

            'frameworks': {
                'Laravel': [
                    r'Laravel [0-9]+\.[0-9]+',
                    r'_token.*csrf',
                    r'artisan'
                ],
                'Django': [
                    r'Django [0-9]+\.[0-9]+',
                    r'csrfmiddlewaretoken',
                    r'django\.js'
                ],
                'Ruby on Rails': [
                    r'Rails [0-9]+\.[0-9]+',
                    r'rails\.js|application\.js',
                    r'csrf-token'
                ],
                'ASP.NET': [
                    r'ASP\.NET [0-9]+\.[0-9]+',
                    r'__VIEWSTATE|__EVENTVALIDATION',
                    r'\.aspx|\.ashx'
                ],
                'Spring': [
                    r'Spring Framework [0-9]+\.[0-9]+',
                    r'spring\.js|spring\.css',
                    r'java\.lang'
                ],
                'Express.js': [
                    r'Express|express\.js',
                    r'X-Powered-By.*Express',
                    r'connect\.js'
                ],
                'Flask': [
                    r'Flask [0-9]+\.[0-9]+',
                    r'Werkzeug [0-9]+\.[0-9]+',
                    r'flask\.js'
                ]
            },

            'servidores': {
                'Apache': [
                    r'Apache/[0-9]+\.[0-9]+',
                    r'Server.*Apache',
                    r'mod_ssl|mod_rewrite'
                ],
                'Nginx': [
                    r'nginx/[0-9]+\.[0-9]+',
                    r'Server.*nginx',
                    r'X-Nginx'
                ],
                'IIS': [
                    r'Microsoft-IIS/[0-9]+\.[0-9]+',
                    r'Server.*IIS',
                    r'X-AspNet-Version'
                ],
                'LiteSpeed': [
                    r'LiteSpeed',
                    r'X-LiteSpeed'
                ],
                'Tomcat': [
                    r'Apache Tomcat/[0-9]+\.[0-9]+',
                    r'X-Powered-By.*Tomcat'
                ]
            },

            'linguagens': {
                'PHP': [
                    r'PHP/[0-9]+\.[0-9]+',
                    r'X-Powered-By.*PHP',
                    r'\.php|\.phtml'
                ],
                'Python': [
                    r'Python/[0-9]+\.[0-9]+',
                    r'X-Powered-By.*Python',
                    r'\.py'
                ],
                'Node.js': [
                    r'Node\.js|node/[0-9]+\.[0-9]+',
                    r'X-Powered-By.*Node',
                    r'npm|package\.json'
                ],
                'Java': [
                    r'Java/[0-9]+\.[0-9]+',
                    r'X-Powered-By.*Java',
                    r'\.jsp|\.java'
                ],
                'Ruby': [
                    r'Ruby/[0-9]+\.[0-9]+',
                    r'X-Powered-By.*Ruby',
                    r'\.rb|rails'
                ]
            },

            'banco_dados': {
                'MySQL': [
                    r'mysql_connect|mysqli_connect',
                    r'MySQL [0-9]+\.[0-9]+',
                    r'error.*mysql'
                ],
                'PostgreSQL': [
                    r'pg_connect|pgsql',
                    r'PostgreSQL [0-9]+\.[0-9]+',
                    r'error.*postgres'
                ],
                'MongoDB': [
                    r'mongodb|mongo\.js',
                    r'MongoDB [0-9]+\.[0-9]+'
                ],
                'Redis': [
                    r'redis|Redis [0-9]+\.[0-9]+'
                ]
            },

            'javascript': {
                'jQuery': [
                    r'jquery[-.]?[0-9]+\.[0-9]+\.[0-9]+',
                    r'jQuery JavaScript Library'
                ],
                'React': [
                    r'react[-.]?[0-9]+\.[0-9]+\.[0-9]+',
                    r'react\.js|react\.min\.js'
                ],
                'Angular': [
                    r'angular[-.]?[0-9]+\.[0-9]+\.[0-9]+',
                    r'ng-app|angular\.js'
                ],
                'Vue.js': [
                    r'vue[-.]?[0-9]+\.[0-9]+\.[0-9]+',
                    r'vue\.js'
                ],
                'Bootstrap': [
                    r'bootstrap[-.]?[0-9]+\.[0-9]+\.[0-9]+',
                    r'bootstrap\.css|bootstrap\.js'
                ]
            },

            'analytics': {
                'Google Analytics': [
                    r'google-analytics\.com|googletagmanager\.com',
                    r'GA_TRACKING_ID|gtag'
                ],
                'Facebook Pixel': [
                    r'connect\.facebook\.net|facebook\.com/tr',
                    r'fbq\('
                ],
                'Hotjar': [
                    r'hotjar|static\.hotjar\.com'
                ]
            }
        }

    def detectar_tecnologias(self, url: str, verificar_arquivos: bool = True) -> Dict:
        """
        Detecta tecnologias usadas no site

        Args:
            url: URL do site alvo
            verificar_arquivos: Verificar arquivos específicos

        Returns:
            Dict com tecnologias detectadas
        """
        self.logger.info(f"🔍 Detectando tecnologias em: {url}")

        inicio = time.time()

        try:
            # Normalizar URL
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'

            tecnologias = {
                'url_alvo': url,
                'cms': [],
                'frameworks': [],
                'servidores': [],
                'linguagens': [],
                'banco_dados': [],
                'javascript': [],
                'analytics': [],
                'outros': [],
                'headers': {},
                'cookies': {},
                'timestamp': datetime.now().isoformat()
            }

            # 1. Analisar resposta principal
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                tecnologias['status_code'] = response.status_code
                tecnologias['headers'] = dict(response.headers)
                tecnologias['cookies'] = dict(response.cookies)

                # Detectar por headers
                self._detectar_por_headers(tecnologias, response.headers)

                # Detectar por conteúdo HTML
                if response.text:
                    self._detectar_por_conteudo(tecnologias, response.text)

            except Exception as e:
                self.logger.warning(f"Erro ao acessar URL principal: {e}")
                tecnologias['erro_principal'] = str(e)

            # 2. Verificar arquivos específicos
            if verificar_arquivos:
                self._verificar_arquivos_especificos(url, tecnologias)

            # 3. Verificar robots.txt
            self._verificar_robots_txt(url, tecnologias)

            # 4. Calcular confiança
            self._calcular_confianca(tecnologias)

            duracao = time.time() - inicio
            tecnologias['duracao_analise'] = round(duracao, 2)

            self.logger.info(f"✅ Detecção concluída: {sum(len(v) for v in tecnologias.values() if isinstance(v, list))} tecnologias encontradas")
            return tecnologias

        except Exception as e:
            self.logger.error(f"❌ Erro na detecção: {e}")
            return {
                'url_alvo': url,
                'erro': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def _detectar_por_headers(self, tecnologias: Dict, headers: Dict):
        """Detecta tecnologias pelos headers HTTP"""
        headers_str = '\\n'.join(f"{k}: {v}" for k, v in headers.items())

        for categoria, techs in self.assinaturas.items():
            for tech, patterns in techs.items():
                for pattern in patterns:
                    if re.search(pattern, headers_str, re.IGNORECASE):
                        if tech not in tecnologias[categoria]:
                            tecnologias[categoria].append(tech)
                            self.logger.debug(f"📋 Tecnologia detectada por header: {tech}")
                        break

    def _detectar_por_conteudo(self, tecnologias: Dict, conteudo: str):
        """Detecta tecnologias pelo conteúdo da página"""
        # Verificar por metatags generator
        generator_match = re.search(r'<meta name="generator" content="([^"]+)"', conteudo, re.IGNORECASE)
        if generator_match:
            generator = generator_match.group(1)
            if 'WordPress' in generator:
                tecnologias['cms'].append('WordPress')
            elif 'Joomla' in generator:
                tecnologias['cms'].append('Joomla')
            elif 'Drupal' in generator:
                tecnologias['cms'].append('Drupal')

        # Verificar por comentários HTML
        comments = re.findall(r'<!--.*?-->', conteudo, re.DOTALL)
        for comment in comments:
            for categoria, techs in self.assinaturas.items():
                for tech, patterns in techs.items():
                    for pattern in patterns:
                        if re.search(pattern, comment, re.IGNORECASE):
                            if tech not in tecnologias[categoria]:
                                tecnologias[categoria].append(tech)
                            break

        # Verificar por scripts e links
        scripts = re.findall(r'<script[^>]*src="([^"]+)"', conteudo, re.IGNORECASE)
        links = re.findall(r'<link[^>]*href="([^"]+)"', conteudo, re.IGNORECASE)

        for url in scripts + links:
            for categoria, techs in self.assinaturas.items():
                for tech, patterns in techs.items():
                    for pattern in patterns:
                        if re.search(pattern, url, re.IGNORECASE):
                            if tech not in tecnologias[categoria]:
                                tecnologias[categoria].append(tech)
                            break

        # Verificar por fingerprints gerais
        for categoria, techs in self.assinaturas.items():
            for tech, patterns in techs.items():
                for pattern in patterns:
                    if re.search(pattern, conteudo, re.IGNORECASE):
                        if tech not in tecnologias[categoria]:
                            tecnologias[categoria].append(tech)
                            self.logger.debug(f"📋 Tecnologia detectada por conteúdo: {tech}")
                        break

    def _verificar_arquivos_especificos(self, url: str, tecnologias: Dict):
        """Verifica arquivos específicos que revelam tecnologias"""
        arquivos_teste = [
            '/wp-admin/', '/administrator/', '/admin/', '/phpmyadmin/',
            '/wp-content/', '/wp-includes/', '/joomla/', '/drupal/',
            '/readme.txt', '/changelog.txt', '/composer.json', '/package.json',
            '/web.config', '/crossdomain.xml', '/clientaccesspolicy.xml'
        ]

        for arquivo in arquivos_teste:
            try:
                test_url = urljoin(url, arquivo)
                response = self.session.get(test_url, timeout=5, verify=False)

                if response.status_code == 200:
                    # WordPress
                    if '/wp-admin/' in arquivo or '/wp-content/' in arquivo:
                        if 'WordPress' not in tecnologias['cms']:
                            tecnologias['cms'].append('WordPress')
                    # Joomla
                    elif '/administrator/' in arquivo:
                        if 'Joomla' not in tecnologias['cms']:
                            tecnologias['cms'].append('Joomla')
                    # Drupal
                    elif '/drupal/' in arquivo:
                        if 'Drupal' not in tecnologias['cms']:
                            tecnologias['cms'].append('Drupal')
                    # PHP
                    elif arquivo.endswith('.php'):
                        if 'PHP' not in tecnologias['linguagens']:
                            tecnologias['linguagens'].append('PHP')
                    # Node.js
                    elif arquivo == '/package.json':
                        if 'Node.js' not in tecnologias['linguagens']:
                            tecnologias['linguagens'].append('Node.js')

            except:
                continue

    def _verificar_robots_txt(self, url: str, tecnologias: Dict):
        """Verifica robots.txt para pistas sobre tecnologias"""
        try:
            robots_url = urljoin(url, '/robots.txt')
            response = self.session.get(robots_url, timeout=5, verify=False)

            if response.status_code == 200:
                conteudo = response.text

                # Verificar por caminhos específicos
                if 'wp-admin' in conteudo or 'wp-content' in conteudo:
                    if 'WordPress' not in tecnologias['cms']:
                        tecnologias['cms'].append('WordPress')
                elif 'administrator' in conteudo:
                    if 'Joomla' not in tecnologias['cms']:
                        tecnologias['cms'].append('Joomla')

        except:
            pass

    def _calcular_confianca(self, tecnologias: Dict):
        """Calcula nível de confiança para detecções"""
        total_deteccoes = sum(len(v) for v in tecnologias.values() if isinstance(v, list))

        if total_deteccoes == 0:
            tecnologias['confianca'] = 'baixa'
        elif total_deteccoes <= 3:
            tecnologias['confianca'] = 'media'
        else:
            tecnologias['confianca'] = 'alta'

    def salvar_resultados(self, resultado: Dict, formato: str = 'json', arquivo: str = None):
        """Salva resultados da detecção em arquivo"""
        if not arquivo:
            parsed_url = urlparse(resultado['url_alvo'])
            dominio = parsed_url.netloc.replace('.', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            arquivo = f"tecnologias_{dominio}_{timestamp}.{formato}"

        if formato == 'json':
            with open(arquivo, 'w', encoding='utf-8') as f:
                json.dump(resultado, f, indent=2, ensure_ascii=False)

        elif formato == 'txt':
            with open(arquivo, 'w', encoding='utf-8') as f:
                f.write(f"Detecção de Tecnologias - {resultado['url_alvo']}\\n")
                f.write(f"Confiança: {resultado.get('confianca', 'N/A')}\\n")
                f.write(f"Data: {resultado['timestamp']}\\n\\n")

                for categoria, techs in resultado.items():
                    if isinstance(techs, list) and techs:
                        f.write(f"{categoria.upper()}:\\n")
                        for tech in techs:
                            f.write(f"  • {tech}\\n")
                        f.write("\\n")

        self.logger.info(f"💾 Resultados salvos em: {arquivo}")


# Funções de compatibilidade
def detectar_tecnologias(url: str) -> Dict:
    """Função de compatibilidade para detecção básica"""
    detector = DetectorTecnologiasPython()
    return detector.detectar_tecnologias(url)

def detectar_tecnologias_completo(url: str) -> Dict:
    """Função de compatibilidade para detecção completa"""
    detector = DetectorTecnologiasPython()
    return detector.detectar_tecnologias(url, verificar_arquivos=True)


if __name__ == "__main__":
    # Teste do detector
    detector = DetectorTecnologiasPython()

    # Teste com site conhecido
    url_teste = "https://wordpress.com"

    print(f"🔍 Testando detecção de tecnologias em: {url_teste}")
    resultado = detector.detectar_tecnologias(url_teste)

    if 'erro' not in resultado:
        print(f"✅ Detecção concluída com confiança: {resultado.get('confianca', 'N/A')}")
        print("\\n📋 Tecnologias detectadas:")

        for categoria, techs in resultado.items():
            if isinstance(techs, list) and techs:
                print(f"\\n{categoria.upper()}:")
                for tech in techs:
                    print(f"  • {tech}")
    else:
        print(f"❌ Erro: {resultado['erro']}")
