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

    def executar_deteccao(self, alvo):
        """
        Executa a detecção de tecnologias no alvo especificado
        Args:
            alvo (str): URL ou IP do alvo
        Returns:
            dict: Resultados da detecção de tecnologias
        """
        self.logger.info(f"Iniciando detecção de tecnologias para: {alvo}")
        
        try:
            # Garantir que o alvo tenha protocolo
            if not alvo.startswith(('http://', 'https://')):
                url = f"http://{alvo}"
            else:
                url = alvo
                
            inicio = time.time()
            resultados = self._analisar_site(url)
            tempo_execucao = time.time() - inicio
            
            # Verificar headers de segurança
            headers_seguranca = self.verificar_headers_seguranca(url)
            
            return {
                'sucesso': True,
                'alvo': alvo,
                'tecnologias': resultados,
                'headers_seguranca': headers_seguranca,
                'tempo_execucao': tempo_execucao,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Erro na detecção de tecnologias: {str(e)}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            return {
                'sucesso': False,
                'alvo': alvo,
                'erro': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def _carregar_assinaturas(self):
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
                ]
            },
            'frameworks': {
                'Laravel': [
                    r'laravel_session',
                    r'Laravel [0-9]+\.[0-9]+',
                    r'XSRF-TOKEN'
                ],
                'Django': [
                    r'csrftoken',
                    r'django',
                    r'__debug__'
                ],
                'Flask': [
                    r'flask',
                    r'werkzeug',
                    r'jinja'
                ]
            }
        }
                
    def _analisar_site(self, url):
        """
        Analisa um site e detecta as tecnologias utilizadas
        Args:
            url (str): URL do site a ser analisado
        Returns:
            dict: Tecnologias detectadas por categoria
        """
        tecnologias = {}
        assinaturas = self._carregar_assinaturas()
        
        try:
            # Fazer requisição para o site
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            conteudo = resp.text.lower()
            headers = resp.headers
            
            # Detectar servidor web
            servidor = headers.get('Server', '')
            if servidor:
                tecnologias['servidor_web'] = servidor
                
            # Detectar linguagem de programação
            if 'php' in headers.get('X-Powered-By', '').lower():
                tecnologias['linguagem'] = 'PHP'
            elif 'asp.net' in headers.get('X-Powered-By', '').lower():
                tecnologias['linguagem'] = 'ASP.NET'
            elif 'jsessionid' in str(resp.cookies):
                tecnologias['linguagem'] = 'Java'
            
            # Detectar CMS
            for cms, padroes in assinaturas['cms'].items():
                for padrao in padroes:
                    if re.search(padrao, conteudo, re.IGNORECASE) or re.search(padrao, str(headers), re.IGNORECASE):
                        tecnologias['cms'] = cms
                        break
            
            # Detectar frameworks
            if 'frameworks' in assinaturas:
                for framework, padroes in assinaturas['frameworks'].items():
                    for padrao in padroes:
                        if re.search(padrao, conteudo, re.IGNORECASE) or re.search(padrao, str(headers), re.IGNORECASE):
                            tecnologias['framework'] = framework
                            break
            
            # Detectar frameworks de JavaScript
            if 'react' in conteudo or 'reactjs' in conteudo:
                tecnologias['frontend_framework'] = 'React'
            elif 'vue' in conteudo or 'vuejs' in conteudo:
                tecnologias['frontend_framework'] = 'Vue.js'
            elif 'angular' in conteudo:
                tecnologias['frontend_framework'] = 'Angular'
                
            # Detectar CDNs
            if 'cloudflare' in headers.get('CF-RAY', '').lower() or 'cloudflare' in servidor.lower():
                tecnologias['cdn'] = 'Cloudflare'
            elif 'akamai' in headers.get('Server', '').lower():
                tecnologias['cdn'] = 'Akamai'
            elif 'fastly' in headers.get('Via', '').lower():
                tecnologias['cdn'] = 'Fastly'
                
            return tecnologias
            
        except requests.RequestException as e:
            self.logger.error(f"Erro ao analisar site {url}: {e}")
            return {'erro': str(e)}
            
    def verificar_headers_seguranca(self, url):
        """Verifica headers de segurança no site"""
        headers_seguranca = {
            'X-XSS-Protection': 'não encontrado',
            'X-Content-Type-Options': 'não encontrado',
            'X-Frame-Options': 'não encontrado',
            'Content-Security-Policy': 'não encontrado',
            'Strict-Transport-Security': 'não encontrado',
        }
        
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            
            for header in headers_seguranca.keys():
                if header in resp.headers:
                    headers_seguranca[header] = resp.headers[header]
            
            return headers_seguranca
        except Exception as e:
            self.logger.error(f"Erro ao verificar headers de segurança: {str(e)}")
            return headers_seguranca
