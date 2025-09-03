"""
Plugin de Technology Detection
Detecta tecnologias e frameworks em aplicações web
"""

import requests
import time
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List
import re

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import WebPlugin, PluginResult


class TechnologyDetectorPlugin(WebPlugin):
    """Plugin para detecção de tecnologias web"""
    
    def __init__(self):
        super().__init__()
        self.description = "Detecção de tecnologias e frameworks web"
        self.version = "1.0.0"
        
        # Configurações
        self.timeout = 10
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Patterns para detecção de tecnologias
        self.tech_patterns = {
            # Servidores Web
            'Apache': {
                'headers': ['server'],
                'patterns': [r'apache', r'httpd']
            },
            'Nginx': {
                'headers': ['server'],
                'patterns': [r'nginx']
            },
            'IIS': {
                'headers': ['server'],
                'patterns': [r'microsoft-iis', r'iis']
            },
            
            # Linguagens Backend
            'PHP': {
                'headers': ['x-powered-by', 'server'],
                'patterns': [r'php', r'set-cookie.*PHPSESSID'],
                'content': [r'<?php']
            },
            'ASP.NET': {
                'headers': ['x-powered-by', 'server'],
                'patterns': [r'asp\.net', r'set-cookie.*ASP\.NET_SessionId']
            },
            'Python': {
                'headers': ['server', 'x-powered-by'],
                'patterns': [r'python', r'django', r'flask', r'gunicorn']
            },
            'Java': {
                'headers': ['server', 'x-powered-by'],
                'patterns': [r'tomcat', r'jetty', r'set-cookie.*JSESSIONID']
            },
            'Node.js': {
                'headers': ['x-powered-by', 'server'],
                'patterns': [r'express', r'node\.js']
            },
            
            # Frameworks JavaScript
            'jQuery': {
                'content': [r'jquery', r'/jquery[-.]?\d']
            },
            'React': {
                'content': [r'react', r'__REACT_DEVTOOLS_GLOBAL_HOOK__']
            },
            'Vue.js': {
                'content': [r'vue\.js', r'vue\s*=', r'__VUE__']
            },
            'Angular': {
                'content': [r'angular', r'ng-app', r'ng-controller']
            },
            'Bootstrap': {
                'content': [r'bootstrap', r'btn-primary', r'container-fluid']
            },
            
            # CMS
            'WordPress': {
                'content': [r'wp-content', r'wp-includes', r'/wp-json/', r'wordpress'],
                'headers': ['x-powered-by'],
                'patterns': [r'wordpress']
            },
            'Drupal': {
                'content': [r'drupal', r'sites/default/files', r'/sites/all/'],
                'headers': ['x-powered-by', 'x-drupal-cache']
            },
            'Joomla': {
                'content': [r'joomla', r'/media/jui/', r'/administrator/']
            },
            
            # E-commerce
            'Magento': {
                'content': [r'magento', r'/skin/frontend/', r'Mage\.Cookies']
            },
            'WooCommerce': {
                'content': [r'woocommerce', r'wc-', r'/woocommerce/']
            },
            'Shopify': {
                'content': [r'shopify', r'\.myshopify\.com', r'Shopify\.shop']
            },
            
            # Databases (via errors ou headers)
            'MySQL': {
                'content': [r'mysql', r'mysqld']
            },
            'PostgreSQL': {
                'content': [r'postgresql', r'postgres']
            },
            'MongoDB': {
                'content': [r'mongodb', r'mongo']
            }
        }
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa detecção de tecnologias"""
        start_time = time.time()
        
        try:
            url = self._normalize_url(target)
            
            if not self._is_accessible(url):
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error=f"URL não acessível: {url}"
                )
            
            # Coletar dados para análise
            page_data = self._collect_page_data(url)
            
            # Detectar tecnologias
            detected_technologies = self._detect_technologies(page_data)
            
            # Detectar versões se possível
            versioned_technologies = self._detect_versions(page_data, detected_technologies)
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    'url': url,
                    'technologies': versioned_technologies,
                    'raw_technologies': detected_technologies,
                    'confidence_scores': self._calculate_confidence_scores(page_data, detected_technologies)
                }
            )
            
        except Exception as e:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error=str(e)
            )
    
    def validate_target(self, target: str) -> bool:
        """Valida se é uma URL válida"""
        try:
            url = self._normalize_url(target)
            parsed = urlparse(url)
            return parsed.scheme in ['http', 'https'] and bool(parsed.netloc)
        except:
            return False
    
    def _normalize_url(self, target: str) -> str:
        """Normaliza para URL completa"""
        if not target.startswith(('http://', 'https://')):
            return f"https://{target}"
        return target
    
    def _is_accessible(self, url: str) -> bool:
        """Verifica se URL é acessível"""
        try:
            response = requests.head(url, headers=self.headers, timeout=5, verify=False)
            return response.status_code < 500
        except:
            return False
    
    def _collect_page_data(self, url: str) -> Dict[str, Any]:
        """Coleta dados da página para análise"""
        data = {
            'headers': {},
            'content': '',
            'status_code': 0,
            'cookies': {}
        }
        
        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            data['headers'] = dict(response.headers)
            data['content'] = response.text[:10000]  # Primeiros 10KB
            data['status_code'] = response.status_code
            data['cookies'] = dict(response.cookies)
            
        except Exception as e:
            data['error'] = str(e)
        
        return data
    
    def _detect_technologies(self, page_data: Dict[str, Any]) -> List[str]:
        """Detecta tecnologias baseado nos padrões"""
        detected = []
        headers = page_data.get('headers', {})
        content = page_data.get('content', '').lower()
        cookies = page_data.get('cookies', {})
        
        for tech_name, tech_config in self.tech_patterns.items():
            found = False
            
            # Verificar headers
            if 'headers' in tech_config and 'patterns' in tech_config:
                for header_name in tech_config['headers']:
                    header_value = headers.get(header_name, '').lower()
                    if header_value:
                        for pattern in tech_config['patterns']:
                            if re.search(pattern, header_value, re.IGNORECASE):
                                found = True
                                break
                    if found:
                        break
            
            # Verificar conteúdo
            if not found and 'content' in tech_config:
                for pattern in tech_config['content']:
                    if re.search(pattern, content, re.IGNORECASE):
                        found = True
                        break
            
            # Verificar cookies
            if not found and 'patterns' in tech_config:
                cookie_string = str(cookies).lower()
                for pattern in tech_config['patterns']:
                    if re.search(pattern, cookie_string, re.IGNORECASE):
                        found = True
                        break
            
            if found:
                detected.append(tech_name)
        
        return detected
    
    def _detect_versions(self, page_data: Dict[str, Any], technologies: List[str]) -> Dict[str, Dict[str, Any]]:
        """Tenta detectar versões das tecnologias encontradas"""
        versioned_tech = {}
        content = page_data.get('content', '')
        headers = page_data.get('headers', {})
        
        for tech in technologies:
            tech_info = {
                'name': tech,
                'version': 'unknown',
                'confidence': 'medium'
            }
            
            # Padrões específicos para detectar versões
            if tech == 'jQuery':
                version_match = re.search(r'jquery[/-](\d+\.\d+\.\d+)', content, re.IGNORECASE)
                if version_match:
                    tech_info['version'] = version_match.group(1)
                    tech_info['confidence'] = 'high'
            
            elif tech == 'WordPress':
                # Tentar detectar versão do WordPress
                version_match = re.search(r'wp-includes.*?ver=([0-9.]+)', content)
                if not version_match:
                    version_match = re.search(r'wordpress.*?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', content, re.IGNORECASE)
                if version_match:
                    tech_info['version'] = version_match.group(1)
                    tech_info['confidence'] = 'high'
            
            elif tech == 'Apache':
                server_header = headers.get('server', '')
                version_match = re.search(r'apache/([0-9.]+)', server_header, re.IGNORECASE)
                if version_match:
                    tech_info['version'] = version_match.group(1)
                    tech_info['confidence'] = 'high'
            
            elif tech == 'Nginx':
                server_header = headers.get('server', '')
                version_match = re.search(r'nginx/([0-9.]+)', server_header, re.IGNORECASE)
                if version_match:
                    tech_info['version'] = version_match.group(1)
                    tech_info['confidence'] = 'high'
            
            elif tech == 'PHP':
                powered_by = headers.get('x-powered-by', '')
                version_match = re.search(r'php/([0-9.]+)', powered_by, re.IGNORECASE)
                if version_match:
                    tech_info['version'] = version_match.group(1)
                    tech_info['confidence'] = 'high'
            
            versioned_tech[tech] = tech_info
        
        return versioned_tech
    
    def _calculate_confidence_scores(self, page_data: Dict[str, Any], technologies: List[str]) -> Dict[str, str]:
        """Calcula scores de confiança para as detecções"""
        confidence_scores = {}
        
        for tech in technologies:
            # Lógica simples de confiança
            # Alta: detectado em headers + conteúdo
            # Média: detectado só em uma fonte
            # Baixa: detecção ambígua
            
            score = 'medium'  # Default
            
            # Por simplicidade, mantemos medium para todos
            # Em uma implementação real, seria mais sofisticado
            confidence_scores[tech] = score
        
        return confidence_scores
