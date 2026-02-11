"""
Plugin de Scanner Web
Verifica serviços HTTP/HTTPS e coleta informações básicas
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
from utils.http_session import create_requests_session


class WebScannerPlugin(WebPlugin):
    """Plugin para análise básica de aplicações web"""
    
    def __init__(self):
        super().__init__()
        self.description = "Scanner básico de aplicações web"
        self.version = "1.0.0"
        
        # Configurações
        self.timeout = 10
        self.max_redirects = 5
        
        # Headers para parecer um browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Diretórios comuns para testar
        self.common_dirs = [
            '/', '/admin', '/login', '/api', '/docs', '/wp-admin',
            '/phpmyadmin', '/robots.txt', '/sitemap.xml', '/favicon.ico'
        ]
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa scanning web"""
        start_time = time.time()
        
        try:
            session = create_requests_session(plugin_config=self.config, headers=self.headers)
            actual_target = context.get('original_target', target)

            # Normalizar URL
            url = self._normalize_url(actual_target)
            
            # Verificar se é acessível
            if not self._is_web_accessible(session, url):
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error=f"URL não acessível: {url}"
                )
            
            # Coletar informações básicas
            info = self._collect_basic_info(session, url)
            
            # Testar diretórios comuns
            directories = self._test_common_directories(session, url)
            
            # Buscar tecnologias
            technologies = self._detect_technologies(info.get('headers', {}), info.get('content', ''))
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    'url': url,
                    'basic_info': info,
                    'directories_found': directories,
                    'technologies': technologies,
                    'services': [{
                        'service': 'HTTP/HTTPS',
                        'host': urlparse(url).hostname,
                        'port': urlparse(url).port or (443 if url.startswith('https') else 80)
                    }]
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
        """Valida se o target é uma URL válida"""
        try:
            url = self._normalize_url(target)
            parsed = urlparse(url)
            return parsed.scheme in ['http', 'https'] and bool(parsed.netloc)
        except:
            return False
    
    def _normalize_url(self, target: str) -> str:
        """Normaliza target para URL completa"""
        if not target.startswith(('http://', 'https://')):
            # Tentar HTTPS primeiro
            return f"https://{target}"
        return target
    
    def _is_web_accessible(self, session: requests.Session, url: str) -> bool:
        """Verifica se a URL é acessível"""
        try:
            response = session.head(
                url, 
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            return response.status_code < 500
        except:
            # Tentar HTTP se HTTPS falhar
            if url.startswith('https://'):
                http_url = url.replace('https://', 'http://')
                try:
                    response = session.head(
                        http_url,
                        headers=self.headers,
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                    return response.status_code < 500
                except:
                    return False
            return False
    
    def _collect_basic_info(self, session: requests.Session, url: str) -> Dict[str, Any]:
        """Coleta informações básicas da página"""
        try:
            response = session.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'content': response.text[:1000],  # Primeiros 1000 chars
                'final_url': response.url,
                'redirects': len(response.history)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _test_common_directories(self, session: requests.Session, base_url: str) -> List[Dict[str, Any]]:
        """Testa diretórios comuns"""
        found_dirs = []
        
        for directory in self.common_dirs:
            try:
                url = urljoin(base_url, directory)
                response = session.head(
                    url,
                    headers=self.headers,
                    timeout=5,
                    allow_redirects=False,
                    verify=False
                )
                
                if response.status_code < 400:
                    found_dirs.append({
                        'path': directory,
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': response.headers.get('Content-Length', 'unknown')
                    })
                    
            except:
                continue
        
        return found_dirs
    
    def _detect_technologies(self, headers: Dict[str, str], content: str) -> List[str]:
        """Detecta tecnologias baseado em headers e conteúdo"""
        technologies = []
        
        # Detectar pelo header Server
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        
        # Detectar pelo header X-Powered-By
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        elif 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        
        # Detectar pelo conteúdo
        content_lower = content.lower()
        
        # Frameworks JavaScript
        if 'jquery' in content_lower:
            technologies.append('jQuery')
        if 'bootstrap' in content_lower:
            technologies.append('Bootstrap')
        if 'react' in content_lower:
            technologies.append('React')
        if 'angular' in content_lower:
            technologies.append('Angular')
        if 'vue' in content_lower:
            technologies.append('Vue.js')
        
        # CMS
        if 'wp-content' in content_lower or 'wordpress' in content_lower:
            technologies.append('WordPress')
        if 'drupal' in content_lower:
            technologies.append('Drupal')
        if 'joomla' in content_lower:
            technologies.append('Joomla')
        
        # Outros
        if 'generator' in content_lower and 'wordpress' in content_lower:
            technologies.append('WordPress')
        
        return list(set(technologies))  # Remove duplicatas
