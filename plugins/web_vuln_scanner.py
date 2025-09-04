"""
Plugin de Detecção de Vulnerabilidades Web
Verifica vulnerabilidades comuns em aplicações web
"""

import requests
import time
from urllib.parse import urljoin, urlparse
from typing import Dict, Any, List
import re

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import VulnerabilityPlugin, PluginResult


class WebVulnScannerPlugin(VulnerabilityPlugin):
    """Plugin para detecção de vulnerabilidades web básicas"""
    
    def __init__(self):
        super().__init__()
        self.description = "Scanner de vulnerabilidades web comuns"
        self.version = "1.0.0"
        self.category = "vulnerability"
        self.supported_targets = ["url", "domain"]
        
        # Configurações
        self.timeout = 15
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Payloads para testes
        self.xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "';alert('XSS');//"
        ]
        
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users;--",
            "1' UNION SELECT null,null,null--"
        ]
        
        self.lfi_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "php://filter/read=convert.base64-encode/resource=index.php"
        ]
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa scanning de vulnerabilidades web"""
        start_time = time.time()
        
        try:
            # Buscar URLs acessíveis baseadas no contexto
            accessible_urls = self._find_accessible_urls(target, context)
            
            if not accessible_urls:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error=f"Nenhuma URL web acessível encontrada para: {target}"
                )
            
            all_vulnerabilities = []
            tested_urls = []
            
            # Testar cada URL encontrada
            for url in accessible_urls:
                tested_urls.append(url)
                vulnerabilities = []
                
                # Testes de segurança básicos
                vulnerabilities.extend(self._test_security_headers(url))
                vulnerabilities.extend(self._test_directory_traversal(url))
                vulnerabilities.extend(self._test_sql_injection(url))
                vulnerabilities.extend(self._test_xss_reflection(url))
                vulnerabilities.extend(self._test_sensitive_files(url))
                
                all_vulnerabilities.extend(vulnerabilities)
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    'target': target,
                    'tested_urls': tested_urls,
                    'vulnerabilities': all_vulnerabilities,
                    'vulnerabilities_count': len(all_vulnerabilities),
                    'tests_performed': [
                        'security_headers', 'directory_traversal', 
                        'sql_injection', 'xss_reflection', 'sensitive_files'
                    ]
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
    
    def _find_accessible_urls(self, target: str, context: Dict[str, Any]) -> List[str]:
        """Encontra URLs web acessíveis baseadas no contexto"""
        accessible_urls = []
        
        # Lista de portas web comuns para testar
        web_ports = [80, 443, 8000, 8080, 8443, 9000, 9443, 3000]
        
        # Tentar descobrir portas do contexto
        discovered_ports = []
        
        # Buscar portas descobertas no contexto
        if 'discoveries' in context:
            discoveries = context['discoveries']
            
            # Buscar hosts e portas
            if 'hosts' in discoveries:
                for host_info in discoveries.get('hosts', []):
                    if isinstance(host_info, dict) and 'ports' in host_info:
                        for port_info in host_info['ports']:
                            port = port_info.get('port')
                            service = port_info.get('service', '').lower()
                            
                            # Verificar se é porta web
                            if port in web_ports or any(web_service in service for web_service in ['http', 'web', 'apache', 'nginx']):
                                discovered_ports.append(port)
        
        # Adicionar portas padrão se nenhuma foi descoberta
        if not discovered_ports:
            discovered_ports = [80, 443, 8000, 8080]
        
        # Gerar URLs para testar
        host = target.replace('http://', '').replace('https://', '').split('/')[0]
        
        for port in discovered_ports:
            # Determinar protocolo baseado na porta
            if port in [443, 8443, 9443]:
                urls_to_test = [f"https://{host}:{port}", f"https://{host}"]
            else:
                urls_to_test = [f"http://{host}:{port}", f"http://{host}"]
            
            for url in urls_to_test:
                if self._is_accessible(url):
                    accessible_urls.append(url)
                    break  # Para evitar duplicatas para o mesmo host
        
        # Se ainda não encontrou nada, tentar URLs básicas
        if not accessible_urls:
            basic_urls = [
                f"http://{host}",
                f"https://{host}",
                f"http://{host}:80",
                f"http://{host}:8000",
                f"http://{host}:8080"
            ]
            
            for url in basic_urls:
                if self._is_accessible(url):
                    accessible_urls.append(url)
        
        return list(set(accessible_urls))  # Remover duplicatas
    
    def _is_accessible(self, url: str) -> bool:
        """Verifica se URL é acessível"""
        try:
            # Primeiro tenta HEAD
            response = requests.head(
                url, 
                headers=self.headers, 
                timeout=5, 
                verify=False,
                allow_redirects=True
            )
            if response.status_code < 500:
                return True
        except:
            pass
        
        try:
            # Se HEAD falhar, tenta GET
            response = requests.get(
                url, 
                headers=self.headers, 
                timeout=5, 
                verify=False,
                allow_redirects=True
            )
            return response.status_code < 500
        except:
            return False
    
    def _test_security_headers(self, url: str) -> List[Dict[str, Any]]:
        """Testa headers de segurança"""
        vulnerabilities = []
        
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            headers = response.headers
            
            # Headers de segurança importantes
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'X-XSS-Protection': 'XSS filter',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content Security Policy'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'severity': 'Medium',
                        'description': f'Missing {header} header - {description}',
                        'recommendation': f'Add {header} header to improve security',
                        'location': url
                    })
            
            # Verificar se servidor expõe informações sensíveis
            server_header = headers.get('Server', '')
            if server_header and any(tech in server_header.lower() for tech in ['apache/', 'nginx/', 'iis/']):
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'description': f'Server header reveals technology: {server_header}',
                    'recommendation': 'Remove or obfuscate Server header',
                    'location': url
                })
                
        except Exception as e:
            pass  # Falhar silenciosamente
        
        return vulnerabilities
    
    def _test_directory_traversal(self, url: str) -> List[Dict[str, Any]]:
        """Testa vulnerabilidades de directory traversal"""
        vulnerabilities = []
        
        # URLs comuns que podem ter parâmetros de arquivo
        test_params = ['file', 'page', 'include', 'template', 'path', 'doc']
        
        for param in test_params:
            for payload in self.lfi_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = requests.get(
                        test_url, 
                        headers=self.headers, 
                        timeout=5, 
                        verify=False
                    )
                    
                    content = response.text.lower()
                    
                    # Indicadores de sucesso em LFI
                    if any(indicator in content for indicator in [
                        'root:x:', 'bin/bash', '[fonts]', 'windows nt'
                    ]):
                        vulnerabilities.append({
                            'type': 'Local File Inclusion',
                            'severity': 'High',
                            'description': f'Possible LFI vulnerability in parameter {param}',
                            'payload': payload,
                            'recommendation': 'Validate and sanitize file path parameters',
                            'location': test_url
                        })
                        break  # Para evitar duplicatas
                        
                except:
                    continue
        
        return vulnerabilities
    
    def _test_sql_injection(self, url: str) -> List[Dict[str, Any]]:
        """Testa vulnerabilidades de SQL injection"""
        vulnerabilities = []
        
        # Parâmetros comuns para testar
        test_params = ['id', 'user', 'search', 'query', 'cat', 'category']
        
        for param in test_params:
            for payload in self.sqli_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = requests.get(
                        test_url,
                        headers=self.headers,
                        timeout=10,
                        verify=False
                    )
                    
                    content = response.text.lower()
                    
                    # Indicadores de erro SQL
                    sql_errors = [
                        'sql syntax', 'mysql_fetch', 'ora-01756', 'microsoft ole db',
                        'unclosed quotation mark', 'sqlite_error', 'warning: mysql'
                    ]
                    
                    if any(error in content for error in sql_errors):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'description': f'Possible SQL injection in parameter {param}',
                            'payload': payload,
                            'recommendation': 'Use parameterized queries and input validation',
                            'location': test_url
                        })
                        break
                        
                except:
                    continue
        
        return vulnerabilities
    
    def _test_xss_reflection(self, url: str) -> List[Dict[str, Any]]:
        """Testa XSS por reflexão"""
        vulnerabilities = []
        
        test_params = ['q', 'search', 'query', 'name', 'message']
        
        for param in test_params:
            for payload in self.xss_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = requests.get(
                        test_url,
                        headers=self.headers,
                        timeout=10,
                        verify=False
                    )
                    
                    # Verificar se payload foi refletido sem escape
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'severity': 'Medium',
                            'description': f'Possible reflected XSS in parameter {param}',
                            'payload': payload,
                            'recommendation': 'Encode user input and implement CSP',
                            'location': test_url
                        })
                        break
                        
                except:
                    continue
        
        return vulnerabilities
    
    def _test_sensitive_files(self, url: str) -> List[Dict[str, Any]]:
        """Testa acesso a arquivos sensíveis"""
        vulnerabilities = []
        
        sensitive_files = [
            '.env', '.git/config', 'config.php', 'wp-config.php',
            'database.yml', 'settings.py', 'web.config', 
            'phpinfo.php', 'info.php', 'test.php'
        ]
        
        for file_path in sensitive_files:
            try:
                test_url = urljoin(url, file_path)
                response = requests.get(
                    test_url,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                if response.status_code == 200 and len(response.content) > 100:
                    content = response.text.lower()
                    
                    # Verificar conteúdo sensível
                    sensitive_patterns = [
                        'password', 'secret', 'api_key', 'private_key',
                        'database', 'mysql', 'postgresql', 'mongodb'
                    ]
                    
                    if any(pattern in content for pattern in sensitive_patterns):
                        vulnerabilities.append({
                            'type': 'Sensitive File Exposure',
                            'severity': 'High',
                            'description': f'Sensitive file accessible: {file_path}',
                            'recommendation': 'Restrict access to sensitive files',
                            'location': test_url
                        })
                        
            except:
                continue
        
        return vulnerabilities
