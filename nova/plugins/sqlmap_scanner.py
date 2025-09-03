"""
Plugin SQLMap para detecção de vulnerabilidades SQL Injection
Utiliza SQLMap para testes automatizados de SQL Injection
"""

import subprocess
import json
import tempfile
import time
import re
from typing import Dict, Any, List
from pathlib import Path
from urllib.parse import urlparse, urljoin

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import VulnerabilityPlugin, PluginResult


class SQLMapPlugin(VulnerabilityPlugin):
    """Plugin para detecção de SQL Injection usando SQLMap"""
    
    def __init__(self):
        super().__init__()
        self.description = "Detecção de vulnerabilidades SQL Injection usando SQLMap"
        self.version = "1.0.0"
        self.requirements = ["sqlmap"]
        self.supported_targets = ["url", "domain"]
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa teste SQLMap"""
        start_time = time.time()
        
        try:
            # Verificar se sqlmap está disponível
            if not self._check_sqlmap_available():
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error="SQLMap não está instalado ou não está no PATH"
                )
            
            # Preparar URLs para teste
            test_urls = self._prepare_test_urls(target, context)
            
            if not test_urls:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error="Nenhuma URL válida encontrada para teste SQLMap"
                )
            
            # Executar testes SQLMap
            all_results = []
            
            for url in test_urls[:3]:  # Limitar a 3 URLs para evitar testes muito longos
                result = self._run_sqlmap_test(url)
                if result:
                    all_results.append(result)
            
            # Processar resultados
            processed_results = self._process_sqlmap_results(all_results, target)
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data=processed_results
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
        """Valida se é um alvo válido para SQLMap"""
        return len(target.strip()) > 0
    
    def _check_sqlmap_available(self) -> bool:
        """Verifica se SQLMap está disponível"""
        try:
            # Tentar diferentes caminhos para sqlmap
            sqlmap_paths = ['sqlmap', '/usr/bin/sqlmap', '/snap/bin/sqlmap']
            
            for path in sqlmap_paths:
                try:
                    result = subprocess.run(
                        [path, '--version'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        self.sqlmap_binary = path
                        return True
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
            
            return False
        except:
            return False
    
    def _prepare_test_urls(self, target: str, context: Dict[str, Any]) -> List[str]:
        """Prepara URLs para teste SQLMap"""
        test_urls = []
        
        # Se já é uma URL com parâmetros
        if target.startswith('http') and ('?' in target or '=' in target):
            test_urls.append(target)
            return test_urls
        
        # Construir URLs base
        base_urls = []
        if target.startswith('http'):
            base_urls.append(target.rstrip('/'))
        else:
            # Usar contexto para determinar protocolos
            open_ports = context.get('discoveries', {}).get('open_ports', [])
            
            if 443 in open_ports:
                base_urls.append(f"https://{target}")
            if 80 in open_ports or not base_urls:
                base_urls.append(f"http://{target}")
        
        # Adicionar URLs com parâmetros comuns para teste
        test_params = [
            '?id=1',
            '?page=1',
            '?user=test',
            '?search=test',
            '?category=1',
            '?product=1',
            '?article=1',
            '?news=1',
            '?post=1'
        ]
        
        common_paths = [
            '/',
            '/index.php',
            '/login.php',
            '/search.php',
            '/product.php',
            '/article.php',
            '/news.php',
            '/admin/'
        ]
        
        # Combinar URLs base com paths e parâmetros
        for base_url in base_urls:
            for path in common_paths:
                for param in test_params:
                    test_url = urljoin(base_url, path) + param
                    test_urls.append(test_url)
        
        return test_urls
    
    def _run_sqlmap_test(self, url: str) -> Dict[str, Any]:
        """Executa teste SQLMap em uma URL específica"""
        try:
            # Criar arquivo temporário para output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name
            
            # Comando SQLMap básico e seguro
            cmd = [
                getattr(self, 'sqlmap_binary', 'sqlmap'),
                '-u', url,
                '--batch',  # Não interativo
                '--random-agent',  # User-agent aleatório
                '--timeout', '10',  # Timeout por request
                '--retries', '1',  # Reduzir tentativas
                '--level', '1',  # Nível básico
                '--risk', '1',  # Risco baixo
                '--threads', '1',  # Single thread
                '--technique', 'B',  # Apenas Boolean-based blind
                '--output-dir', '/tmp',  # Diretório de output
                '--flush-session',  # Não usar sessões anteriores
                '--answers', 'quit=Y,follow=N,continue=Y',  # Respostas automáticas
            ]
            
            # Executar comando
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # Timeout total de 1 minuto
            )
            
            return {
                'url': url,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'vulnerable': self._check_vulnerability_in_output(result.stdout),
                'injection_types': self._extract_injection_types(result.stdout),
                'databases': self._extract_databases(result.stdout)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'url': url,
                'returncode': -1,
                'stdout': '',
                'stderr': 'Timeout após 60 segundos',
                'vulnerable': False,
                'injection_types': [],
                'databases': []
            }
        except Exception as e:
            return {
                'url': url,
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'vulnerable': False,
                'injection_types': [],
                'databases': []
            }
        finally:
            # Limpar arquivo temporário
            try:
                Path(output_file).unlink(missing_ok=True)
            except:
                pass
    
    def _check_vulnerability_in_output(self, output: str) -> bool:
        """Verifica se SQLMap encontrou vulnerabilidades"""
        vulnerability_indicators = [
            'is vulnerable',
            'injectable parameter',
            'Parameter:',
            'Type:',
            'Title:',
            'Payload:',
            'sqlmap identified the following injection point'
        ]
        
        output_lower = output.lower()
        return any(indicator.lower() in output_lower for indicator in vulnerability_indicators)
    
    def _extract_injection_types(self, output: str) -> List[str]:
        """Extrai tipos de injeção encontrados"""
        injection_types = []
        
        # Padrões para diferentes tipos de injeção
        patterns = {
            'Boolean-based blind': r'Type:\s*boolean-based blind',
            'Time-based blind': r'Type:\s*time-based blind',
            'Error-based': r'Type:\s*error-based',
            'Union query': r'Type:\s*UNION query',
            'Stacked queries': r'Type:\s*stacked queries'
        }
        
        for injection_type, pattern in patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                injection_types.append(injection_type)
        
        return injection_types
    
    def _extract_databases(self, output: str) -> List[str]:
        """Extrai nomes de databases encontrados"""
        databases = []
        
        # Procurar por nomes de databases na saída
        db_pattern = r'available databases.*?:\s*\[(.*?)\]'
        match = re.search(db_pattern, output, re.IGNORECASE | re.DOTALL)
        
        if match:
            db_list = match.group(1)
            # Limpar e dividir nomes de databases
            databases = [db.strip().strip("'\"") for db in db_list.split(',')]
            databases = [db for db in databases if db and db != '*']
        
        return databases
    
    def _process_sqlmap_results(self, all_results: List[Dict[str, Any]], target: str) -> Dict[str, Any]:
        """Processa todos os resultados SQLMap"""
        processed = {
            'target': target,
            'total_urls_tested': len(all_results),
            'vulnerable_urls': [],
            'vulnerabilities': [],
            'injection_types_found': set(),
            'databases_found': set(),
            'summary': {
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': 0,
                'affected_parameters': []
            },
            'detailed_results': all_results
        }
        
        for result in all_results:
            if result.get('vulnerable', False):
                processed['vulnerable_urls'].append(result['url'])
                
                # Criar objeto de vulnerabilidade
                vulnerability = {
                    'type': 'SQL Injection',
                    'severity': 'HIGH',
                    'url': result['url'],
                    'injection_types': result.get('injection_types', []),
                    'databases': result.get('databases', []),
                    'description': 'Vulnerabilidade de SQL Injection detectada pelo SQLMap',
                    'impact': 'Possível acesso não autorizado ao banco de dados',
                    'recommendation': 'Implementar consultas parametrizadas e validação de entrada'
                }
                
                processed['vulnerabilities'].append(vulnerability)
                processed['summary']['total_vulnerabilities'] += 1
                
                # Considerar crítica se encontrou databases ou tipos específicos
                if result.get('databases') or 'Union query' in result.get('injection_types', []):
                    processed['summary']['critical_vulnerabilities'] += 1
                    vulnerability['severity'] = 'CRITICAL'
                
                # Adicionar tipos de injeção encontrados
                processed['injection_types_found'].update(result.get('injection_types', []))
                
                # Adicionar databases encontrados
                processed['databases_found'].update(result.get('databases', []))
        
        # Converter sets para listas para JSON
        processed['injection_types_found'] = list(processed['injection_types_found'])
        processed['databases_found'] = list(processed['databases_found'])
        
        return processed
