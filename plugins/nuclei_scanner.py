"""
Plugin de varredura Nuclei
Utiliza Nuclei para detecção de vulnerabilidades usando templates
"""

import subprocess
import json
import tempfile
import time
from typing import Dict, Any, List
from pathlib import Path

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import VulnerabilityPlugin, PluginResult
from utils.http_session import resolve_use_tor
from utils.proxy_env import build_proxy_env


class NucleiScannerPlugin(VulnerabilityPlugin):
    """Plugin para varreduras Nuclei de vulnerabilidades"""
    
    def __init__(self):
        super().__init__()
        self.description = "Scanner de vulnerabilidades Nuclei com templates atualizados"
        self.version = "1.0.0"
        self.requirements = ["nuclei"]
        self.supported_targets = ["url", "domain", "ip"]
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa varredura Nuclei"""
        start_time = time.time()
        
        try:
            # Verificar se nuclei está disponível
            if not self._check_nuclei_available():
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error="Nuclei não está instalado ou não está no PATH"
                )
            
            # Preparar alvo
            prepared_target = self._prepare_target(target, context)
            
            # Executar varredura
            nuclei_results = self._run_nuclei_scan(prepared_target, context)
            
            # Processar resultados
            processed_results = self._process_nuclei_results(nuclei_results, target)
            
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
        """Valida se é um alvo válido para Nuclei"""
        return len(target.strip()) > 0
    
    def _check_nuclei_available(self) -> bool:
        """Verifica se Nuclei está disponível"""
        try:
            result = subprocess.run(
                ['nuclei', '-version'],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _prepare_target(self, target: str, context: Dict[str, Any]) -> List[str]:
        """Prepara lista de alvos para Nuclei"""
        targets = []
        
        # Se o target é um domínio/IP simples
        if not target.startswith('http'):
            # Adicionar protocolos baseado no contexto
            open_ports = context.get('discoveries', {}).get('open_ports', [])
            
            if 443 in open_ports or 8443 in open_ports:
                targets.append(f"https://{target}")
            if 80 in open_ports or 8080 in open_ports or not targets:
                targets.append(f"http://{target}")
        else:
            targets.append(target)
        
        return targets
    
    def _run_nuclei_scan(self, targets: List[str], context: Dict[str, Any]) -> Dict[str, Any]:
        """Executa varredura Nuclei"""
        # Criar arquivo temporário para targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for target in targets:
                f.write(f"{target}\n")
            targets_file = f.name
        
        # Criar arquivo temporário para output JSON
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name
        
        try:
            use_tor = resolve_use_tor(self.config)
            env = build_proxy_env(use_tor=use_tor)

            # Comando nuclei
            cmd = [
                'nuclei',
                '-l', targets_file,
                '-j',  # JSON output
                '-o', output_file,
                '-silent',
                '-c', '25',  # concurrency
                '-rl', '150',  # rate limit
                '-timeout', '10',
                '-retries', '1'
            ]
            
            # Adicionar severidades baseadas no contexto
            if context.get('mode') == 'quick':
                cmd.extend(['-s', 'critical,high'])
            else:
                cmd.extend(['-s', 'critical,high,medium'])
            
            # Executar comando
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=300  # 5 minutos
            )
            
            # Ler resultados JSON
            results = []
            if Path(output_file).exists():
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    results.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue
                except Exception:
                    pass
            
            return {
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'results': results,
                'targets': targets
            }
            
        except subprocess.TimeoutExpired:
            raise Exception("Nuclei timeout após 5 minutos")
        finally:
            # Limpar arquivos temporários
            Path(targets_file).unlink(missing_ok=True)
            Path(output_file).unlink(missing_ok=True)
    
    def _process_nuclei_results(self, nuclei_results: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Processa resultados do Nuclei"""
        processed = {
            'target': target,
            'targets_scanned': nuclei_results.get('targets', []),
            'vulnerabilities': [],
            'vulnerabilities_by_severity': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
                'info': []
            },
            'total_vulnerabilities': 0,
            'templates_used': [],
            'raw_output': nuclei_results.get('stdout', ''),
            'errors': nuclei_results.get('stderr', '')
        }
        
        # Processar cada resultado
        for result in nuclei_results.get('results', []):
            vuln = self._process_vulnerability(result)
            if vuln:
                processed['vulnerabilities'].append(vuln)
                
                # Categorizar por severidade
                severity = vuln.get('severity', 'info').lower()
                if severity in processed['vulnerabilities_by_severity']:
                    processed['vulnerabilities_by_severity'][severity].append(vuln)
                
                # Adicionar template usado
                template_id = vuln.get('template_id')
                if template_id and template_id not in processed['templates_used']:
                    processed['templates_used'].append(template_id)
        
        processed['total_vulnerabilities'] = len(processed['vulnerabilities'])
        
        return processed
    
    def _process_vulnerability(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Processa uma vulnerabilidade individual"""
        try:
            template_info = result.get('info', {})
            
            vuln = {
                'template_id': result.get('template-id', 'unknown'),
                'template_name': template_info.get('name', 'Unknown'),
                'severity': template_info.get('severity', 'info'),
                'description': template_info.get('description', ''),
                'reference': template_info.get('reference', []),
                'classification': template_info.get('classification', {}),
                'tags': template_info.get('tags', []),
                'host': result.get('host', ''),
                'matched_at': result.get('matched-at', ''),
                'extracted_results': result.get('extracted-results', []),
                'curl_command': result.get('curl-command', ''),
                'timestamp': result.get('timestamp', ''),
                'type': result.get('type', 'http')
            }
            
            # Processar matcher
            if 'matcher-status' in result:
                vuln['matcher_status'] = result['matcher-status']
            
            # Processar metadata adicional
            if 'metadata' in template_info:
                vuln['metadata'] = template_info['metadata']
            
            return vuln
            
        except Exception as e:
            return {
                'template_id': 'error',
                'template_name': 'Processing Error',
                'severity': 'info',
                'description': f'Erro ao processar resultado: {str(e)}',
                'raw_result': result
            }
