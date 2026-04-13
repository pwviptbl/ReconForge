"""
Plugin de Escaneamento Passivo
Converte RequestNodes e Endpoints descobertos em Findings para garantir que sejam testados.
"""

from typing import Dict, Any, List
import time
from urllib.parse import urlparse

from core.plugin_base import BasePlugin, PluginResult
from core.models import Finding


class PassiveScannerPlugin(BasePlugin):
    """
    Plugin que transforma descobertas passivas (reconhecimento) em Findings.
    Isso garante que endpoints com parâmetros sejam enviados para a fila de exploração
    mesmo que nenhum scanner de detecção ativa tenha encontrado vulnerabilidades neles.
    """

    def __init__(self):
        super().__init__()
        self.description = "Converte descobertas de reconhecimento em alvos de teste para a fila de exploração"
        self.version = "1.0.0"
        self.category = "vulnerability"
        self.supported_targets = ["url", "domain"]

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Processa descobertas do contexto e gera findings passivos"""
        start_time = time.time()
        findings = []
        
        # Determinar o dominio base do alvo para evitar testar dominios externos
        actual_target = context.get("original_target", target)
        target_netloc = urlparse(actual_target if "://" in actual_target else f"https://{actual_target}").netloc.lower()

        ignored_extensions = {
            ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".webp",
            ".css", ".scss", ".less", ".js",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".mp4", ".webm", ".avi", ".mp3", ".wav",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".zip", ".tar", ".gz", ".7z", ".rar"
        }

        discoveries = context.get("discoveries", {})
        request_nodes = discoveries.get("request_nodes", [])
        forms = discoveries.get("forms", [])
        
        # 1. Processar RequestNodes (requests interceptadas pelo browser ou proxy)
        for node in request_nodes:
            url = node.get("url")
            if not url:
                continue
            
            parsed = urlparse(url)
            host = (parsed.hostname or parsed.netloc or "").lower()
            
            # Filtrar dominios externos
            if target_netloc and host != target_netloc and not host.endswith("." + target_netloc):
                continue
            
            # Filtrar extensoes estaticas
            path = parsed.path.lower()
            if any(path.endswith(ext) for ext in ignored_extensions):
                continue

            # Identificar parâmetros interessantes
            params = node.get("params") or {}
            data = node.get("data") or {}
            json_body = node.get("json") or {}
            
            # Coletar todos os nomes de parâmetros
            all_params = list(params.keys()) + list(data.keys()) + list(json_body.keys())
            
            if not all_params:
                # Se não tem parâmetro mas é um POST/PUT, ainda é interessante
                if node.get("method") in ["POST", "PUT", "PATCH"]:
                    all_params = [""] # Placeholder para testar o body
                else:
                    continue

            for param in all_params:
                findings.append(self._create_passive_finding(
                    target=target,
                    endpoint=url,
                    method=node.get("method", "GET"),
                    parameter=param,
                    source="WebFlowMapper/Passive",
                    run_id=context.get("run_id")
                ))

        # 2. Processar Formulários (mapeados estaticamente ou via DOM)
        for form in forms:
            action = form.get("action")
            if not action:
                continue
            
            parsed = urlparse(action)
            host = (parsed.hostname or parsed.netloc or "").lower()
            
            # Filtrar dominios externos
            if target_netloc and host != target_netloc and not host.endswith("." + target_netloc):
                continue
            
            # Filtrar extensoes estaticas
            path = parsed.path.lower()
            if any(path.endswith(ext) for ext in ignored_extensions):
                continue

            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            
            for inp in inputs:
                name = inp.get("name")
                if not name or inp.get("type") in ["submit", "button", "reset"]:
                    continue
                
                findings.append(self._create_passive_finding(
                    target=target,
                    endpoint=action,
                    method=method,
                    parameter=name,
                    source="WebFlowMapper/Form",
                    run_id=context.get("run_id")
                ))

        # Deduplicação básica local para não sobrecarregar o state
        deduped = self._deduplicate_findings(findings)

        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=time.time() - start_time,
            data={
                "findings": [f.to_dict() for f in deduped],
                "total_generated": len(deduped)
            }
        )

    def _create_passive_finding(self, target: str, endpoint: str, method: str, parameter: str, source: str, run_id: Any) -> Finding:
        return Finding(
            category="passive", # Categoria especial para ser expandida pelo QueueBuild
            target=target,
            endpoint=endpoint,
            method=method,
            parameter=parameter,
            detection_source=f"PassiveScanner({source})",
            confidence_score=0.51, # Justo acima do threshold default (0.50) para passar no ValidationGate
            raw_evidence=f"Endpoint descoberto via reconhecimento com parâmetro '{parameter}'",
            run_id=run_id
        )

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique = []
        for f in findings:
            key = (f.endpoint, f.method, f.parameter)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
