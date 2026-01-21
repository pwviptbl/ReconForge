"""
Plugin Gerador de Relatórios
Consolida os resultados de outras verificações num relatório Markdown.
"""
import time
from datetime import datetime
from typing import Dict, Any, List

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult
from core.config import get_config

class ReportGeneratorPlugin(NetworkPlugin):
    """Plugin para gerar relatórios de pentest em formato Markdown."""

    def __init__(self):
        super().__init__()
        self.name = "ReportGenerator"
        self.description = "Gera um relatório consolidado em Markdown a partir dos resultados da varredura."
        self.version = "1.0.0"
        self.supported_targets = ["ip", "domain"]  # Atua sobre um alvo, mas usa o contexto

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Gera um relatório Markdown a partir do contexto de descobertas."""
        start_time = time.time()

        try:
            report_content = self._generate_markdown_report(target, context)

            # Salvar o relatório num ficheiro
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            data_dir = Path(get_config('output.data_dir', 'dados'))
            report_dir = data_dir / "relatorios"
            report_dir.mkdir(parents=True, exist_ok=True)
            report_filename = report_dir / f"relatorio_{target.replace('/', '_')}_{timestamp}.md"

            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(report_content)

            execution_time = time.time() - start_time
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    'message': f"Relatório gerado com sucesso: {report_filename}",
                    'report_path': str(report_filename)
                }
            )

        except Exception as e:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error=f"Falha ao gerar o relatório: {str(e)}"
            )

    def _generate_markdown_report(self, target: str, context: Dict[str, Any]) -> str:
        """Constrói o conteúdo do relatório em Markdown."""
        report = []

        # Cabeçalho
        report.append(f"# Relatório de Análise de Segurança para: {target}")
        report.append(f"**Data da Análise:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Extrair descobertas do contexto
        discoveries = context.get('discoveries', {})
        vulns = context.get('vulnerabilities', [])
        executed_plugins = context.get('executed_plugins', [])
        errors = context.get('errors', [])

        # Adicionar secções ao relatório
        report.append(self._format_summary(discoveries, vulns, executed_plugins, errors))
        report.append(self._format_discoveries(discoveries))
        report.append(self._format_technologies(discoveries))
        report.append(self._format_vulnerabilities(vulns))
        report.append(self._format_errors(errors))

        return "\n".join(report)

    def _format_summary(
        self,
        discoveries: Dict[str, Any],
        vulns: List[Dict[str, Any]],
        executed_plugins: List[str],
        errors: List[Any]
    ) -> str:
        report = ["## Resumo Executivo\n"]
        report.append(f"- **Plugins executados:** {len(executed_plugins)}")
        report.append(f"- **Hosts descobertos:** {len(discoveries.get('hosts', []))}")
        report.append(f"- **Portas abertas:** {len(discoveries.get('open_ports', []))}")
        report.append(f"- **Serviços:** {len(discoveries.get('services', []))}")
        report.append(f"- **Tecnologias:** {len(discoveries.get('technologies', []))}")
        report.append(f"- **Vulnerabilidades:** {len(vulns)}")
        report.append(f"- **Erros:** {len(errors)}\n")
        return "\n".join(report)

    def _format_discoveries(self, discoveries: Dict[str, Any]) -> str:
        hosts = discoveries.get('hosts', [])
        ports = discoveries.get('open_ports', [])
        services = discoveries.get('services', [])

        if not (hosts or ports or services):
            return ""

        report = ["## Descobertas\n"]

        if hosts:
            report.append("**Hosts:** " + ", ".join(str(h) for h in hosts))

        if ports:
            report.append("\n**Portas Abertas:** " + ", ".join(str(p) for p in sorted(set(ports))))

        if services:
            report.append("\n**Serviços Identificados:**\n")
            report.append("| Porta | Serviço | Versão | Produto |")
            report.append("|-------|---------|--------|---------|")
            for svc in services:
                if not isinstance(svc, dict):
                    report.append(f"| N/A | {svc} |  |  |")
                    continue
                port = svc.get('port', 'N/A')
                name = svc.get('service', 'unknown')
                version = svc.get('version', '')
                product = svc.get('product', '')
                report.append(f"| {port} | {name} | {version} | {product} |")

        report.append("")
        return "\n".join(report)

    def _format_technologies(self, discoveries: Dict[str, Any]) -> str:
        techs = discoveries.get('technologies', [])
        if not techs:
            return ""

        unique = []
        for t in techs:
            value = t.get('name') if isinstance(t, dict) else str(t)
            if value and value not in unique:
                unique.append(value)

        return "## Tecnologias Detectadas\n\n" + ", ".join(unique) + "\n"

    def _format_vulnerabilities(self, vulns: List[Dict[str, Any]]) -> str:
        if not vulns:
            return ""

        report = ["## Vulnerabilidades\n"]

        by_service = {}
        for vuln in vulns:
            service = vuln.get('service') or 'unknown'
            by_service.setdefault(service, []).append(vuln)

        for service, items in sorted(by_service.items()):
            report.append(f"\n### Serviço: {service}\n")
            report.append("| Severidade | Título | Porta | Referência |")
            report.append("|------------|--------|-------|------------|")
            for vuln in items:
                severity = str(vuln.get('severity', 'UNKNOWN')).upper()
                title = vuln.get('title') or vuln.get('description') or 'N/A'
                port = vuln.get('port', 'N/A')
                ref = vuln.get('url') or vuln.get('cve') or vuln.get('id') or ''
                report.append(f"| {severity} | {title} | {port} | {ref} |")

        report.append("")
        return "\n".join(report)

    def _format_errors(self, errors: List[Any]) -> str:
        if not errors:
            return ""
        report = ["## Erros e Avisos\n"]
        for err in errors:
            report.append(f"- {err}")
        report.append("")
        return "\n".join(report)
