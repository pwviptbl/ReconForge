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
            report_filename = f"relatorio_{target.replace('/', '_')}_{timestamp}.md"

            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(report_content)

            execution_time = time.time() - start_time
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    'message': f"Relatório gerado com sucesso: {report_filename}",
                    'report_path': report_filename
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

        # Adicionar secções ao relatório
        report.append(self._format_nmap_results(discoveries))
        report.append(self._format_firewall_results(discoveries))
        report.append(self._format_protocol_analysis(discoveries))

        return "\n".join(report)

    def _format_nmap_results(self, discoveries: Dict[str, Any]) -> str:
        """Formata os resultados do Nmap para Markdown."""
        nmap_results = discoveries.get('NmapScannerPlugin', {})
        if not nmap_results:
            return ""

        report = ["## Resultados do Nmap Scanner\n"]
        for host_info in nmap_results.get('hosts', []):
            ip = host_info.get('ip', 'N/A')
            report.append(f"### Host: {ip}\n")

            # Detalhes do SO
            os_info = host_info.get('os_detection', {})
            if os_info and os_info.get('name'):
                report.append(f"- **Sistema Operacional:** {os_info['name']} (Acurácia: {os_info['accuracy']}%)")

            # Portas e Serviços
            report.append("\n**Portas Abertas:**\n")
            report.append("| Porta | Protocolo | Serviço | Versão |")
            report.append("|-------|-----------|---------|--------|")
            for port_info in host_info.get('ports', []):
                if port_info.get('state') == 'open':
                    report.append(f"| {port_info.get('port')} | {port_info.get('protocol')} | {port_info.get('service')} | {port_info.get('version', '')} |")

            report.append("\n")

        # Vulnerabilidades
        vulns = nmap_results.get('vulnerabilities', [])
        if vulns:
            report.append("**Vulnerabilidades Encontradas:**\n")
            for vuln in vulns:
                report.append(f"- **Host:** {vuln['host']}:{vuln['port']}")
                report.append(f"  - **Script:** `{vuln['script_id']}`")
                report.append(f"  - **Detalhes:**\n```\n{vuln['output']}\n```")

        return "\n".join(report)

    def _format_firewall_results(self, discoveries: Dict[str, Any]) -> str:
        """Formata os resultados do Firewall Detector para Markdown."""
        firewall_results = discoveries.get('FirewallDetectorPlugin', {})
        if not firewall_results:
            return ""

        report = ["## Análise de Firewall\n"]
        network_firewall = firewall_results.get('network_firewall', {})
        if network_firewall:
            report.append(f"- **Detecção de Firewall de Rede:** {network_firewall.get('likelihood', 'N/A').upper()}")
            report.append(f"- **Resumo:** {network_firewall.get('summary', 'Nenhum detalhe disponível.')}\n")

        waf_detection = firewall_results.get('waf_detection', {})
        if waf_detection and waf_detection.get('detected'):
            report.append("**Detecção de WAF (Web Application Firewall):**\n")
            report.append(f"- **WAFs Identificados:** {', '.join(waf_detection.get('identified_wafs', ['Nenhum']))}")
            report.append(f"- **Confiança:** {waf_detection.get('confidence', 'N/A').upper()}")

        return "\n".join(report)

    def _format_protocol_analysis(self, discoveries: Dict[str, Any]) -> str:
        """Formata os resultados do Protocol Analyzer para Markdown."""
        protocol_results = discoveries.get('ProtocolAnalyzer', {})
        if not protocol_results:
            return ""

        report = ["## Análise de Protocolos\n"]
        port_details = protocol_results.get('port_details', {})
        for port, details in port_details.items():
            report.append(f"### Análise da Porta {port}\n")

            # Informações do Serviço
            if details.get('service_info'):
                report.append("**Informações do Serviço:**\n")
                for info in details['service_info']:
                    report.append(f"- **Script:** `{info['script']}`")
                    report.append(f"  - **Detalhes:**\n```\n{info['details']}\n```")

            # Vulnerabilidades
            if details.get('vulnerabilities'):
                report.append("\n**Vulnerabilidades Encontradas:**\n")
                for vuln in details['vulnerabilities']:
                    report.append(f"- **Script:** `{vuln['script']}`")
                    report.append(f"  - **Detalhes:**\n```\n{vuln['details']}\n```")

        return "\n".join(report)
