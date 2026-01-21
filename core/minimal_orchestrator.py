"""
Orquestrador Minimalista do ReconForge
Versão sem IA, com seleção manual de plugins via menu interativo
Permite ver resultados entre execuções para tomada de decisão
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

from .config import get_config
from .plugin_manager import PluginManager
from .plugin_base import PluginResult
from .storage import Storage
from utils.logger import get_logger

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import print as rprint


class MinimalOrchestrator:
    """Orquestrador minimalista com menu interativo para seleção de plugins"""
    
    def __init__(self, verbose: bool = False):
        self.logger = get_logger('MinimalOrchestrator')
        self.console = Console()
        
        # Inicializar componentes
        self.plugin_manager = PluginManager()
        data_dir = Path(get_config('output.data_dir', 'dados'))
        self.storage = Storage(data_dir / "reconforge.db")
        self.run_id = None
        self.loaded_session = False

        # Agrupamento e pre-requisitos de plugins
        self.plugin_groups = {
            'PortScannerPlugin': ('Infra', 'Scanner'),
            'NmapScannerPlugin': ('Infra', 'Scanner'),
            'NetworkMapperPlugin': ('Infra', 'Scanner'),
            'DNSResolverPlugin': ('Infra', 'Recon'),
            'ReconnaissancePlugin': ('Infra', 'Recon'),
            'ProtocolAnalyzer': ('Infra', 'Testes'),
            'MisconfigurationAnalyzer': ('Infra', 'Testes'),
            'FirewallDetectorPlugin': ('Infra', 'Testes'),
            'SSLAnalyzerPlugin': ('Infra', 'Testes'),
            'TrafficAnalyzerPlugin': ('Infra', 'Testes'),
            'ExploitSearcherPlugin': ('Infra', 'Vulnerabilidades'),
            'ExploitSuggester': ('Infra', 'Vulnerabilidades'),
            'ReportGenerator': ('Infra', 'Testes'),
            'DirectoryScannerPlugin': ('Web', 'Scanner'),
            'WebScannerPlugin': ('Web', 'Scanner'),
            'WebCrawlerPlugin': ('Web', 'Scanner'),
            'TechnologyDetectorPlugin': ('Web', 'Recon'),
            'WhatWebScannerPlugin': ('Web', 'Recon'),
            'SubdomainEnumerator': ('Web', 'Recon'),
            'SubfinderPlugin': ('Web', 'Recon'),
            'WebVulnScannerPlugin': ('Web', 'Vulnerabilidades'),
            'NucleiScannerPlugin': ('Web', 'Vulnerabilidades'),
            'SQLMapPlugin': ('Web', 'Vulnerabilidades')
        }
        self.plugin_prereqs = {
            'NmapScannerPlugin': ['PortScannerPlugin'],
            'NetworkMapperPlugin': ['PortScannerPlugin'],
            'ProtocolAnalyzer': ['PortScannerPlugin'],
            'MisconfigurationAnalyzer': ['PortScannerPlugin'],
            'FirewallDetectorPlugin': ['PortScannerPlugin'],
            'SSLAnalyzerPlugin': ['PortScannerPlugin'],
            'TrafficAnalyzerPlugin': ['PortScannerPlugin'],
            'ExploitSearcherPlugin': ['NmapScannerPlugin'],
            'ExploitSuggester': ['NmapScannerPlugin'],
            'DirectoryScannerPlugin': ['PortScannerPlugin'],
            'WebScannerPlugin': ['PortScannerPlugin'],
            'WebCrawlerPlugin': ['PortScannerPlugin'],
            'TechnologyDetectorPlugin': ['PortScannerPlugin'],
            'WhatWebScannerPlugin': ['PortScannerPlugin'],
            'WebVulnScannerPlugin': ['PortScannerPlugin'],
            'NucleiScannerPlugin': ['PortScannerPlugin'],
            'SQLMapPlugin': ['PortScannerPlugin']
        }
        
        # Estado do pentest
        self.context = {}
        self.results = {}
        
        self.logger.info("🎯 ReconForge Orquestrador inicializado")
    
    def run_interactive(self, target: str) -> Dict[str, Any]:
        """
        Executa pentest com seleção interativa de plugins
        O usuário escolhe um plugin por vez, vê os resultados e decide o próximo
        """
        self.logger.info(f"🚀 Iniciando varredura: {target}")
        
        if not (self.loaded_session and self.context.get('target') == target):
            # Inicializar contexto
            self.context = {
                'target': target,
                'start_time': datetime.now(),
                'executed_plugins': [],
                'plugin_states': {},
                'discoveries': {
                    'hosts': [],
                    'open_ports': [],
                    'services': [],
                    'technologies': []
                },
                'vulnerabilities': [],
                'errors': []
            }
            self.results = {}
            self.run_id = self.storage.create_run(self.context['target'], self.context, {})
        else:
            self._ensure_context_defaults()
            self.loaded_session = False
        
        try:
            # Loop principal interativo
            self._run_interactive_loop()
            
            # Gerar relatório final
            report_path = self._generate_report()
            
            end_time = datetime.now()
            duration = (end_time - self.context['start_time']).total_seconds()
            
            # Resultado final
            result = {
                'success': True,
                'target': target,
                'duration_seconds': duration,
                'plugins_executed': len(self.context['executed_plugins']),
                'vulnerabilities_found': len(self.context['vulnerabilities']),
                'discoveries': self.context['discoveries'],
                'report_path': report_path,
                'context': self.context
            }
            
            self._show_final_summary(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"💥 Erro na varredura: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e),
                'target': target,
                'context': self.context
            }

    def load_session(self, target: str, context: Dict[str, Any], results: Dict[str, Any], run_id: int):
        """Carrega uma sessao salva antes de iniciar a varredura"""
        self.context = context
        self.results = self._hydrate_results(results)
        self.run_id = run_id
        self.loaded_session = True
        self.context['target'] = target
        self._ensure_context_defaults()
    
    def _run_interactive_loop(self):
        """Loop principal: mostra resultados atuais e permite escolher próximo plugin"""
        while True:
            self.console.clear()
            
            # Mostrar estado atual
            self._show_current_state()
            
            # Mostrar plugins disponíveis
            available = self._get_available_plugins()
            
            if not available:
                rprint("\n[yellow]⚠️ Todos os plugins foram executados![/yellow]")
                input("\nPressione ENTER para ver o resumo final...")
                break
            
            # Mostrar menu de plugins
            self._show_plugin_menu(available)
            
            # Ler escolha do usuário
            choice = Prompt.ask("\n[bold green]👉 Escolha[/bold green]").strip().lower()
            
            if choice in ['q', 'quit', 'sair', 'exit']:
                if Confirm.ask("[yellow]Deseja encerrar a varredura?[/yellow]"):
                    break
                continue
            
            if choice in ['r', 'results', 'resultados']:
                self._show_detailed_results()
                continue

            if choice in ['d', 'discoveries', 'descobertas']:
                self._show_discoveries()
                continue
            
            if choice in ['v', 'vulns', 'vulnerabilities']:
                self._show_vulnerabilities()
                continue

            if choice in ['s', 'services', 'servicos']:
                self._show_services()
                continue
            
            # Tentar executar plugin
            plugin_name = self._parse_plugin_choice(choice, available)
            
            if plugin_name:
                self._execute_plugin(plugin_name)
                input("\n[dim]Pressione ENTER para continuar...[/dim]")
            else:
                rprint(f"[red]❌ Opção inválida: {choice}[/red]")
                time.sleep(1)
    
    def _show_current_state(self):
        """Mostra o estado atual da varredura com todas as descobertas"""
        discoveries = self.context['discoveries']
        vulns = self.context['vulnerabilities']
        executed = self.context['executed_plugins']
        
        # Cabeçalho
        self.console.print(Panel.fit(
            f"[bold cyan]🔍 ReconForge - Análise Interativa[/bold cyan]\n"
            f"[dim]Alvo: {self.context['target']}[/dim]",
            border_style="cyan"
        ))
        
        # Estatísticas rápidas
        stats = Table(show_header=False, box=None, padding=(0, 2))
        stats.add_column("", style="bold")
        stats.add_column("")
        stats.add_row("🔌 Plugins executados:", f"[cyan]{len(executed)}[/cyan]")
        stats.add_row("🖥️  Hosts:", f"[green]{len(discoveries['hosts'])}[/green]")
        stats.add_row("🔓 Portas abertas:", f"[yellow]{len(discoveries['open_ports'])}[/yellow]")
        stats.add_row("⚙️  Serviços:", f"[blue]{len(discoveries['services'])}[/blue]")
        stats.add_row("🛠️  Tecnologias:", f"[magenta]{len(discoveries['technologies'])}[/magenta]")
        stats.add_row("⚠️  Vulnerabilidades:", f"[red]{len(vulns)}[/red]")
        self.console.print(stats)
        
        # Mostrar vulnerabilidades resumidas se houver
        if vulns:
            self.console.print("\n[bold red]═══ Vulnerabilidades Encontradas ═══[/bold red]")
            for vuln in vulns[:5]:
                severity = vuln.get('severity', 'unknown').upper()
                title = vuln.get('title', vuln.get('description', 'N/A'))[:60]
                if severity in ['CRITICAL', 'HIGH']:
                    rprint(f"  [red]• [{severity}][/red] {title}")
                elif severity == 'MEDIUM':
                    rprint(f"  [yellow]• [{severity}][/yellow] {title}")
                else:
                    rprint(f"  [dim]• [{severity}][/dim] {title}")
        if len(vulns) > 5:
            rprint(f"  [dim]... e mais {len(vulns) - 5} vulnerabilidades (digite 'v' para ver todas)[/dim]")

    def _show_discoveries(self):
        """Mostra descobertas atuais sob demanda"""
        self.console.clear()
        discoveries = self.context['discoveries']

        if not (discoveries['hosts'] or discoveries['open_ports'] or discoveries['services'] or discoveries['technologies']):
            rprint("[yellow]Nenhuma descoberta disponível ainda.[/yellow]")
            input("\nPressione ENTER para voltar...")
            return

        self.console.print(Panel.fit(
            "[bold]🔎 Descobertas Atuais[/bold]",
            border_style="cyan"
        ))

        # Hosts
        if discoveries['hosts']:
            hosts_str = ", ".join(str(h) for h in discoveries['hosts'][:10])
            if len(discoveries['hosts']) > 10:
                hosts_str += f" (+{len(discoveries['hosts']) - 10})"
            rprint(f"\n  [green][bold]Hosts:[/bold][/green] {hosts_str}")

        # Portas com serviços
        if discoveries['open_ports'] or discoveries['services']:
            self._show_ports_services_summary()

        # Tecnologias
        if discoveries['technologies']:
            techs = list(set(discoveries['technologies']))[:10]
            techs_str = ", ".join(str(t) for t in techs)
            if len(discoveries['technologies']) > 10:
                techs_str += f" (+{len(discoveries['technologies']) - 10})"
            rprint(f"\n  [magenta][bold]Tecnologias:[/bold][/magenta] {techs_str}")

        input("\n[dim]Pressione ENTER para voltar...[/dim]")
    
    def _show_ports_services_summary(self):
        """Mostra resumo de portas e serviços"""
        discoveries = self.context['discoveries']
        ports = discoveries['open_ports']
        services = discoveries['services']
        
        # Criar mapa de porta -> serviço
        port_service_map = {}
        for service in services:
            if isinstance(service, dict):
                port = service.get('port')
                if port:
                    svc_name = service.get('service', 'unknown')
                    version = service.get('version', '')
                    product = service.get('product', '')
                    info = svc_name
                    if version:
                        info += f" {version}"
                    if product and product not in info:
                        info += f" ({product})"
                    port_service_map[port] = info
        
        # Mostrar portas com serviços
        port_info = []
        for port in sorted(set(ports))[:15]:
            if port in port_service_map:
                port_info.append(f"{port}/{port_service_map[port]}")
            else:
                port_info.append(str(port))
        
        if port_info:
            rprint(f"  [yellow]Portas/Serviços:[/yellow] {', '.join(port_info)}")
            if len(ports) > 15:
                rprint(f"  [dim]... e mais {len(ports) - 15} portas (digite 's' para ver todas)[/dim]")
    
    def _show_plugin_menu(self, available: List[Dict]):
        """Mostra menu de plugins disponíveis"""
        self.console.print("\n[bold]═══ Plugins Disponíveis ═══[/bold]")
        
        # Agrupar por categoria mae e subcategoria
        categories = {}
        for plugin in available:
            parent = plugin.get('parent_category', 'Infra')
            subgroup = plugin.get('subcategory', 'Scanner')
            if parent not in categories:
                categories[parent] = {}
            if subgroup not in categories[parent]:
                categories[parent][subgroup] = []
            categories[parent][subgroup].append(plugin)
        
        # Contador global para numeração
        idx = 1
        plugin_map = {}
        
        executed = set(self.context['executed_plugins'])
        for parent, subgroups in sorted(categories.items()):
            rprint(f"\n  [bold magenta]📂 {parent.upper()}[/bold magenta]")
            for subgroup, plugins in sorted(subgroups.items()):
                rprint(f"    [bold]• {subgroup}[/bold]")
                for plugin in plugins:
                    name = plugin['name']
                    desc = plugin.get('description', '')[:40]
                    status = self.context['plugin_states'].get(name)
                    if status == 'success':
                        status_icon = "✅"
                    elif status == 'failed':
                        status_icon = "❌"
                    elif name in executed:
                        status_icon = "↻"
                    else:
                        status_icon = "•"
                    rprint(f"      [cyan]{idx:2}[/cyan] {status_icon} {name} [dim]({desc})[/dim]")
                    plugin_map[idx] = name
                    plugin_map[name.lower()] = name
                    idx += 1
        
        self._plugin_map = plugin_map
        
        # Opções adicionais
        rprint("\n[bold yellow]Outras opções:[/bold yellow]")
        rprint("  [cyan]r[/cyan] - Ver resultados detalhados de plugins executados")
        rprint("  [cyan]d[/cyan] - Ver descobertas atuais")
        rprint("  [cyan]s[/cyan] - Ver lista completa de serviços")
        rprint("  [cyan]v[/cyan] - Ver todas as vulnerabilidades")
        rprint("  [cyan]q[/cyan] - Encerrar varredura")
    
    def _get_available_plugins(self) -> List[Dict]:
        """Retorna plugins disponíveis para o alvo"""
        available = []
        
        for plugin_name, plugin in self.plugin_manager.plugins.items():
            if plugin.validate_target(self.context['target']):
                info = plugin.get_info()
                parent, subgroup = self._classify_plugin(info)
                info['parent_category'] = parent
                info['subcategory'] = subgroup
                available.append(info)
        
        return sorted(
            available,
            key=lambda x: (x.get('parent_category', 'z'), x.get('subcategory', 'z'), x['name'])
        )
    
    def _parse_plugin_choice(self, choice: str, available: List[Dict]) -> Optional[str]:
        """Converte escolha do usuário em nome de plugin"""
        # Tentar como número
        try:
            num = int(choice)
            if hasattr(self, '_plugin_map') and num in self._plugin_map:
                return self._plugin_map[num]
        except ValueError:
            pass
        
        # Tentar como nome (busca parcial)
        choice_lower = choice.lower()
        for plugin in available:
            if choice_lower in plugin['name'].lower():
                return plugin['name']
        
        # Tentar no mapa
        if hasattr(self, '_plugin_map') and choice_lower in self._plugin_map:
            return self._plugin_map[choice_lower]
        
        return None
    
    def _show_plugin_result_details(self, result):
        """Mostra resultados detalhados de um plugin executado"""
        data = result.data
        
        rprint(f"\n[bold]📊 Resultados do {result.plugin_name}:[/bold]")
        
        # Hosts descobertos
        if data.get('hosts'):
            rprint(f"\n  [green][bold]🖥️  Hosts ({len(data['hosts'])}):[/bold][/green]")
            for host in data['hosts'][:20]:
                rprint(f"    • {host}")
            if len(data['hosts']) > 20:
                rprint(f"    [dim]... e mais {len(data['hosts']) - 20}[/dim]")
        
        # Portas abertas
        if data.get('open_ports'):
            rprint(f"\n  [yellow][bold]🔓 Portas Abertas ({len(data['open_ports'])}):[/bold][/yellow]")
            ports_str = ", ".join(str(p) for p in sorted(data['open_ports'])[:30])
            rprint(f"    {ports_str}")
            if len(data['open_ports']) > 30:
                rprint(f"    [dim]... e mais {len(data['open_ports']) - 30}[/dim]")
        
        # Serviços
        if data.get('services'):
            rprint(f"\n  [blue][bold]⚙️  Serviços ({len(data['services'])}):[/bold][/blue]")
            for service in data['services'][:15]:
                if isinstance(service, dict):
                    port = service.get('port', 'N/A')
                    svc = service.get('service', 'unknown')
                    version = service.get('version', '')
                    product = service.get('product', '')
                    line = f"    • Porta {port}: {svc}"
                    if version:
                        line += f" {version}"
                    if product:
                        line += f" ({product})"
                    rprint(line)
                else:
                    rprint(f"    • {service}")
            if len(data['services']) > 15:
                rprint(f"    [dim]... e mais {len(data['services']) - 15}[/dim]")
        
        # Tecnologias
        if data.get('technologies'):
            rprint(f"\n  [magenta][bold]🛠️  Tecnologias ({len(data['technologies'])}):[/bold][/magenta]")
            techs = list(set(data['technologies']))
            for tech in techs[:10]:
                rprint(f"    • {tech}")
            if len(techs) > 10:
                rprint(f"    [dim]... e mais {len(techs) - 10}[/dim]")
        
        # Vulnerabilidades
        if data.get('vulnerabilities'):
            rprint(f"\n  [red][bold]⚠️  Vulnerabilidades ({len(data['vulnerabilities'])}):[/bold][/red]")
            for vuln in data['vulnerabilities'][:10]:
                severity = vuln.get('severity', 'unknown').upper()
                title = vuln.get('title', vuln.get('description', 'N/A'))[:70]
                if severity in ['CRITICAL', 'HIGH']:
                    rprint(f"    [red]• [{severity}] {title}[/red]")
                elif severity == 'MEDIUM':
                    rprint(f"    [yellow]• [{severity}] {title}[/yellow]")
                else:
                    rprint(f"    • [{severity}] {title}")
            if len(data['vulnerabilities']) > 10:
                rprint(f"    [dim]... e mais {len(data['vulnerabilities']) - 10}[/dim]")

        # ExploitSearcherPlugin - resumo especifico
        if result.plugin_name == 'ExploitSearcherPlugin' or 'security_report' in data:
            software_analyzed = data.get('software_analyzed')
            total_exploits = data.get('total_exploits_found')
            if software_analyzed is not None or total_exploits is not None:
                rprint("\n  [bold]🧭 Resumo de Exploits:[/bold]")
                if software_analyzed is not None:
                    rprint(f"    • Softwares analisados: {software_analyzed}")
                if total_exploits is not None:
                    rprint(f"    • Exploits encontrados: {total_exploits}")

            exploits_by_severity = data.get('exploits_by_severity', {})
            if isinstance(exploits_by_severity, dict) and exploits_by_severity:
                counts = []
                for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'REPOSITORIES', 'ERRORS']:
                    if sev in exploits_by_severity:
                        counts.append(f"{sev}:{len(exploits_by_severity[sev])}")
                if counts:
                    rprint(f"    • Por severidade: {', '.join(counts)}")

            security_report = data.get('security_report', {})
            if isinstance(security_report, dict):
                risk = security_report.get('risk_assessment', {})
                if risk:
                    overall = risk.get('overall_risk_level')
                    score = risk.get('risk_score')
                    if overall or score is not None:
                        rprint("    • Risco geral: " + f"{overall or 'N/A'} (score {score})")

                top_threats = security_report.get('top_threats', [])
                if top_threats:
                    rprint("    • Top threats:")
                    for threat in top_threats[:5]:
                        title = threat.get('title', threat.get('name', 'N/A'))
                        rprint(f"      - {title}")

            detailed_results = data.get('detailed_results', {})
            if isinstance(detailed_results, dict) and detailed_results:
                rprint("    • Alvos com exploits:")
                for key, exploits in list(detailed_results.items())[:5]:
                    rprint(f"      - {key}: {len(exploits)}")
                if len(detailed_results) > 5:
                    rprint(f"      [dim]... e mais {len(detailed_results) - 5}[/dim]")
                rprint("\n  [bold]🧾 Detalhes (ExploitSearcher):[/bold]")
                for key, exploits in list(detailed_results.items())[:5]:
                    rprint(f"    • {key} ({len(exploits)} exploits)")
                    for exploit in exploits[:5]:
                        title = exploit.get('title') or exploit.get('name') or 'N/A'
                        source = exploit.get('source', 'unknown')
                        cve_id = exploit.get('cve_id') or exploit.get('cve')
                        url = exploit.get('url') or exploit.get('path')
                        line = f"      - {title} [dim]({source})[/dim]"
                        if cve_id:
                            line += f" [dim]{cve_id}[/dim]"
                        rprint(line)
                        if url:
                            rprint(f"        [dim]{url}[/dim]")
                    if len(exploits) > 5:
                        rprint(f"      [dim]... e mais {len(exploits) - 5}[/dim]")
                if len(detailed_results) > 5:
                    rprint(f"    [dim]... e mais {len(detailed_results) - 5} alvos[/dim]")

        # ExploitSuggester - resumo especifico
        if result.plugin_name == 'ExploitSuggester':
            exploits = data.get('exploits', [])
            if isinstance(exploits, list):
                total_entries = len(exploits)
                total_exploits = 0
                for entry in exploits:
                    items = entry.get('exploits', [])
                    if isinstance(items, list):
                        total_exploits += len(items)
                rprint("\n  [bold]🧭 Resumo de Exploits:[/bold]")
                rprint(f"    • CVEs com resultados: {total_entries}")
                rprint(f"    • Exploits encontrados: {total_exploits}")
                if total_entries:
                    rprint("\n  [bold]🧾 Detalhes (ExploitSuggester):[/bold]")
                    for entry in exploits[:10]:
                        cve = entry.get('cve', 'N/A')
                        items = entry.get('exploits', [])
                        rprint(f"    • {cve} ({len(items)} exploits)")
                        if isinstance(items, list):
                            for exploit in items[:5]:
                                title = exploit.get('title', 'N/A')
                                path = exploit.get('path', '')
                                if path:
                                    rprint(f"      - {title} [dim]({path})[/dim]")
                                else:
                                    rprint(f"      - {title}")
                            if len(items) > 5:
                                rprint(f"      [dim]... e mais {len(items) - 5}[/dim]")
                    if total_entries > 10:
                        rprint(f"    [dim]... e mais {total_entries - 10} CVEs[/dim]")
        
        # Dados brutos (resumo)
        other_keys = [k for k in data.keys() if k not in ['hosts', 'open_ports', 'services', 'technologies', 'vulnerabilities', 'raw_output']]
        if other_keys:
            rprint(f"\n  [dim][bold]📋 Outros dados:[/bold] {', '.join(other_keys)}[/dim]")
    
    def _show_detailed_results(self):
        """Mostra um resumo geral e permite ver detalhes por plugin"""
        self.console.clear()

        if not self.results:
            rprint("[yellow]Nenhum plugin foi executado ainda.[/yellow]")
            input("\nPressione ENTER para voltar...")
            return

        while True:
            self.console.clear()
            self.console.print(Panel.fit(
                "[bold]📋 Resultados dos Plugins (Resumo)[/bold]",
                border_style="cyan"
            ))

            plugin_names = list(self.results.keys())
            for idx, plugin_name in enumerate(plugin_names, 1):
                result = self.results[plugin_name]
                data = result.data or {}
                parts = []

                if data.get('hosts'):
                    parts.append(f"hosts:{len(data['hosts'])}")
                if data.get('open_ports'):
                    parts.append(f"ports:{len(data['open_ports'])}")
                if data.get('services'):
                    parts.append(f"services:{len(data['services'])}")
                if data.get('technologies'):
                    parts.append(f"techs:{len(data['technologies'])}")
                if data.get('vulnerabilities'):
                    parts.append(f"vulns:{len(data['vulnerabilities'])}")

                if plugin_name == 'ExploitSearcherPlugin':
                    total_exploits = data.get('total_exploits_found')
                    if total_exploits is not None:
                        parts.append(f"exploits:{total_exploits}")

                if plugin_name == 'ExploitSuggester':
                    exploits = data.get('exploits', [])
                    if isinstance(exploits, list):
                        total_exploits = 0
                        for entry in exploits:
                            items = entry.get('exploits', [])
                            if isinstance(items, list):
                                total_exploits += len(items)
                        parts.append(f"exploits:{total_exploits}")

                summary = ", ".join(parts) if parts else "sem dados resumidos"
                self.console.print(f"[cyan]{idx}[/cyan] - {plugin_name} [dim]({summary})[/dim]")

            choice = input("\n👉 ID para ver detalhes (ENTER para voltar): ").strip()
            if not choice:
                return
            if not choice.isdigit() or int(choice) < 1 or int(choice) > len(plugin_names):
                rprint("[red]❌ ID inválido![/red]")
                input("\nPressione ENTER para continuar...")
                continue

            selected = plugin_names[int(choice) - 1]
            self.console.clear()
            self.console.print(f"\n[bold cyan]═══ {selected} ═══[/bold cyan]")
            self._show_plugin_result_details(self.results[selected])
            input("\n[dim]Pressione ENTER para voltar...[/dim]")
    
    def _show_vulnerabilities(self):
        """Mostra todas as vulnerabilidades encontradas"""
        self.console.clear()
        
        vulns = self.context['vulnerabilities']
        
        if not vulns:
            rprint("[green]Nenhuma vulnerabilidade encontrada ainda.[/green]")
            input("\nPressione ENTER para voltar...")
            return
        
        self.console.print(Panel.fit(
            f"[bold red]⚠️  Vulnerabilidades Encontradas ({len(vulns)})[/bold red]",
            border_style="red"
        ))

        filter_value = Prompt.ask(
            "[dim]Filtro por servico/porta (ex: ftp, http, 22). ENTER para todos[/dim]",
            default=""
        ).strip().lower()
        severity_filter = Prompt.ask(
            "[dim]Filtro por severidade (critical, high, medium, low, info). ENTER para todas[/dim]",
            default=""
        ).strip().upper()
        valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'}
        if severity_filter and severity_filter not in valid_severities:
            rprint("[yellow]Severidade invalida, mostrando todas.[/yellow]")
            severity_filter = ""
        if filter_value or severity_filter:
            filtered = []
            for vuln in vulns:
                service = str(vuln.get('service', '')).lower()
                port = str(vuln.get('port', ''))
                sev = str(vuln.get('severity', 'unknown')).upper()
                matches_service = not filter_value or filter_value in service or filter_value == port
                matches_severity = not severity_filter or sev == severity_filter
                if matches_service and matches_severity:
                    filtered.append(vuln)
            vulns = filtered

        if not vulns:
            rprint("[yellow]Nenhuma vulnerabilidade corresponde ao filtro.[/yellow]")
            input("\nPressione ENTER para voltar...")
            return
        
        # Agrupar por servico e severidade
        by_service = {}
        for vuln in vulns:
            service = vuln.get('service') or 'unknown'
            by_service.setdefault(service, []).append(vuln)

        for service_name in sorted(by_service.keys()):
            service_vulns = by_service[service_name]
            self.console.print(f"\n[bold cyan]🔧 Serviço: {service_name} ({len(service_vulns)})[/bold cyan]")

            by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': [], 'UNKNOWN': []}
            for vuln in service_vulns:
                sev = vuln.get('severity', 'unknown').upper()
                if sev not in by_severity:
                    sev = 'UNKNOWN'
                by_severity[sev].append(vuln)

            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']:
                if by_severity[severity]:
                    if severity in ['CRITICAL', 'HIGH']:
                        color = "red"
                    elif severity == 'MEDIUM':
                        color = "yellow"
                    else:
                        color = "dim"

                    rprint(f"\n[{color}][bold]{severity} ({len(by_severity[severity])}):[/bold][/{color}]")
                    for vuln in by_severity[severity]:
                        title = vuln.get('title', vuln.get('description', 'N/A'))
                        rprint(f"  • {title}")
                        if vuln.get('url'):
                            rprint(f"    [dim]URL: {vuln['url']}[/dim]")
            for key in by_severity:
                by_severity[key] = []
        
        input("\n[dim]Pressione ENTER para voltar...[/dim]")
    
    def _show_services(self):
        """Mostra lista completa de serviços descobertos"""
        self.console.clear()
        
        services = self.context['discoveries']['services']
        ports = self.context['discoveries']['open_ports']
        
        if not services and not ports:
            rprint("[yellow]Nenhum serviço descoberto ainda.[/yellow]")
            input("\nPressione ENTER para voltar...")
            return
        
        self.console.print(Panel.fit(
            f"[bold blue]⚙️  Serviços Descobertos[/bold blue]",
            border_style="blue"
        ))
        
        # Criar tabela de serviços
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Porta", style="yellow", width=8)
        table.add_column("Serviço", style="cyan")
        table.add_column("Versão", style="white")
        table.add_column("Produto", style="dim")
        
        # Processar serviços
        seen_ports = set()
        for service in services:
            if isinstance(service, dict):
                port = str(service.get('port', 'N/A'))
                svc = service.get('service', 'unknown')
                version = service.get('version', '')
                product = service.get('product', '')
                table.add_row(port, svc, version, product)
                if service.get('port'):
                    seen_ports.add(service['port'])
        
        # Adicionar portas sem serviço identificado
        for port in sorted(set(ports)):
            if port not in seen_ports:
                table.add_row(str(port), "[dim]unknown[/dim]", "", "")
        
        self.console.print(table)
        
        input("\n[dim]Pressione ENTER para voltar...[/dim]")

    def _ensure_context_defaults(self):
        """Garante estrutura minima do contexto apos carregar"""
        if not isinstance(self.context, dict):
            self.context = {}
        self.context.setdefault('target', '')
        start_time = self.context.get('start_time')
        if isinstance(start_time, str):
            try:
                start_time = datetime.fromisoformat(start_time)
            except ValueError:
                start_time = datetime.now()
        elif start_time is None:
            start_time = datetime.now()
        self.context['start_time'] = start_time
        self.context.setdefault('executed_plugins', [])
        self.context.setdefault('plugin_states', {})
        self.context.setdefault('discoveries', {})
        self.context['discoveries'].setdefault('hosts', [])
        self.context['discoveries'].setdefault('open_ports', [])
        self.context['discoveries'].setdefault('services', [])
        self.context['discoveries'].setdefault('technologies', [])
        self.context.setdefault('vulnerabilities', [])
        self.context.setdefault('errors', [])

    def _hydrate_results(self, results: Dict[str, Any]) -> Dict[str, PluginResult]:
        """Restaura resultados salvos do SQLite"""
        hydrated = {}
        for plugin_name, result_data in results.items():
            if isinstance(result_data, dict):
                try:
                    hydrated[plugin_name] = PluginResult(**result_data)
                except TypeError:
                    continue
        return hydrated

    def _persist_state(self):
        """Persiste contexto e resultados no SQLite"""
        if not self.run_id:
            return
        serializable_results = {
            name: result.to_dict() if isinstance(result, PluginResult) else result
            for name, result in self.results.items()
        }
        self.storage.update_run(self.run_id, self.context, serializable_results)
    
    def _update_context_with_result(self, result):
        """Atualiza contexto com resultado do plugin"""
        data = result.data
        
        # Atualizar descobertas
        if 'hosts' in data:
            new_hosts = [h for h in data['hosts'] if h not in self.context['discoveries']['hosts']]
            self.context['discoveries']['hosts'].extend(new_hosts)
        
        if 'open_ports' in data:
            new_ports = [p for p in data['open_ports'] if p not in self.context['discoveries']['open_ports']]
            self.context['discoveries']['open_ports'].extend(new_ports)
        
        if 'services' in data:
            new_services = [s for s in data['services'] if s not in self.context['discoveries']['services']]
            self.context['discoveries']['services'].extend(new_services)
        
        if 'technologies' in data:
            new_techs = [t for t in data['technologies'] if t not in self.context['discoveries']['technologies']]
            self.context['discoveries']['technologies'].extend(new_techs)
        
        # Atualizar vulnerabilidades
        if 'vulnerabilities' in data:
            existing_keys = {self._vuln_key(v) for v in self.context['vulnerabilities']}
            for vuln in data['vulnerabilities']:
                if self._vuln_key(vuln) not in existing_keys:
                    self.context['vulnerabilities'].append(vuln)
                    existing_keys.add(self._vuln_key(vuln))
        
        # Armazenar resultado completo
        self.results[result.plugin_name] = result
        self._persist_state()

    def _classify_plugin(self, plugin_info: Dict[str, Any]) -> tuple[str, str]:
        """Determina categoria mae e subcategoria de um plugin"""
        name = plugin_info.get('name', '')
        if name in self.plugin_groups:
            return self.plugin_groups[name]
        category = plugin_info.get('category', 'infra').lower()
        if category == 'web':
            return ('Web', 'Scanner')
        if category == 'vulnerability':
            return ('Web', 'Vulnerabilidades')
        return ('Infra', 'Scanner')

    def _ensure_prerequisites(self, plugin_name: str) -> bool:
        """Garante que pre-requisitos foram executados"""
        prereqs = self.plugin_prereqs.get(plugin_name, [])
        if not prereqs:
            return True

        executed = set(self.context['executed_plugins'])
        missing = [p for p in prereqs if p not in executed]
        if not missing:
            return True

        missing_str = ", ".join(missing)
        if not Confirm.ask(
            f"[yellow]Este plugin requer: {missing_str}. Executar agora?[/yellow]",
            default=True
        ):
            rprint("[yellow]⏭️ Pre-requisitos nao executados. Plugin ignorado.[/yellow]")
            return False

        for prereq in missing:
            if not self.plugin_manager.get_plugin(prereq):
                rprint(f"[red]❌ Pre-requisito nao encontrado: {prereq}[/red]")
                return False
            self._execute_plugin(prereq, skip_prereq_check=True)

        return True

    def _execute_plugin(self, plugin_name: str, skip_prereq_check: bool = False):
        """Executa um plugin e mostra resultados detalhados"""
        self.console.print(f"\n[bold cyan]{'═' * 50}[/bold cyan]")
        self.console.print(f"[bold cyan]🔌 Executando: {plugin_name}[/bold cyan]")
        self.console.print(f"[bold cyan]{'═' * 50}[/bold cyan]")

        plugin = self.plugin_manager.get_plugin(plugin_name)
        if not plugin:
            rprint(f"[red]❌ Plugin não encontrado![/red]")
            return

        # Checar pre-requisitos
        if not skip_prereq_check and not self._ensure_prerequisites(plugin_name):
            return

        cached = self.storage.get_cached_result(self.context['target'], plugin_name)
        if cached and not skip_prereq_check:
            if Confirm.ask(
                f"[yellow]Resultado salvo encontrado para {plugin_name}. Usar cache?[/yellow]",
                default=True
            ):
                try:
                    result = PluginResult(**cached)
                except TypeError:
                    result = None
                if result:
                    if plugin_name not in self.context['executed_plugins']:
                        self.context['executed_plugins'].append(plugin_name)
                    self.context['plugin_states'][plugin_name] = 'success' if result.success else 'failed'
                    self._show_plugin_result_details(result)
                    self._update_context_with_result(result)
                    return

        # Executar plugin
        start_time = time.time()
        rprint(f"[dim]⏳ Executando {plugin_name}...[/dim]")

        try:
            result = self.plugin_manager.execute_plugin(
                plugin_name,
                self.context['target'],
                self.context
            )

            execution_time = time.time() - start_time

            self.context['executed_plugins'].append(plugin_name)

            if result.success:
                self.context['plugin_states'][plugin_name] = 'success'
                rprint(f"\n[green]✅ Concluído em {execution_time:.1f}s[/green]")

                # Mostrar resultados DETALHADOS do plugin
                self._show_plugin_result_details(result)

                # Atualizar contexto
                self._update_context_with_result(result)
                self.storage.set_cached_result(self.context['target'], plugin_name, result.to_dict())
                
            else:
                self.context['plugin_states'][plugin_name] = 'failed'
                rprint(f"\n[red]❌ Falhou após {execution_time:.1f}s[/red]")
                rprint(f"[red]Erro: {result.error}[/red]")
                self.context['errors'].append({
                    'plugin': plugin_name,
                    'error': result.error,
                    'timestamp': result.timestamp
                })

        except Exception as e:
            rprint(f"[red]💥 Erro inesperado: {e}[/red]")
            self.context['errors'].append({
                'plugin': plugin_name,
                'error': str(e),
                'timestamp': time.time()
            })

    def _vuln_key(self, vuln: Dict[str, Any]) -> str:
        """Gera uma chave consistente para deduplicar vulnerabilidades"""
        return "|".join([
            str(vuln.get('title', '')),
            str(vuln.get('cve', '')),
            str(vuln.get('host', '')),
            str(vuln.get('port', '')),
            str(vuln.get('url', ''))
        ])
    
    def _show_final_summary(self, result: Dict):
        """Mostra resumo final da varredura"""
        self.console.clear()
        
        discoveries = self.context['discoveries']
        vulns = self.context['vulnerabilities']
        
        self.console.print(Panel.fit(
            "[bold green]✅ Varredura Concluída[/bold green]",
            border_style="green"
        ))
        
        summary_table = Table(title="📊 Resumo Final", show_header=True, header_style="bold green")
        summary_table.add_column("Métrica", style="cyan")
        summary_table.add_column("Valor", style="white")
        
        summary_table.add_row("Alvo", self.context['target'])
        summary_table.add_row("Duração", f"{result['duration_seconds']:.1f} segundos")
        summary_table.add_row("Plugins Executados", str(result['plugins_executed']))
        summary_table.add_row("Hosts Descobertos", str(len(discoveries['hosts'])))
        summary_table.add_row("Portas Abertas", str(len(discoveries['open_ports'])))
        summary_table.add_row("Serviços", str(len(discoveries['services'])))
        summary_table.add_row("Tecnologias", str(len(discoveries['technologies'])))
        summary_table.add_row("Vulnerabilidades", str(len(vulns)))
        summary_table.add_row("Erros", str(len(self.context['errors'])))
        
        self.console.print(summary_table)
        
        # Listar vulnerabilidades se houver
        if vulns:
            vuln_table = Table(title="⚠️ Vulnerabilidades Encontradas", show_header=True, header_style="bold red")
            vuln_table.add_column("Severidade", style="bold")
            vuln_table.add_column("Descrição", style="white")
            
            for vuln in vulns[:10]:
                severity = vuln.get('severity', 'unknown').upper()
                if severity in ['CRITICAL', 'HIGH']:
                    sev_style = "[red]"
                elif severity == 'MEDIUM':
                    sev_style = "[yellow]"
                else:
                    sev_style = "[dim]"
                
                desc = vuln.get('description', vuln.get('title', 'N/A'))[:80]
                vuln_table.add_row(f"{sev_style}{severity}[/]", desc)
            
            if len(vulns) > 10:
                vuln_table.add_row("...", f"+ {len(vulns) - 10} vulnerabilidades adicionais")
            
            self.console.print(vuln_table)
        
        rprint(f"\n[bold green]📄 Relatório salvo em: {result.get('report_path', 'N/A')}[/bold green]")
    
    def _generate_report(self) -> str:
        """Gera relatório final e retorna caminho do arquivo"""
        data_dir = Path(get_config('output.data_dir', 'dados'))
        data_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime(get_config('output.timestamp_format', '%Y%m%d_%H%M%S'))
        report_file = data_dir / f"scan_{timestamp}.json"
        
        # Preparar dados do relatório
        start_time = self.context.get('start_time')
        if isinstance(start_time, str):
            try:
                start_time = datetime.fromisoformat(start_time)
            except ValueError:
                start_time = datetime.now()
        if start_time is None:
            start_time = datetime.now()

        report_data = {
            'metadata': {
                'target': self.context['target'],
                'start_time': start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': (datetime.now() - start_time).total_seconds(),
                'mode': 'interactive'
            },
            'execution': {
                'plugins_executed': self.context['executed_plugins'],
                'plugin_states': self.context['plugin_states'],
                'errors': self.context['errors']
            },
            'discoveries': self.context['discoveries'],
            'vulnerabilities': self.context['vulnerabilities'],
            'detailed_results': {
                name: {
                    'success': result.success,
                    'execution_time': result.execution_time,
                    'data': result.data,
                    'error': result.error
                }
                for name, result in self.results.items()
            }
        }
        
        # Salvar relatório
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        self.logger.info(f"📄 Relatório salvo: {report_file}")
        return str(report_file)
