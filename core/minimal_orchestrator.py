"""
Orquestrador Minimalista do VarreduraIA
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
        
        # Estado do pentest
        self.context = {}
        self.results = {}
        
        self.logger.info("🎯 VarreduraIA Orquestrador inicializado")
    
    def run_interactive(self, target: str) -> Dict[str, Any]:
        """
        Executa pentest com seleção interativa de plugins
        O usuário escolhe um plugin por vez, vê os resultados e decide o próximo
        """
        self.logger.info(f"🚀 Iniciando varredura: {target}")
        
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
            f"[bold cyan]🔍 VarreduraIA - Análise Interativa[/bold cyan]\n"
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
        
        # Mostrar descobertas detalhadas se houver
        if discoveries['hosts'] or discoveries['open_ports'] or discoveries['services']:
            self.console.print("\n[bold]═══ Descobertas Atuais ═══[/bold]")
            
            # Hosts
            if discoveries['hosts']:
                hosts_str = ", ".join(str(h) for h in discoveries['hosts'][:10])
                if len(discoveries['hosts']) > 10:
                    hosts_str += f" (+{len(discoveries['hosts']) - 10})"
                rprint(f"  [green]Hosts:[/green] {hosts_str}")
            
            # Portas com serviços
            if discoveries['open_ports'] or discoveries['services']:
                self._show_ports_services_summary()
            
            # Tecnologias
            if discoveries['technologies']:
                techs = list(set(discoveries['technologies']))[:10]
                techs_str = ", ".join(str(t) for t in techs)
                if len(discoveries['technologies']) > 10:
                    techs_str += f" (+{len(discoveries['technologies']) - 10})"
                rprint(f"  [magenta]Tecnologias:[/magenta] {techs_str}")
        
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
        
        # Agrupar por categoria
        categories = {}
        for plugin in available:
            cat = plugin.get('category', 'outros')
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(plugin)
        
        # Contador global para numeração
        idx = 1
        plugin_map = {}
        
        for category, plugins in sorted(categories.items()):
            rprint(f"\n  [bold magenta]📂 {category.upper()}[/bold magenta]")
            for plugin in plugins:
                name = plugin['name']
                desc = plugin.get('description', '')[:40]
                rprint(f"    [cyan]{idx:2}[/cyan] - {name} [dim]({desc})[/dim]")
                plugin_map[idx] = name
                plugin_map[name.lower()] = name
                idx += 1
        
        self._plugin_map = plugin_map
        
        # Opções adicionais
        rprint("\n[bold yellow]Outras opções:[/bold yellow]")
        rprint("  [cyan]r[/cyan] - Ver resultados detalhados de plugins executados")
        rprint("  [cyan]s[/cyan] - Ver lista completa de serviços")
        rprint("  [cyan]v[/cyan] - Ver todas as vulnerabilidades")
        rprint("  [cyan]q[/cyan] - Encerrar varredura")
    
    def _get_available_plugins(self) -> List[Dict]:
        """Retorna plugins ainda não executados"""
        executed = set(self.context['executed_plugins'])
        available = []
        
        for plugin_name, plugin in self.plugin_manager.plugins.items():
            if plugin_name not in executed:
                if plugin.validate_target(self.context['target']):
                    available.append(plugin.get_info())
        
        return sorted(available, key=lambda x: (x.get('category', 'z'), x['name']))
    
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
    
    def _execute_plugin(self, plugin_name: str):
        """Executa um plugin e mostra resultados detalhados"""
        self.console.print(f"\n[bold cyan]{'═' * 50}[/bold cyan]")
        self.console.print(f"[bold cyan]🔌 Executando: {plugin_name}[/bold cyan]")
        self.console.print(f"[bold cyan]{'═' * 50}[/bold cyan]")
        
        plugin = self.plugin_manager.get_plugin(plugin_name)
        if not plugin:
            rprint(f"[red]❌ Plugin não encontrado![/red]")
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
            self.logger.error(f"💥 Erro ao executar {plugin_name}: {e}")
            rprint(f"[red]💥 Erro: {e}[/red]")
            self.context['errors'].append({
                'plugin': plugin_name,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
    
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
        
        # Dados brutos (resumo)
        other_keys = [k for k in data.keys() if k not in ['hosts', 'open_ports', 'services', 'technologies', 'vulnerabilities', 'raw_output']]
        if other_keys:
            rprint(f"\n  [dim][bold]📋 Outros dados:[/bold] {', '.join(other_keys)}[/dim]")
    
    def _show_detailed_results(self):
        """Mostra resultados detalhados de todos os plugins executados"""
        self.console.clear()
        
        if not self.results:
            rprint("[yellow]Nenhum plugin foi executado ainda.[/yellow]")
            input("\nPressione ENTER para voltar...")
            return
        
        self.console.print(Panel.fit(
            "[bold]📋 Resultados Detalhados dos Plugins[/bold]",
            border_style="cyan"
        ))
        
        for plugin_name, result in self.results.items():
            self.console.print(f"\n[bold cyan]═══ {plugin_name} ═══[/bold cyan]")
            self._show_plugin_result_details(result)
        
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
        
        # Agrupar por severidade
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': [], 'UNKNOWN': []}
        for vuln in vulns:
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
            self.context['vulnerabilities'].extend(data['vulnerabilities'])
        
        # Armazenar resultado completo
        self.results[result.plugin_name] = result
    
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
        report_data = {
            'metadata': {
                'target': self.context['target'],
                'start_time': self.context['start_time'].isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': (datetime.now() - self.context['start_time']).total_seconds(),
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
