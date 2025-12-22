"""
Orquestrador Minimalista do VarreduraIA
Versão sem IA, com seleção manual de plugins via menu interativo
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
        self.active_plugins: Set[str] = set()  # Plugins ativos selecionados pelo usuário
        
        self.logger.info("🎯 VarreduraIA Orquestrador Minimalista inicializado")
    
    def run_interactive(self, target: str) -> Dict[str, Any]:
        """
        Executa pentest com seleção interativa de plugins
        
        Args:
            target: Alvo da varredura
            
        Returns:
            Dict com resultados do pentest
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
            # Menu principal de seleção de plugins
            self._show_plugin_selection_menu()
            
            if not self.active_plugins:
                rprint("[yellow]⚠️ Nenhum plugin selecionado. Encerrando.[/yellow]")
                return {'success': False, 'error': 'Nenhum plugin selecionado'}
            
            # Loop de execução
            self._run_execution_loop()
            
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
            return {
                'success': False,
                'error': str(e),
                'target': target,
                'context': self.context
            }
    
    def _show_plugin_selection_menu(self):
        """Mostra menu de seleção de plugins"""
        while True:
            self.console.clear()
            
            # Cabeçalho
            self.console.print(Panel.fit(
                f"[bold cyan]🔌 Seleção de Plugins[/bold cyan]\n"
                f"[dim]Alvo: {self.context['target']}[/dim]",
                border_style="cyan"
            ))
            
            # Obter todos os plugins disponíveis
            all_plugins = self._get_all_plugins_info()
            
            # Agrupar por categoria
            categories = {}
            for plugin in all_plugins:
                cat = plugin.get('category', 'outros')
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(plugin)
            
            # Mostrar tabela de plugins por categoria
            for category, plugins in sorted(categories.items()):
                table = Table(title=f"📂 {category.upper()}", show_header=True, header_style="bold magenta")
                table.add_column("#", style="dim", width=4)
                table.add_column("Plugin", style="cyan", no_wrap=True)
                table.add_column("Status", style="bold", width=10)
                table.add_column("Descrição", style="white")
                
                for i, plugin in enumerate(plugins):
                    status = "[green]✅ ATIVO[/green]" if plugin['name'] in self.active_plugins else "[red]❌[/red]"
                    table.add_row(
                        str(i + 1),
                        plugin['name'],
                        status,
                        plugin.get('description', 'N/A')[:50]
                    )
                
                self.console.print(table)
                self.console.print()
            
            # Estatísticas
            rprint(f"\n[bold]📊 Plugins ativos: {len(self.active_plugins)}/{len(all_plugins)}[/bold]")
            
            # Menu de opções
            rprint("\n[bold yellow]Opções:[/bold yellow]")
            rprint("  [cyan]1-N[/cyan]  - Toggle plugin por número (ex: 1, 5, 12)")
            rprint("  [cyan]nome[/cyan] - Toggle plugin por nome (ex: NmapScannerPlugin)")
            rprint("  [cyan]cat:X[/cyan]- Toggle todos de uma categoria (ex: cat:network)")
            rprint("  [cyan]all[/cyan]  - Ativar todos os plugins")
            rprint("  [cyan]none[/cyan] - Desativar todos os plugins")
            rprint("  [cyan]run[/cyan]  - Iniciar execução")
            rprint("  [cyan]quit[/cyan] - Sair sem executar")
            
            # Input do usuário
            choice = Prompt.ask("\n[bold green]👉 Escolha[/bold green]").strip().lower()
            
            if choice == 'quit' or choice == 'q':
                self.active_plugins.clear()
                break
            
            elif choice == 'run' or choice == 'r':
                if self.active_plugins:
                    break
                else:
                    rprint("[red]❌ Selecione pelo menos um plugin![/red]")
                    time.sleep(1)
            
            elif choice == 'all':
                self.active_plugins = set(p['name'] for p in all_plugins)
                rprint("[green]✅ Todos os plugins ativados![/green]")
                time.sleep(0.5)
            
            elif choice == 'none':
                self.active_plugins.clear()
                rprint("[yellow]❌ Todos os plugins desativados![/yellow]")
                time.sleep(0.5)
            
            elif choice.startswith('cat:'):
                category = choice[4:].strip()
                if category in categories:
                    for plugin in categories[category]:
                        if plugin['name'] in self.active_plugins:
                            self.active_plugins.discard(plugin['name'])
                        else:
                            self.active_plugins.add(plugin['name'])
                    rprint(f"[cyan]🔄 Categoria '{category}' alterada[/cyan]")
                else:
                    rprint(f"[red]❌ Categoria '{category}' não encontrada[/red]")
                time.sleep(0.5)
            
            else:
                # Tentar como número ou nome
                self._toggle_plugin(choice, all_plugins)
                time.sleep(0.3)
    
    def _toggle_plugin(self, choice: str, all_plugins: List[Dict]):
        """Toggle um plugin por número ou nome"""
        # Tentar como número
        try:
            num = int(choice)
            if 1 <= num <= len(all_plugins):
                plugin_name = all_plugins[num - 1]['name']
                if plugin_name in self.active_plugins:
                    self.active_plugins.discard(plugin_name)
                    rprint(f"[red]❌ {plugin_name} desativado[/red]")
                else:
                    self.active_plugins.add(plugin_name)
                    rprint(f"[green]✅ {plugin_name} ativado[/green]")
                return
        except ValueError:
            pass
        
        # Tentar como nome (busca parcial)
        for plugin in all_plugins:
            if choice.lower() in plugin['name'].lower():
                plugin_name = plugin['name']
                if plugin_name in self.active_plugins:
                    self.active_plugins.discard(plugin_name)
                    rprint(f"[red]❌ {plugin_name} desativado[/red]")
                else:
                    self.active_plugins.add(plugin_name)
                    rprint(f"[green]✅ {plugin_name} ativado[/green]")
                return
        
        rprint(f"[red]❌ Plugin '{choice}' não encontrado[/red]")
    
    def _get_all_plugins_info(self) -> List[Dict[str, Any]]:
        """Obtém informações de todos os plugins"""
        plugins_info = []
        for plugin_name, plugin in self.plugin_manager.plugins.items():
            plugins_info.append(plugin.get_info())
        return sorted(plugins_info, key=lambda x: (x.get('category', 'z'), x['name']))
    
    def _run_execution_loop(self):
        """Executa os plugins ativos em sequência"""
        self.console.clear()
        
        self.console.print(Panel.fit(
            f"[bold green]🚀 Executando Varredura[/bold green]\n"
            f"[dim]Alvo: {self.context['target']} | Plugins: {len(self.active_plugins)}[/dim]",
            border_style="green"
        ))
        
        plugins_to_run = list(self.active_plugins)
        total = len(plugins_to_run)
        
        for i, plugin_name in enumerate(plugins_to_run, 1):
            rprint(f"\n[bold cyan]═══ [{i}/{total}] {plugin_name} ═══[/bold cyan]")
            
            # Verificar se o plugin está disponível e é adequado para o alvo
            plugin = self.plugin_manager.get_plugin(plugin_name)
            if not plugin:
                rprint(f"[red]❌ Plugin não encontrado![/red]")
                self.context['errors'].append({
                    'plugin': plugin_name,
                    'error': 'Plugin não encontrado',
                    'timestamp': datetime.now().isoformat()
                })
                continue
            
            if not plugin.validate_target(self.context['target']):
                rprint(f"[yellow]⚠️ Plugin não é adequado para este alvo, pulando...[/yellow]")
                continue
            
            # Executar plugin
            start_time = time.time()
            rprint(f"[dim]⏳ Executando...[/dim]")
            
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
                    self._update_context_with_result(result)
                    rprint(f"[green]✅ Concluído em {execution_time:.1f}s[/green]")
                    
                    # Mostrar resumo das descobertas
                    self._show_plugin_discoveries(result)
                else:
                    self.context['plugin_states'][plugin_name] = 'failed'
                    rprint(f"[red]❌ Falhou: {result.error}[/red]")
                    self.context['errors'].append({
                        'plugin': plugin_name,
                        'error': result.error,
                        'timestamp': result.timestamp
                    })
                    
            except Exception as e:
                self.logger.error(f"💥 Erro ao executar {plugin_name}: {e}")
                self.context['errors'].append({
                    'plugin': plugin_name,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
                rprint(f"[red]💥 Erro: {e}[/red]")
        
        rprint("\n[bold green]════════════════════════════════════════[/bold green]")
        rprint("[bold green]       Execução dos plugins concluída![/bold green]")
        rprint("[bold green]════════════════════════════════════════[/bold green]")
    
    def _show_plugin_discoveries(self, result):
        """Mostra as descobertas de um plugin"""
        data = result.data
        
        discoveries = []
        
        if data.get('hosts'):
            discoveries.append(f"Hosts: {len(data['hosts'])}")
        if data.get('open_ports'):
            discoveries.append(f"Portas: {len(data['open_ports'])}")
        if data.get('services'):
            discoveries.append(f"Serviços: {len(data['services'])}")
        if data.get('technologies'):
            discoveries.append(f"Tecnologias: {len(data['technologies'])}")
        if data.get('vulnerabilities'):
            discoveries.append(f"Vulnerabilidades: {len(data['vulnerabilities'])}")
        
        if discoveries:
            rprint(f"[dim]   📊 Descobertas: {', '.join(discoveries)}[/dim]")
    
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
        self.console.print("\n")
        
        # Resumo de descobertas
        discoveries = self.context['discoveries']
        vulns = self.context['vulnerabilities']
        
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
            
            for vuln in vulns[:10]:  # Limitar a 10
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
        report_file = data_dir / f"minimal_scan_{timestamp}.json"
        
        # Preparar dados do relatório
        report_data = {
            'metadata': {
                'target': self.context['target'],
                'start_time': self.context['start_time'].isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': (datetime.now() - self.context['start_time']).total_seconds(),
                'mode': 'minimal-manual'
            },
            'execution': {
                'plugins_selected': list(self.active_plugins),
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
