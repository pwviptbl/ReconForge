#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utilitário para gerenciar plugins do ReconForge
Permite listar, habilitar, desabilitar e configurar plugins
"""

import sys
import argparse
from pathlib import Path
import json
import yaml

# Adicionar diretório atual ao path
sys.path.insert(0, str(Path(__file__).parent))

from core.plugin_manager import PluginManager
from core.config import get_config
from utils.logger import setup_logger
from rich.console import Console
from rich.table import Table
from rich import print as rprint


def list_plugins(plugin_manager: PluginManager, console: Console):
    """Lista todos os plugins e seus status"""
    
    # Criar tabela
    table = Table(title="🔌 Plugins ReconForge")
    table.add_column("Plugin", style="cyan", no_wrap=True)
    table.add_column("Status", style="bold")
    table.add_column("Categoria", style="magenta")
    table.add_column("Descrição", style="white")
    table.add_column("Versão", style="dim")
    
    # Obter status de todos os plugins
    enabled_status = plugin_manager.list_enabled_plugins()
    
    # Adicionar plugins carregados (habilitados)
    for plugin_name, plugin in plugin_manager.plugins.items():
        table.add_row(
            plugin.__class__.__name__,
            "[green]✅ Habilitado[/green]",
            plugin.category,
            plugin.description or "N/A",
            plugin.version
        )
    
    # Adicionar plugins desabilitados
    for plugin_class_name, is_enabled in enabled_status.items():
        if not is_enabled:
            table.add_row(
                plugin_class_name,
                "[red]❌ Desabilitado[/red]",
                "N/A",
                "N/A",
                "N/A"
            )
    
    console.print(table)
    
    # Estatísticas
    total_plugins = len(enabled_status)
    enabled_count = sum(1 for status in enabled_status.values() if status)
    disabled_count = total_plugins - enabled_count
    
    rprint(f"\n📊 [bold]Estatísticas:[/bold]")
    rprint(f"   Total: {total_plugins} plugins")
    rprint(f"   Habilitados: {enabled_count}")
    rprint(f"   Desabilitados: {disabled_count}")


def enable_plugin(plugin_manager: PluginManager, plugin_name: str):
    """Habilita um plugin"""
    if plugin_manager.enable_plugin(plugin_name):
        rprint(f"[green]✅ Plugin {plugin_name} habilitado com sucesso![/green]")
        rprint("[yellow]💡 Execute o programa novamente para carregar o plugin.[/yellow]")
    else:
        rprint(f"[red]❌ Falha ao habilitar plugin {plugin_name}[/red]")


def disable_plugin(plugin_manager: PluginManager, plugin_name: str):
    """Desabilita um plugin"""
    if plugin_manager.disable_plugin(plugin_name):
        rprint(f"[red]❌ Plugin {plugin_name} desabilitado com sucesso![/red]")
    else:
        rprint(f"[red]❌ Falha ao desabilitar plugin {plugin_name}[/red]")


def show_plugin_config(plugin_manager: PluginManager, plugin_name: str):
    """Mostra configuração de um plugin"""
    config = plugin_manager.get_plugin_config(plugin_name)
    
    if config:
        rprint(f"[bold cyan]🔧 Configuração do plugin {plugin_name}:[/bold cyan]")
        
        # Formatar como YAML para melhor legibilidade
        yaml_output = yaml.dump(config, default_flow_style=False, allow_unicode=True)
        rprint(f"[dim]{yaml_output}[/dim]")
    else:
        rprint(f"[yellow]⚠️ Plugin {plugin_name} não possui configuração específica[/yellow]")


def update_plugin_config(plugin_manager: PluginManager, plugin_name: str, config_file: str):
    """Atualiza configuração de um plugin via arquivo"""
    try:
        config_path = Path(config_file)
        if not config_path.exists():
            rprint(f"[red]❌ Arquivo de configuração não encontrado: {config_file}[/red]")
            return
        
        # Carregar nova configuração
        with open(config_path, 'r', encoding='utf-8') as f:
            if config_path.suffix.lower() == '.json':
                new_config = json.load(f)
            else:  # YAML
                new_config = yaml.safe_load(f)
        
        # Atualizar configuração
        if plugin_manager.update_plugin_config(plugin_name, new_config):
            rprint(f"[green]✅ Configuração do plugin {plugin_name} atualizada![/green]")
        else:
            rprint(f"[red]❌ Falha ao atualizar configuração do plugin {plugin_name}[/red]")
            
    except Exception as e:
        rprint(f"[red]❌ Erro ao processar arquivo de configuração: {e}[/red]")


def show_categories(plugin_manager: PluginManager):
    """Mostra categorias de plugins"""
    categories = plugin_manager.get_plugin_categories()
    
    rprint("[bold cyan]📂 Categorias de plugins disponíveis:[/bold cyan]")
    for category in categories:
        plugins_in_category = [
            name for name, plugin in plugin_manager.plugins.items()
            if plugin.category == category
        ]
        rprint(f"   {category}: {len(plugins_in_category)} plugins")


def export_config(plugin_manager: PluginManager, output_file: str):
    """Exporta configuração atual dos plugins"""
    try:
        # Preparar dados para exportação
        export_data = {
            'plugins': {
                'enabled': plugin_manager.list_enabled_plugins(),
                'config': {}
            }
        }
        
        # Adicionar configurações específicas
        all_plugin_configs = get_config('plugins.config', {})
        export_data['plugins']['config'] = all_plugin_configs
        
        # Salvar arquivo
        output_path = Path(output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            if output_path.suffix.lower() == '.json':
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            else:  # YAML
                yaml.dump(export_data, f, default_flow_style=False, allow_unicode=True)
        
        rprint(f"[green]✅ Configuração exportada para: {output_file}[/green]")
        
    except Exception as e:
        rprint(f"[red]❌ Erro ao exportar configuração: {e}[/red]")


def main():
    """Função principal"""
    parser = argparse.ArgumentParser(
        description='Gerenciador de Plugins ReconForge',
        epilog="""
Exemplos:
  %(prog)s list                                    # Listar todos os plugins
  %(prog)s enable DNSResolverPlugin               # Habilitar plugin específico
  %(prog)s disable NucleiScannerPlugin           # Desabilitar plugin específico
  %(prog)s config DNSResolverPlugin              # Mostrar configuração do plugin
  %(prog)s config DNSResolverPlugin config.yaml # Atualizar configuração do plugin
  %(prog)s categories                            # Mostrar categorias disponíveis
  %(prog)s export plugins_config.yaml           # Exportar configuração atual
        """
    )
    
    parser.add_argument('action', choices=['list', 'enable', 'disable', 'config', 'categories', 'export'],
                       help='Ação a executar')
    parser.add_argument('plugin_name', nargs='?', help='Nome do plugin (para enable/disable/config)')
    parser.add_argument('config_file', nargs='?', help='Arquivo de configuração (para config/export)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Output verboso')
    
    args = parser.parse_args()
    
    # Setup
    logger = setup_logger('PluginManager', verbose=args.verbose)
    console = Console()
    
    try:
        # Inicializar gerenciador de plugins
        plugin_manager = PluginManager()
        
        # Executar ação
        if args.action == 'list':
            list_plugins(plugin_manager, console)
            
        elif args.action == 'enable':
            if not args.plugin_name:
                rprint("[red]❌ Nome do plugin é obrigatório para habilitar[/red]")
                return 1
            enable_plugin(plugin_manager, args.plugin_name)
            
        elif args.action == 'disable':
            if not args.plugin_name:
                rprint("[red]❌ Nome do plugin é obrigatório para desabilitar[/red]")
                return 1
            disable_plugin(plugin_manager, args.plugin_name)
            
        elif args.action == 'config':
            if not args.plugin_name:
                rprint("[red]❌ Nome do plugin é obrigatório para configuração[/red]")
                return 1
            
            if args.config_file:
                update_plugin_config(plugin_manager, args.plugin_name, args.config_file)
            else:
                show_plugin_config(plugin_manager, args.plugin_name)
                
        elif args.action == 'categories':
            show_categories(plugin_manager)
            
        elif args.action == 'export':
            if not args.plugin_name:
                rprint("[red]❌ Nome do arquivo de saída é obrigatório para exportar[/red]")
                return 1
            export_config(plugin_manager, args.plugin_name)
        
        return 0
        
    except KeyboardInterrupt:
        rprint("\n[yellow]🛑 Operação cancelada pelo usuário[/yellow]")
        return 1
    except Exception as e:
        rprint(f"[red]💥 Erro: {e}[/red]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
