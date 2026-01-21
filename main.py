#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconForge
Sistema de pentest com seleção manual de plugins via menu interativo.
"""

import sys
from pathlib import Path

# Adicionar diretório atual ao path
sys.path.insert(0, str(Path(__file__).parent))

from core.minimal_orchestrator import MinimalOrchestrator
from core.storage import Storage
from core.config import get_config
from utils.logger import setup_logger


def main():
    """Função principal"""
    from rich.console import Console
    from rich.panel import Panel
    from rich import print as rprint
    
    console = Console()
    
    # Banner
    console.print(Panel.fit(
        "[bold cyan]🔍 ReconForge[/bold cyan]\n"
        "[dim]Sistema de Pentest com Seleção Manual de Plugins[/dim]",
        border_style="cyan"
    ))
    
    try:
        data_dir = Path(get_config('output.data_dir', 'dados'))
        storage = Storage(data_dir / "reconforge.db")

        # Setup logger
        logger = setup_logger('ReconForge', verbose=True)

        while True:
            rprint("\n[bold yellow]Selecione uma opção:[/bold yellow]")
            rprint("  [cyan]1[/cyan] - Nova varredura")
            rprint("  [cyan]2[/cyan] - Carregar sessão")
            rprint("  [cyan]3[/cyan] - Listar alvos salvos")
            rprint("  [cyan]4[/cyan] - Apagar alvo")
            rprint("  [cyan]5[/cyan] - Sair")

            choice = input("👉 Opção: ").strip()

            if choice == '1':
                rprint("\n[bold yellow]🎯 Digite o alvo da varredura:[/bold yellow]")
                rprint("[dim](IP, domínio, URL ou CIDR)[/dim]")
                target = input("👉 Alvo: ").strip()
                if not target:
                    rprint("[red]❌ Alvo não pode ser vazio![/red]")
                    continue
                orchestrator = MinimalOrchestrator(verbose=True)
                result = orchestrator.run_interactive(target=target)
                if result.get('success'):
                    logger.info("✅ Varredura concluída com sucesso!")
                    logger.info(f"📊 Relatório salvo em: {result.get('report_path', 'N/A')}")
                else:
                    logger.error(f"❌ Varredura falhou: {result.get('error', 'Erro desconhecido')}")
                continue

            if choice == '2':
                targets = storage.list_targets_with_ids()
                if not targets:
                    rprint("[yellow]Nenhum alvo salvo ainda.[/yellow]")
                    continue
                rprint("\n[bold cyan]Alvos salvos:[/bold cyan]")
                for run_id, target, updated_at in targets:
                    rprint(f"  • [cyan]{run_id}[/cyan] - {target} [dim]({updated_at})[/dim]")
                choice_id = input("👉 ID da sessão para carregar: ").strip()
                if not choice_id.isdigit():
                    rprint("[yellow]ID inválido.[/yellow]")
                    continue
                loaded = storage.load_run_by_id(int(choice_id))
                if not loaded:
                    rprint("[yellow]Sessão não encontrada.[/yellow]")
                    continue
                run_id, context, results, target = loaded
                orchestrator = MinimalOrchestrator(verbose=True)
                orchestrator.load_session(target, context, results, run_id)
                result = orchestrator.run_interactive(target=target)
                if result.get('success'):
                    logger.info("✅ Varredura concluída com sucesso!")
                    logger.info(f"📊 Relatório salvo em: {result.get('report_path', 'N/A')}")
                else:
                    logger.error(f"❌ Varredura falhou: {result.get('error', 'Erro desconhecido')}")
                continue

            if choice == '3':
                targets = storage.list_targets_with_ids()
                if not targets:
                    rprint("[yellow]Nenhum alvo salvo ainda.[/yellow]")
                    continue
                rprint("\n[bold cyan]Alvos salvos:[/bold cyan]")
                for run_id, target, updated_at in targets:
                    rprint(f"  • [cyan]{run_id}[/cyan] - {target} [dim]({updated_at})[/dim]")
                continue

            if choice == '4':
                targets = storage.list_targets_with_ids()
                if not targets:
                    rprint("[yellow]Nenhum alvo salvo ainda.[/yellow]")
                    continue
                rprint("\n[bold cyan]Alvos salvos:[/bold cyan]")
                for run_id, target, updated_at in targets:
                    rprint(f"  • [cyan]{run_id}[/cyan] - {target} [dim]({updated_at})[/dim]")
                choice_id = input("👉 ID do alvo para apagar: ").strip()
                if not choice_id.isdigit():
                    rprint("[yellow]ID inválido.[/yellow]")
                    continue
                loaded = storage.load_run_by_id(int(choice_id))
                if not loaded:
                    rprint("[yellow]Sessão não encontrada.[/yellow]")
                    continue
                _, _, _, target = loaded
                storage.delete_target(target)
                rprint(f"[green]Alvo apagado: {target}[/green]")
                continue

            if choice == '5':
                return 0

            rprint("[red]❌ Opção inválida![/red]")
            
    except KeyboardInterrupt:
        rprint("\n[yellow]🛑 Operação cancelada pelo usuário[/yellow]")
        return 1
    except Exception as e:
        rprint(f"[red]💥 Erro crítico: {e}[/red]")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
