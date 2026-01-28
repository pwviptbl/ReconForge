#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconForge
Sistema de pentest com seleção manual de plugins via menu interativo.
"""

import sys
import argparse
import textwrap
import logging
from pathlib import Path

# Adicionar diretório atual ao path
sys.path.insert(0, str(Path(__file__).parent))

from core.minimal_orchestrator import MinimalOrchestrator
from core.storage import Storage
from core.config import get_config
from utils.logger import setup_logger


def _format_plugin_help(orchestrator: MinimalOrchestrator) -> tuple[str, list[str]]:
    catalog = orchestrator.get_plugin_catalog(target=None, include_unvalidated=True)
    order = orchestrator.get_ordered_plugins(target=None)
    info_map = {info['name']: info for info in catalog}
    lines = ["Plugins disponíveis (numeração para --plugins):"]
    for idx, name in enumerate(order, 1):
        info = info_map.get(name, {})
        desc = (info.get('description') or '').strip()
        if desc:
            desc = desc[:60]
            lines.append(f"  {idx:2} - {name} ({desc})")
        else:
            lines.append(f"  {idx:2} - {name}")
    return "\n".join(lines), order


def _parse_plugins_arg(raw: str, ordered_plugins: list[str]) -> tuple[list[str], list[str]]:
    if not raw:
        return [], []

    selected = []
    invalid = []
    items = [item.strip() for item in raw.split(',') if item.strip()]
    number_map = {idx: name for idx, name in enumerate(ordered_plugins, 1)}

    for item in items:
        if item.isdigit():
            num = int(item)
            if num in number_map:
                selected.append(number_map[num])
            else:
                invalid.append(item)
            continue

        lowered = item.lower()
        exact = [name for name in ordered_plugins if name.lower() == lowered]
        if len(exact) == 1:
            selected.append(exact[0])
            continue

        partial = [name for name in ordered_plugins if lowered in name.lower()]
        if len(partial) == 1:
            selected.append(partial[0])
        else:
            invalid.append(item)

    return selected, invalid


def run_interactive_menu() -> int:
    """Executa o menu interativo atual"""
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


def main():
    """Função principal"""
    try:
        logging.disable(logging.CRITICAL)
        help_orchestrator = MinimalOrchestrator(quiet=True)
        logging.disable(logging.NOTSET)
        plugin_help, plugin_order = _format_plugin_help(help_orchestrator)

        parser = argparse.ArgumentParser(
            description='ReconForge - Orquestrador de plugins de pentest',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent(plugin_help)
        )
        parser.add_argument('target', nargs='?', help='Alvo (IP, domínio, URL ou CIDR)')
        parser.add_argument('--plugins', help='Lista de plugins por número ou nome (ex: 1,2,4)')
        parser.add_argument('--list-plugins', action='store_true', help='Lista plugins disponíveis e sai')
        parser.add_argument('--no-cache', action='store_true', help='Ignora resultados em cache (modo não interativo)')

        args = parser.parse_args()

        if args.list_plugins:
            print(plugin_help)
            return 0

        if args.plugins and not args.target:
            print("❌ Você deve informar um alvo ao usar --plugins.")
            return 2

        if not args.target:
            return run_interactive_menu()

        setup_logger('ReconForge', verbose=True)

        selected_plugins = None
        if args.plugins:
            selected_plugins, invalid = _parse_plugins_arg(args.plugins, plugin_order)
            if invalid:
                print(f"❌ Plugins inválidos: {', '.join(invalid)}")
                return 2

        orchestrator = MinimalOrchestrator(verbose=True)
        result = orchestrator.run_non_interactive(
            target=args.target,
            selected_plugins=selected_plugins,
            use_cache=not args.no_cache
        )

        return 0 if result.get('success') else 1

    except KeyboardInterrupt:
        print("\n🛑 Operação cancelada pelo usuário")
        return 1


if __name__ == "__main__":
    sys.exit(main())
