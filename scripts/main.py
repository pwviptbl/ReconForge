#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconForge
Sistema de pentest com seleção manual de plugins via menu interativo.
"""

import sys
import os
import argparse
import textwrap
import logging
from pathlib import Path

# Garantir execução a partir da raiz do projeto
PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

from core.minimal_orchestrator import MinimalOrchestrator
from core.storage import Storage
from core.config import get_config
from core.workflow_orchestrator import WorkflowOrchestrator, run_pipeline
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


def _select_plugins_for_goal(goal: str, available_plugins: list[str]) -> list[str]:
    """
    Seleciona plugins relevantes baseado no objetivo/orientação informado
    
    Args:
        goal: Objetivo descrito pelo usuário (ex: "encontrar vulnerabilidades web")
        available_plugins: Lista de plugins disponíveis
        
    Returns:
        Lista de plugins selecionados para o objetivo
    """
    goal_lower = goal.lower()
    selected = set()
    
    # Mapeamento de palavras-chave para plugins
    keyword_mapping = {
        # Web/HTTP
        'web': ['DirectoryScannerPlugin', 'WebCrawlerPlugin', 'KatanaCrawlerPlugin', 'GauCollectorPlugin',
                'WebVulnScannerPlugin', 'TechnologyDetectorPlugin', 'HeaderAnalyzerPlugin'],
        'diretório': ['DirectoryScannerPlugin'],
        'directory': ['DirectoryScannerPlugin'],
        'crawl': ['WebCrawlerPlugin'],
        'spider': ['WebCrawlerPlugin'],
        'katana': ['KatanaCrawlerPlugin'],
        'gau': ['GauCollectorPlugin'],
        
        # Vulnerabilidades
        'vuln': ['NucleiScannerPlugin', 'WebVulnScannerPlugin', 'MisconfigurationAnalyzerPlugin'],
        'vulnerabilidade': ['NucleiScannerPlugin', 'WebVulnScannerPlugin', 'MisconfigurationAnalyzerPlugin'],
        'cve': ['ExploitSearcherPlugin', 'ExploitSuggesterPlugin'],
        'exploit': ['ExploitSearcherPlugin', 'ExploitSuggesterPlugin'],
        
        # Rede
        'rede': ['PortScannerPlugin', 'NetworkMapperPlugin', 'NmapScannerPlugin'],
        'network': ['PortScannerPlugin', 'NetworkMapperPlugin', 'NmapScannerPlugin'],
        'porta': ['PortScannerPlugin', 'NmapScannerPlugin', 'PortExposureAuditPlugin'],
        'port': ['PortScannerPlugin', 'NmapScannerPlugin', 'PortExposureAuditPlugin'],
        'scan': ['PortScannerPlugin', 'NmapScannerPlugin'],
        'nmap': ['NmapScannerPlugin'],
        
        # DNS e subdomínios
        'dns': ['DNSResolverPlugin', 'SubdomainEnumeratorPlugin'],
        'subdomain': ['SubdomainEnumeratorPlugin', 'SubfinderPlugin'],
        'subdomínio': ['SubdomainEnumeratorPlugin', 'SubfinderPlugin'],
        
        # SSL/TLS
        'ssl': ['SSLAnalyzerPlugin'],
        'tls': ['SSLAnalyzerPlugin'],
        'certificado': ['SSLAnalyzerPlugin'],
        'https': ['SSLAnalyzerPlugin'],
        
        # Firewall/WAF
        'firewall': ['FirewallDetectorPlugin'],
        'waf': ['FirewallDetectorPlugin'],
        'bypass': ['FirewallDetectorPlugin'],
        
        # SSH
        'ssh': ['SSHPolicyCheckPlugin'],
        
        # Reconhecimento
        'recon': ['ReconnaissancePlugin', 'TechnologyDetectorPlugin', 'WhatWebScannerPlugin'],
        'reconhecimento': ['ReconnaissancePlugin', 'TechnologyDetectorPlugin'],
        'tecnologia': ['TechnologyDetectorPlugin', 'WhatWebScannerPlugin'],
        'technology': ['TechnologyDetectorPlugin', 'WhatWebScannerPlugin'],
        
        # Completo
        'completo': available_plugins,
        'full': available_plugins,
        'tudo': available_plugins,
        'all': available_plugins,
    }
    
    # Buscar plugins baseado nas palavras-chave
    for keyword, plugins in keyword_mapping.items():
        if keyword in goal_lower:
            for plugin in plugins:
                if plugin in available_plugins:
                    selected.add(plugin)
    
    # Se nenhum plugin foi selecionado, usar conjunto padrão
    if not selected:
        default_plugins = ['PortScannerPlugin', 'TechnologyDetectorPlugin']
        for plugin in default_plugins:
            if plugin in available_plugins:
                selected.add(plugin)
    
    # Sempre incluir PortScanner como base (se disponível)
    if 'PortScannerPlugin' in available_plugins:
        selected.add('PortScannerPlugin')
    
    return list(selected)


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
        parser.add_argument('-e', '--exclude-plugins', help='Lista de plugins a EXCLUIR por número ou nome (ex: 15,DirectoryScanner)')
        parser.add_argument('--list-plugins', action='store_true', help='Lista plugins disponíveis e sai')
        parser.add_argument('--no-cache', action='store_true', help='Ignora resultados em cache (modo não interativo)')
        
        # Argumentos de IA
        parser.add_argument('--ai', action='store_true', 
                          help='Habilita modo com IA para seleção inteligente de plugins')
        parser.add_argument('-o', '--orientacao', type=str, metavar='OBJETIVO',
                          help='Orientação/objetivo para a IA (ex: "encontrar vulnerabilidades web")')
        parser.add_argument('--model', type=str, 
                          help='Modelo de IA a usar (ex: gemini-2.5-flash-lite, gpt-4)')
        parser.add_argument('--config', type=str, 
                          help='Arquivo de configuração YAML customizado')

        # Modo pipeline (Fase 1 — WorkflowOrchestrator)
        parser.add_argument(
            '--pipeline',
            action='store_true',
            help=(
                'Executa o novo pipeline orientado a estágios (WorkflowOrchestrator). '
                'Substitui o modo não-interativo clássico. '
                'Compatível com --plugins para restringir estágios de detecção.'
            ),
        )
        parser.add_argument(
            '--recon-plugins',
            type=str,
            metavar='PLUGINS',
            help='Plugins de reconhecimento para o pipeline (ex: NmapScannerPlugin,SubfinderPlugin).',
        )
        parser.add_argument(
            '--detect-plugins',
            type=str,
            metavar='PLUGINS',
            help='Plugins de detecção para o pipeline (ex: XssScannerPlugin,NucleiScannerPlugin).',
        )
        parser.add_argument(
            '--exploit-categories',
            type=str,
            metavar='CATS',
            help='Categorias de exploit a executar (ex: xss,sqli,ssrf). Padrão: todas disponíveis.',
        )
        parser.add_argument(
            '--max-exploit-attempts',
            type=int,
            default=5,
            metavar='N',
            help='Máximo de tentativas de exploit por item da queue (padrão: 5).',
        )

        args = parser.parse_args()

        if args.list_plugins:
            print(plugin_help)
            return 0

        # Validação de argumentos
        if (args.plugins or args.exclude_plugins) and not args.target:
            print("❌ Você deve informar um alvo ao usar --plugins ou --exclude-plugins.")
            return 2
        
        if args.orientacao and not args.ai:
            print("⚠️  Argumento -o/--orientacao requer --ai. Habilitando modo IA automaticamente.")
            args.ai = True
        
        if args.ai and not args.target:
            print("❌ Você deve informar um alvo ao usar --ai.")
            return 2

        if not args.target:
            return run_interactive_menu()

        setup_logger('ReconForge', verbose=True)

        # ----------------------------------------------------------------
        # Modo Pipeline — WorkflowOrchestrator (Fases 1-3)
        # ----------------------------------------------------------------
        if args.pipeline:
            recon_plugins = None
            detect_plugins = None
            exploit_categories = None

            if args.recon_plugins:
                recon_plugins = [p.strip() for p in args.recon_plugins.split(',') if p.strip()]

            if args.detect_plugins:
                detect_plugins = [p.strip() for p in args.detect_plugins.split(',') if p.strip()]
            elif args.plugins:
                # --plugins no modo pipeline mapeia para detect-plugins
                detect_plugins_parsed, invalid = _parse_plugins_arg(args.plugins, plugin_order)
                if invalid:
                    print(f"❌ Plugins inválidos: {', '.join(invalid)}")
                    return 2
                detect_plugins = detect_plugins_parsed if detect_plugins_parsed else None

            if hasattr(args, 'exploit_categories') and args.exploit_categories:
                exploit_categories = [c.strip() for c in args.exploit_categories.split(',') if c.strip()]

            state = run_pipeline(
                target=args.target,
                verbose=True,
                quiet=False,
                recon_plugins=recon_plugins,
                detect_plugins=detect_plugins,
                max_exploit_attempts=getattr(args, 'max_exploit_attempts', 5),
                exploit_categories=exploit_categories,
            )

            summary = state.summary()
            detected_findings = summary.get("findings_detected", len(state.findings) + len(state.rejected_findings))
            validated_findings = summary.get("findings_validated", len(state.findings))
            confirmed = sum(1 for e in state.evidences if e.proof_level == "impact_proven")
            partial_ev = sum(1 for e in state.evidences if e.proof_level == "partial")

            print(f"\n{'='*55}")
            print(f"✅ Pipeline concluído | run_id={summary['run_id']}")
            print(f"   Estágios executados    : {summary['stages_done']}")
            print(f"   Findings detectados    : {detected_findings}")
            print(f"   Findings validados     : {validated_findings}")
            print(f"   Findings descartados   : {len(state.rejected_findings)}")
            print(f"   Items na queue         : {len(state.queue_items)}")
            print(f"   Tentativas de exploit  : {len(state.attempts)}")
            print(f"   Confirmadas (impacto)  : {confirmed}")
            print(f"   Potenciais (parcial)   : {partial_ev}")
            if state.report_path:
                print(f"   Relatório              : {state.report_path}")
            if summary.get('errors'):
                print(f"   Erros                  : {summary['errors']}")
            print(f"{'='*55}")
            return 0 if not state.aborted else 1

        # ----------------------------------------------------------------
        # Modo clássico (MinimalOrchestrator) — mantido intacto
        # ----------------------------------------------------------------
        excluded_plugins = []
        if args.exclude_plugins:
            excluded_plugins, invalid_excluded = _parse_plugins_arg(args.exclude_plugins, plugin_order)
            if invalid_excluded:
                print(f"❌ Plugins para exclusão inválidos: {', '.join(invalid_excluded)}")
                return 2
            print(f"🚫 Plugins excluídos: {', '.join(excluded_plugins)}")

        if args.ai:
            from core.config import get_config, Config
            
            # Carregar configuração
            if args.config:
                config = Config(args.config)
            else:
                config = Config()
            
            # Verificar se IA está habilitada na config
            ai_enabled = config.get('ai.gemini.enabled', False)
            api_key = config.get('ai.gemini.api_key', '')
            
            if not ai_enabled:
                print("❌ IA não está habilitada na configuração. Edite config/default.yaml")
                print("   e defina: ai.gemini.enabled: true")
                return 2
            
            if not api_key:
                print("❌ API Key não configurada. Edite config/default.yaml")
                print("   e defina: ai.gemini.api_key: SUA_API_KEY")
                return 2
            
            # Override do modelo se especificado
            model = args.model or config.get('ai.gemini.model', 'gemini-2.5-flash-lite')
            
            print(f"🤖 Modo IA habilitado")
            print(f"   Modelo: {model}")
            if args.orientacao:
                print(f"   Orientação: {args.orientacao}")
            
            # TODO: Implementar AIOrchestrator
            # Por agora, usar MinimalOrchestrator com seleção inteligente baseada na orientação
            orchestrator = MinimalOrchestrator(verbose=True)
            
            # Se tem orientação, selecionar plugins relevantes
            selected_plugins = None
            if args.orientacao:
                selected_plugins = _select_plugins_for_goal(args.orientacao, plugin_order)
                if selected_plugins:
                    print(f"   Plugins sugeridos pela IA: {', '.join(selected_plugins)}")
            
            # Aplicar exclusões na seleção da IA
            if selected_plugins and excluded_plugins:
                selected_plugins = [p for p in selected_plugins if p not in excluded_plugins]
            
            # Se a IA não selecionou nada específico (None), a exclusão deve ser aplicada sobre "todos"
            # Mas o orchestrator.run_non_interactive trata None como "todos".
            # Se tivermos exclusões, não podemos passar None, temos que passar All - Excluded.
            if selected_plugins is None and excluded_plugins:
                selected_plugins = [p for p in plugin_order if p not in excluded_plugins]

            result = orchestrator.run_non_interactive(
                target=args.target,
                selected_plugins=selected_plugins,
                use_cache=not args.no_cache
            )
        else:
            # Modo padrão (sem IA)
            selected_plugins = None
            if args.plugins:
                selected_plugins, invalid = _parse_plugins_arg(args.plugins, plugin_order)
                if invalid:
                    print(f"❌ Plugins inválidos: {', '.join(invalid)}")
                    return 2

            # Aplicar exclusões
            if excluded_plugins:
                # Se nenhum plugin foi explicitamente selecionado, implica "todos"
                if selected_plugins is None:
                    selected_plugins = plugin_order[:] # Cópia da lista completa
                
                # Filtrar exclusões
                selected_plugins = [p for p in selected_plugins if p not in excluded_plugins]

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
