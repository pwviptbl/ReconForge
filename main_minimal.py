#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VarreduraIA - Versão Minimalista
Sistema de pentest com seleção manual de plugins via menu interativo.
Remove a dependência da IA para tomada de decisões.
"""

import sys
from pathlib import Path

# Adicionar diretório atual ao path
sys.path.insert(0, str(Path(__file__).parent))

from core.minimal_orchestrator import MinimalOrchestrator
from utils.logger import setup_logger


def main():
    """Função principal"""
    from rich.console import Console
    from rich.panel import Panel
    from rich import print as rprint
    
    console = Console()
    
    # Banner
    console.print(Panel.fit(
        "[bold cyan]VarreduraIA - Modo Minimalista[/bold cyan]\n"
        "[dim]Sistema de Pentest com Seleção Manual de Plugins[/dim]",
        border_style="cyan"
    ))
    
    # Solicitar alvo
    rprint("\n[bold yellow]🎯 Digite o alvo da varredura:[/bold yellow]")
    rprint("[dim](IP, domínio, URL ou CIDR)[/dim]")
    
    try:
        target = input("👉 Alvo: ").strip()
        
        if not target:
            rprint("[red]❌ Alvo não pode ser vazio![/red]")
            return 1
        
        # Setup logger
        logger = setup_logger('VarreduraIA', verbose=True)
        
        # Criar orquestrador minimalista
        orchestrator = MinimalOrchestrator(verbose=True)
        
        # Executar pentest
        result = orchestrator.run_interactive(target=target)
        
        if result.get('success'):
            logger.info("✅ Varredura concluída com sucesso!")
            logger.info(f"📊 Relatório salvo em: {result.get('report_path', 'N/A')}")
            return 0
        else:
            logger.error(f"❌ Varredura falhou: {result.get('error', 'Erro desconhecido')}")
            return 1
            
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
