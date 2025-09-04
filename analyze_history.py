#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analisador de Histórico do VarreduraIA
Permite visualizar e analisar o comportamento da IA em sessões anteriores
"""

import sys
import argparse
import json
from pathlib import Path
from datetime import datetime

# Adicionar diretório atual ao path
sys.path.insert(0, str(Path(__file__).parent))

from utils.ai_history import AIHistoryManager
from utils.logger import setup_logger


def format_duration(seconds):
    """Formata duração em segundos para formato legível"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def print_session_overview(analysis):
    """Imprime visão geral da sessão"""
    overview = analysis["session_overview"]
    
    print(f"""
🎯 VISÃO GERAL DA SESSÃO
========================
ID: {overview['id']}
Alvo: {overview['target']}
Duração: {format_duration(overview['duration'])}
Iterações: {overview['total_iterations']}
Plugins executados: {overview['plugins_count']}
Descobertas: {overview['discoveries_count']}
""")


def print_ai_behavior(analysis):
    """Imprime análise de comportamento da IA"""
    behavior = analysis["ai_behavior_analysis"]
    patterns = behavior["decision_patterns"]
    
    print(f"""
🤖 COMPORTAMENTO DA IA
=====================
Decisão mais comum: {patterns.get('most_common_decision', 'N/A')}
Diversidade de plugins: {patterns.get('plugin_diversity', 0)}
Tempo médio de resposta: {patterns.get('avg_response_time', 0):.2f}s

Qualidade do raciocínio:
  • Alto: {patterns['reasoning_quality_distribution']['high']}
  • Médio: {patterns['reasoning_quality_distribution']['medium']}
  • Baixo: {patterns['reasoning_quality_distribution']['low']}
""")
    
    # Análise de progressão
    progression = behavior.get("progression_analysis", {})
    if progression:
        print("Progressões comuns:")
        for prog, count in progression.get("common_progressions", {}).items():
            print(f"  • {prog}: {count}x")
        
        print(f"Fluxo lógico: {'✅ Sim' if progression.get('shows_logical_flow') else '❌ Não'}")


def print_plugin_performance(analysis):
    """Imprime análise de performance dos plugins"""
    plugins = analysis["plugin_performance"]
    
    print(f"""
🔌 PERFORMANCE DOS PLUGINS
==========================
""")
    
    for plugin_name, stats in plugins.items():
        success_rate = stats['success_rate'] * 100
        discovery_rate = stats['discovery_rate'] * 100
        
        print(f"""
{plugin_name}:
  • Execuções: {stats['executions']}
  • Tempo médio: {stats['avg_time']:.2f}s
  • Taxa de sucesso: {success_rate:.1f}%
  • Taxa de descoberta: {discovery_rate:.1f}%
""")


def print_discoveries_timeline(analysis):
    """Imprime timeline das descobertas"""
    discoveries = analysis["discovery_timeline"]
    
    if not discoveries:
        return
        
    print(f"""
🔍 TIMELINE DE DESCOBERTAS
=========================
""")
    
    for discovery in discoveries[-10:]:  # Últimas 10 descobertas
        timestamp = datetime.fromisoformat(discovery["timestamp"]).strftime("%H:%M:%S")
        discovery_type = discovery["type"]
        iteration = discovery["iteration"]
        
        print(f"{timestamp} (It.{iteration}) - {discovery_type}: {discovery['details']}")


def print_improvement_suggestions(analysis):
    """Imprime sugestões de melhoria"""
    suggestions = analysis["improvement_suggestions"]
    
    if not suggestions:
        print("\n✅ Nenhuma sugestão de melhoria - comportamento da IA está adequado!")
        return
        
    print(f"""
💡 SUGESTÕES DE MELHORIA
=======================
""")
    
    for i, suggestion in enumerate(suggestions, 1):
        print(f"{i}. {suggestion}")


def list_sessions():
    """Lista todas as sessões disponíveis"""
    history_manager = AIHistoryManager()
    sessions = history_manager.get_all_sessions()
    
    if not sessions:
        print("❌ Nenhuma sessão de histórico encontrada.")
        return
        
    print(f"""
📋 SESSÕES DISPONÍVEIS ({len(sessions)})
===============================
""")
    
    for session_id in sorted(sessions, reverse=True):
        try:
            analysis = history_manager.get_session_analysis(session_id)
            overview = analysis["session_overview"]
            
            target = overview["target"]
            duration = format_duration(overview["duration"])
            iterations = overview["total_iterations"]
            discoveries = overview["discoveries_count"]
            
            print(f"• {session_id}")
            print(f"  Alvo: {target} | Duração: {duration} | Iterações: {iterations} | Descobertas: {discoveries}")
            print()
            
        except Exception as e:
            print(f"• {session_id} (erro ao ler: {e})")


def analyze_session(session_id):
    """Analisa uma sessão específica"""
    history_manager = AIHistoryManager()
    analysis = history_manager.get_session_analysis(session_id)
    
    if "error" in analysis:
        print(f"❌ Erro: {analysis['error']}")
        return
        
    print_session_overview(analysis)
    print_ai_behavior(analysis)
    print_plugin_performance(analysis)
    print_discoveries_timeline(analysis)
    print_improvement_suggestions(analysis)


def export_session(session_id, output_file):
    """Exporta análise de sessão para arquivo"""
    history_manager = AIHistoryManager()
    analysis = history_manager.get_session_analysis(session_id)
    
    if "error" in analysis:
        print(f"❌ Erro: {analysis['error']}")
        return
        
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)
        
    print(f"✅ Análise exportada para: {output_file}")


def main():
    """Função principal"""
    parser = argparse.ArgumentParser(
        description='Analisador de Histórico do VarreduraIA',
        epilog="""
Exemplos:
  %(prog)s --list                                    # Lista todas as sessões
  %(prog)s --analyze session_192_168_1_1_20250904   # Analisa sessão específica
  %(prog)s --export session_id --output analysis.json # Exporta análise
        """
    )
    
    parser.add_argument('--list', action='store_true',
                       help='Lista todas as sessões disponíveis')
    parser.add_argument('--analyze', metavar='SESSION_ID',
                       help='Analisa uma sessão específica')
    parser.add_argument('--export', metavar='SESSION_ID',
                       help='Exporta análise de sessão para arquivo')
    parser.add_argument('--output', metavar='FILE',
                       help='Arquivo de saída para exportação')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Output verboso')
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger('HistoryAnalyzer', verbose=args.verbose)
    
    try:
        if args.list:
            list_sessions()
        elif args.analyze:
            analyze_session(args.analyze)
        elif args.export:
            if not args.output:
                print("❌ Erro: --output é obrigatório com --export")
                return 1
            export_session(args.export, args.output)
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n🛑 Operação cancelada pelo usuário")
        return 1
    except Exception as e:
        logger.error(f"💥 Erro: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
