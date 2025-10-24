#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VarreduraIA - Versão Simplificada
Sistema de pentest inteligente com plugins desacoplados e loop de decisão por IA.
"""

import sys
import argparse
from pathlib import Path

# Adicionar diretório atual ao path
sys.path.insert(0, str(Path(__file__).parent))

from core.orchestrator import PentestOrchestrator
from utils.logger import setup_logger


def main():
    """Função principal"""
    parser = argparse.ArgumentParser(
        description='VarreduraIA - Sistema de Pentest Inteligente Simplificado',
    epilog="""
Exemplos:
  %(prog)s --target google.com
  %(prog)s --target 192.168.1.0/24
  %(prog)s --target https://example.com
    """
    )
    
    parser.add_argument('--target', required=True, 
                       help='Alvo: IP, domínio, URL ou CIDR')
    # O modo foi simplificado para foco em rede. O orquestrador usa 'network' por padrão.
    parser.add_argument('--max-iterations', type=int, default=20,
                       help='Número máximo de iterações do loop IA')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Output verboso')
    parser.add_argument('--config', help='Arquivo de configuração personalizado')
    parser.add_argument('--manual', action='store_true',
                          help='Ativa o modo de decisão manual pelo usuário')
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger('VarreduraIA', verbose=args.verbose)
    
    try:
        # Criar orquestrador
        orchestrator = PentestOrchestrator(
            config_file=args.config,
            verbose=args.verbose,
            manual_mode=args.manual
        )
        
        # Executar pentest
        result = orchestrator.run_pentest(
            target=args.target,
            max_iterations=args.max_iterations
        )
        
        if result.get('success'):
            logger.info("✅ Pentest concluído com sucesso!")
            logger.info(f"📊 Relatório salvo em: {result.get('report_path', 'N/A')}")
            return 0
        else:
            logger.error(f"❌ Pentest falhou: {result.get('error', 'Erro desconhecido')}")
            return 1
            
    except KeyboardInterrupt:
        logger.info("🛑 Operação cancelada pelo usuário")
        return 1
    except Exception as e:
        logger.error(f"💥 Erro crítico: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
