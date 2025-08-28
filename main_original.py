#!/usr/bin/env python3
"""
Orquestrador Inteligente de Varreduras - CLI
Sistema de Loop Inteligente com IA:
- Resolução DNS inicial
- Scan básico de portas (RustScan)
- Loop adaptativo: IA decide próximos módulos baseada no contexto acumulado
- Execução inteligente até decisão de parar
- Relatório final consolidado
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime

# Garantir diretório raiz no path (compatibilidade)
sys.path.insert(0, str(Path(__file__).parent))


def main():
    """Função principal - Pentest Inteligente com Loop Adaptativo"""
    parser = argparse.ArgumentParser(
        description='Orquestrador Inteligente - Pentest com Loop Adaptativo baseado em IA',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Exemplos de uso:
            %(prog)s --alvo google.com
            %(prog)s --alvo 192.168.1.208
            %(prog)s --alvo example.com --verbose
            
            O sistema executa:
            1. Resolução DNS
            2. Scan inicial (RustScan)  
            3. Loop inteligente: IA decide próximos módulos
            4. Para quando IA considera análise completa
                    """
    )

    # Parâmetros principais
    parser.add_argument('--alvo', required=True, help='Domínio ou IP para resolver')
    parser.add_argument('--verbose', action='store_true', help='Saída verbosa')

    args = parser.parse_args()

    # Importações pós-args para respeitar verbosidade de console
    from modulos.resolucao_dns import ResolucaoDNS
    from modulos.varredura_rustscan import VarreduraRustScan
    from modulos.varredura_nmap import VarreduraNmap
    from modulos.decisao_ia import DecisaoIA

    from core.orquestrador_inteligente import OrquestradorInteligente
    from relatorios.gerador_html import gerar_relatorio_automatico
    from infra.persistencia import salvar_json_resultados
    from utils.logger import obter_logger, log_manager

    # Console só mostra quando --verbose; arquivo mantém nível do config
    log_manager.definir_console_verbose(args.verbose)

    cli_logger = obter_logger("CLI")

    try:
        # Criar instâncias dos módulos principais
        resolver_dns = ResolucaoDNS()
        scanner_portas = VarreduraRustScan()
        scanner_nmap = VarreduraNmap()
        decisao_ia = DecisaoIA()

        orquestrador = OrquestradorInteligente(
            resolver_dns, scanner_portas, scanner_nmap, decisao_ia, obter_logger
        )

        cli_logger.info(f"=== Orquestrador Inteligente - Pentest com Loop Adaptativo ===")
        cli_logger.info(f"Alvo: {args.alvo}")
        cli_logger.info("")

        # Executar pentest inteligente
        resultados = orquestrador.executar_pentest_inteligente(args.alvo)

        # Gerar nomes de arquivos com timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        arquivo_json = f"dados/resultado_{timestamp}.json"
        arquivo_html = f"relatorios/relatorio_{timestamp}.html"

        # Sempre salvar resultados (via camada de persistência)
        salvar_json_resultados(resultados, arquivo_json)
        gerar_relatorio_automatico(resultados, arquivo_html)

        if resultados.get('sucesso_geral'):
            cli_logger.info("✓ Pentest inteligente concluído com sucesso!")

            # Exibir estatísticas finais
            stats = resultados.get('estatisticas', {})
            cli_logger.info(f"\n=== Estatísticas Finais ===")
            cli_logger.info(f"  IPs descobertos: {stats.get('ips_descobertos', 0)}")
            cli_logger.info(f"  Portas abertas: {stats.get('total_portas_abertas', 0)}")
            cli_logger.info(f"  Serviços detectados: {stats.get('servicos_detectados', 0)}")
            cli_logger.info(f"  Vulnerabilidades: {stats.get('vulnerabilidades_encontradas', 0)}")
            cli_logger.info(f"  Módulos executados: {stats.get('modulos_executados', 0)}")
            cli_logger.info(f"  Pontuação de risco: {stats.get('pontuacao_risco_final', 0)}/100")
            cli_logger.info(f"  Tempo total: {resultados.get('tempo_total', 'N/A')}")

            # Exibir contexto de execução
            contexto = resultados.get('contexto_execucao', {})
            cli_logger.info(f"\n=== Resumo da Execução ===")
            cli_logger.info(f"  Motivo da finalização: {contexto.get('motivo_finalizacao', 'N/A')}")
            
            modulos_executados = contexto.get('modulos_executados', [])
            if modulos_executados:
                cli_logger.info(f"  Sequência de execução:")
                for i, modulo in enumerate(modulos_executados, 1):
                    cli_logger.info(f"    {i}. {modulo}")

            # Mostrar portas abertas por host
            portas_abertas = contexto.get('portas_abertas', {})
            if portas_abertas:
                cli_logger.info(f"\n=== Portas Abertas ===")
                for ip, portas in portas_abertas.items():
                    if portas:
                        portas_str = ', '.join(map(str, portas))
                        cli_logger.info(f"  {ip}: {portas_str} ({len(portas)} portas)")

            # Mostrar vulnerabilidades se encontradas
            vulnerabilidades = contexto.get('vulnerabilidades_encontradas', [])
            if vulnerabilidades:
                cli_logger.info(f"\n=== Vulnerabilidades Encontradas ===")
                for i, vuln in enumerate(vulnerabilidades[:5], 1):  # Mostrar até 5
                    ip = vuln.get('ip', 'N/A')
                    tipo = vuln.get('tipo', vuln.get('script', 'N/A'))
                    cli_logger.info(f"  {i}. {ip} - {tipo}")
                
                if len(vulnerabilidades) > 5:
                    cli_logger.info(f"  ... e mais {len(vulnerabilidades) - 5} vulnerabilidades")

            # Análise de vulnerabilidades
            analise_vuln = resultados.get('analise_vulnerabilidades', {})
            if analise_vuln.get('total', 0) > 0:
                cli_logger.info(f"\n=== Análise de Vulnerabilidades ===")
                criticidade = analise_vuln.get('por_criticidade', {})
                for nivel, count in criticidade.items():
                    if count > 0:
                        cli_logger.info(f"  {nivel.title()}: {count}")

            # Recomendações finais
            recomendacoes = resultados.get('recomendacoes_finais', [])
            if recomendacoes:
                cli_logger.info(f"\n=== Recomendações Finais ===")
                for i, rec in enumerate(recomendacoes[:5], 1):
                    cli_logger.info(f"  {i}. {rec}")

            cli_logger.info(f"\n✓ Arquivos salvos:")
            cli_logger.info(f"  JSON: {arquivo_json}")
            cli_logger.info(f"  HTML: {arquivo_html}")

            return 0
        else:
            cli_logger.error(f"✗ Falha no pentest inteligente: {resultados.get('erro', 'Erro desconhecido')}")
            return 1

    except KeyboardInterrupt:
        cli_logger.error("\n✗ Operação cancelada pelo usuário")
        return 1
    except Exception as e:
        cli_logger.error(f"✗ Erro inesperado: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())