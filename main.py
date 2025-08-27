#!/usr/bin/env python3
"""
Orquestrador Inteligente de Varreduras - CLI
Agora com responsabilidades desacopladas:
- Fluxo principal: core/orquestrador_pentest.py (classe OrquestradorPentest)
- Relatórios HTML: relatorios/gerador_html.py (Jinja2 + templates)
- Persistência JSON: infra/persistencia.py
- Utilitários: utils/rede.py, utils/resumo.py
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime

# Garantir diretório raiz no path (compatibilidade)
sys.path.insert(0, str(Path(__file__).parent))


def main():
    """Função principal - Pentest Inicial: DNS + Scan de Portas"""
    parser = argparse.ArgumentParser(
        description='Orquestrador Inteligente - Pentest Inicial: DNS + Scan de Portas',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Exemplos de uso:
            %(prog)s --alvo google.com
            %(prog)s --alvo 192.168.1.208
            %(prog)s --alvo example.com --verbose
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

    from core.orquestrador_pentest import OrquestradorPentest
    from relatorios.gerador_html import gerar_relatorio_automatico
    from infra.persistencia import salvar_json_resultados
    from utils.logger import obter_logger, log_manager

    # Console só mostra quando --verbose; arquivo mantém nível do config
    log_manager.definir_console_verbose(args.verbose)

    cli_logger = obter_logger("CLI")

    try:
        # Criar instâncias dos módulos
        resolver_dns = ResolucaoDNS()
        scanner_portas = VarreduraRustScan()
        scanner_nmap = VarreduraNmap()
        decisao_ia = DecisaoIA()

        orquestrador = OrquestradorPentest(
            resolver_dns, scanner_portas, scanner_nmap, decisao_ia, obter_logger
        )

        cli_logger.info(f"=== Orquestrador Inteligente - Pentest Inicial ===")
        cli_logger.info(f"Alvo: {args.alvo}")
        cli_logger.info("")

        # Executar pentest inicial
        resultados = orquestrador.executar_pentest_inicial(args.alvo)

        # Gerar nomes de arquivos com timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        arquivo_json = f"dados/resultado_{timestamp}.json"
        arquivo_html = f"relatorios/relatorio_{timestamp}.html"

        # Sempre salvar resultados (via camada de persistência)
        salvar_json_resultados(resultados, arquivo_json)
        gerar_relatorio_automatico(resultados, arquivo_html)

        if resultados.get('sucesso_geral'):
            cli_logger.info("✓ Pentest inicial concluído com sucesso!")

            # Exibir resumo DNS
            resumo_dns = resultados.get('resumo_dns', {})
            cli_logger.info(f"\n=== Resolução DNS ===")
            cli_logger.info(f"  Tipo de alvo: {resumo_dns.get('tipo_alvo', 'N/A').title()}")

            if resumo_dns.get('tipo_alvo') == 'dominio':
                cli_logger.info(f"  IP principal: {resumo_dns.get('ip_principal', 'N/A')}")
                cli_logger.info(f"  Total de IPs: {resumo_dns.get('total_ips', 0)}")
                if resumo_dns.get('ips_encontrados'):
                    cli_logger.info(f"  IPs encontrados: {', '.join(resumo_dns['ips_encontrados'])}")
            else:
                cli_logger.info(f"  Hostname principal: {resumo_dns.get('hostname_principal', 'N/A')}")
                if resumo_dns.get('dominios_encontrados'):
                    cli_logger.info(f"  Domínios encontrados: {', '.join(resumo_dns['dominios_encontrados'])}")

            # Exibir resumo do scan de portas
            resumo_scan = resultados.get('resumo_scan', {})
            cli_logger.info(f"\n=== Scan de Portas ===")
            cli_logger.info(f"  IPs scaneados: {resumo_scan.get('total_ips_scaneados', 0)}")
            cli_logger.info(f"  Hosts ativos: {resumo_scan.get('hosts_ativos', 0)}")
            cli_logger.info(f"  Total de portas abertas: {resumo_scan.get('total_portas_abertas', 0)}")

            # Mostrar hosts com portas abertas
            hosts_com_portas = resumo_scan.get('hosts_com_portas_abertas', [])
            if hosts_com_portas:
                cli_logger.info(f"\n  Hosts com portas abertas:")
                for host in hosts_com_portas:
                    portas_str = ', '.join(map(str, host.get('portas', [])))
                    cli_logger.info(f"    {host['ip']}: {portas_str} ({host['portas_abertas']} portas)")

            # Exibir decisão da IA
            decisao_ia_res = resultados.get('decisao_ia', {})
            cli_logger.info(f"\n=== Análise IA ===")
            cli_logger.info(f"  Fonte da decisão: {decisao_ia_res.get('fonte_decisao', 'N/A')}")
            cli_logger.info(f"  Executar Nmap avançado: {'Sim' if decisao_ia_res.get('executar_nmap_avancado') else 'Não'}")
            cli_logger.info(f"  Prioridade: {decisao_ia_res.get('prioridade', 'N/A').title()}")
            cli_logger.info(f"  Justificativa: {decisao_ia_res.get('justificativa_ia', 'N/A')}")

            modulos_recomendados = decisao_ia_res.get('modulos_recomendados', [])
            if modulos_recomendados:
                cli_logger.info(f"  Módulos recomendados: {', '.join(modulos_recomendados)}")

            # Exibir resultados do Nmap avançado se executado
            nmap_avancado = resultados.get('nmap_avancado', {})
            if nmap_avancado.get('executado', True):  # True por padrão se não especificado
                resumo_nmap = nmap_avancado.get('resumo_geral', {})
                cli_logger.info(f"\n=== Nmap Avançado ===")
                cli_logger.info(f"  Módulos executados: {resumo_nmap.get('modulos_executados', 0)}")
                cli_logger.info(f"  IPs analisados: {resumo_nmap.get('ips_analisados', 0)}")
                cli_logger.info(f"  Vulnerabilidades encontradas: {resumo_nmap.get('total_vulnerabilidades', 0)}")
                cli_logger.info(f"  Serviços detectados: {resumo_nmap.get('total_servicos_detectados', 0)}")

                hosts_com_vulns = resumo_nmap.get('hosts_com_vulnerabilidades', [])
                if hosts_com_vulns:
                    cli_logger.info(f"  Hosts com vulnerabilidades: {', '.join(hosts_com_vulns)}")
            else:
                cli_logger.info(f"\n=== Nmap Avançado ===")
                cli_logger.info(f"  Status: Não executado")
                cli_logger.info(f"  Motivo: {nmap_avancado.get('motivo', 'N/A')}")

            # Próximos passos (mesma lógica anterior)
            cli_logger.info(f"\n=== Próximos Passos ===")
            if decisao_ia_res.get('executar_nmap_avancado') and nmap_avancado.get('executado', True):
                if resumo_nmap.get('total_vulnerabilidades', 0) > 0:
                    cli_logger.info("1. Investigar vulnerabilidades encontradas")
                    cli_logger.info("2. Executar exploits específicos")
                    cli_logger.info("3. Verificar impacto das vulnerabilidades")
                else:
                    cli_logger.info("1. Analisar configurações de serviços")
                    cli_logger.info("2. Verificar hardening de segurança")
                    cli_logger.info("3. Executar testes manuais específicos")
            elif hosts_com_portas:
                cli_logger.info("1. Considerar análise manual dos serviços")
                cli_logger.info("2. Verificar configurações básicas de segurança")
                cli_logger.info("3. Monitorar atividade dos serviços")
            else:
                cli_logger.info("1. Verificar firewall ou filtros")
                cli_logger.info("2. Tentar varredura completa de portas")
                cli_logger.info("3. Investigar outros IPs na rede")

            cli_logger.info(f"\n✓ Arquivos salvos:")
            cli_logger.info(f"  JSON: {arquivo_json}")
            cli_logger.info(f"  HTML: {arquivo_html}")

            return 0
        else:
            from utils.logger import obter_logger as _obter_logger  # evitar shadowing
            obter = _obter_logger("CLI")
            obter.error(f"✗ Falha no pentest inicial: {resultados.get('erro', 'Erro desconhecido')}")
            return 1

    except KeyboardInterrupt:
        cli_logger.error("\n✗ Operação cancelada pelo usuário")
        return 1
    except Exception as e:
        cli_logger.error(f"✗ Erro inesperado: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())