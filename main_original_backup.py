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


def executar_scan_web(args):
    """Executa varredura web específica"""
    from modulos.varredura_scraper_auth import executar_scraper_web
    from relatorios.gerador_html import gerar_relatorio_automatico
    from infra.persistencia import salvar_json_resultados
    from utils.logger import obter_logger, log_manager

    # Console só mostra quando --verbose
    log_manager.definir_console_verbose(args.verbose)
    logger = obter_logger("WebScanCLI")

    try:
        logger.info(f"=== Varredura Web Específica ===")
        logger.info(f"Alvo: {args.alvo}")
        logger.info(f"Tipo: {args.tipo_web_scan}")

        # Preparar credenciais se fornecidas
        credenciais = None
        if args.usuario is not None and args.senha is not None:
            credenciais = {
                'usuario': args.usuario,
                'senha': args.senha
            }
            logger.info("Autenticação: Habilitada")
        else:
            logger.info("Autenticação: Desabilitada")

        # Executar scraping
        resultados = executar_scraper_web(
            args.alvo,
            credenciais,
            args.tipo_web_scan
        )

        if 'erro' in resultados:
            logger.error(f"✗ Erro na varredura web: {resultados['erro']}")
            return 1

        # Gerar nomes de arquivos
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        arquivo_json = f"dados/webscan_{timestamp}.json"
        arquivo_html = f"relatorios/webscan_{timestamp}.html"

        # Salvar resultados
        salvar_json_resultados(resultados, arquivo_json)
        gerar_relatorio_automatico(resultados, arquivo_html)

        # Exibir estatísticas
        logger.info("✓ Varredura web concluída com sucesso!")

        analise = resultados.get('analise_final', {})
        logger.info(f"\n=== Estatísticas Web ===")
        logger.info(f"  URLs descobertas: {analise.get('total_urls', 0)}")
        logger.info(f"  Formulários: {analise.get('total_formularios', 0)}")
        logger.info(f"  Endpoints API: {analise.get('total_apis', 0)}")
        logger.info(f"  Parâmetros: {analise.get('total_parametros', 0)}")
        logger.info(f"  Vulnerabilidades: {analise.get('total_vulnerabilidades', 0)}")

        # Tecnologias detectadas
        tech = resultados.get('tecnologias', {})
        if tech:
            logger.info(f"\n=== Tecnologias Detectadas ===")
            for categoria, tecnologia in tech.items():
                logger.info(f"  {categoria.title()}: {tecnologia}")

        # Vulnerabilidades por criticidade
        vuln_por_crit = analise.get('por_criticidade', {})
        if vuln_por_crit:
            logger.info(f"\n=== Vulnerabilidades ===")
            for nivel, count in vuln_por_crit.items():
                logger.info(f"  {nivel.title()}: {count}")

        logger.info(f"\n✓ Arquivos salvos:")
        logger.info(f"  JSON: {arquivo_json}")
        logger.info(f"  HTML: {arquivo_html}")

        return 0

    except Exception as e:
        logger.error(f"✗ Erro inesperado: {str(e)}")
        return 1


def executar_testes_vulnerabilidades(args):
    """Executa testes específicos de vulnerabilidades usando módulos Python puro"""
    import time
    from modulos.analisador_vulnerabilidades_web import AnalisadorVulnerabilidadesWeb
    from relatorios.gerador_html import gerar_relatorio_automatico
    from infra.persistencia import salvar_json_resultados
    from utils.logger import obter_logger, log_manager

    # Console só mostra quando --verbose
    log_manager.definir_console_verbose(args.verbose)
    logger = obter_logger("VulnTestCLI")

    try:
        logger.info(f"=== Testes de Vulnerabilidades (Python Puro) ===")
        logger.info(f"Alvo: {args.alvo}")

        # URL base
        url_base = args.alvo
        if not url_base.startswith('http'):
            url_base = f"https://{url_base}"

        resultados_totais = {
            'alvo': args.alvo,
            'timestamp': datetime.now().isoformat(),
            'testes_executados': [],
            'vulnerabilidades_totais': 0,
            'tempo_total': 0
        }

        inicio_total = time.time()

        # Executar análise completa de vulnerabilidades web
        logger.info(f"\n🕷️ Executando análise de vulnerabilidades web...")
        analisador = AnalisadorVulnerabilidadesWeb()
        resultado_analise = analisador.analisar_url(url_base, testes_completos=True, testar_payloads=True)

        if 'erro' not in resultado_analise:
            vulnerabilidades = resultado_analise.get('vulnerabilidades', [])
            resultados_totais['testes_executados'].append({
                'teste': 'analise_vulnerabilidades_web_python',
                'resultado': resultado_analise
            })
            resultados_totais['vulnerabilidades_totais'] = len(vulnerabilidades)

            logger.info(f"✅ Análise concluída: {len(vulnerabilidades)} vulnerabilidades encontradas")

            # Mostrar headers de segurança
            headers_seguranca = resultado_analise.get('headers_seguranca', {})
            headers_ausentes = [h for h, info in headers_seguranca.items() if info['status'] == 'ausente']
            if headers_ausentes:
                logger.info(f"⚠️ Headers de segurança ausentes: {', '.join(headers_ausentes[:3])}")
        else:
            logger.error(f"❌ Erro na análise: {resultado_analise['erro']}")
            return 1

        resultados_totais['tempo_total'] = time.time() - inicio_total

        # Gerar nomes de arquivos
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        arquivo_json = f"dados/vulntest_{timestamp}.json"
        arquivo_html = f"relatorios/vulntest_{timestamp}.html"

        # Salvar resultados
        salvar_json_resultados(resultados_totais, arquivo_json)
        gerar_relatorio_automatico(resultados_totais, arquivo_html)

        # Exibir estatísticas finais
        logger.info(f"\n✓ Testes de vulnerabilidades concluídos com sucesso!")
        logger.info(f"\n=== Estatísticas Finais ===")
        logger.info(f"  Total de vulnerabilidades: {resultados_totais['vulnerabilidades_totais']}")
        logger.info(f"  Tempo total: {resultados_totais['tempo_total']:.2f}s")

        # Mostrar vulnerabilidades por severidade
        if 'erro' not in resultado_analise:
            severidades = {}
            for vuln in vulnerabilidades:
                sev = vuln.get('severidade', 'baixa')
                severidades[sev] = severidades.get(sev, 0) + 1

            if severidades:
                logger.info(f"\n=== Vulnerabilidades por Severidade ===")
                for sev, count in severidades.items():
                    emoji = "🔴" if sev == 'alta' else "🟡" if sev == 'media' else "🟢"
                    logger.info(f"  {emoji} {sev.title()}: {count}")

        logger.info(f"\n✓ Arquivos salvos:")
        logger.info(f"  JSON: {arquivo_json}")
        logger.info(f"  HTML: {arquivo_html}")

        return 0

    except Exception as e:
        logger.error(f"✗ Erro inesperado: {str(e)}")
        return 1


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

    # Parâmetros principais (CLI simplificado)
    parser.add_argument('--alvo', required=True, help='Domínio, IP ou URL base do alvo')
    parser.add_argument('--verbose', action='store_true', help='Saída verbosa no console')
    parser.add_argument('--web-scan', action='store_true', help='Modo Web: estudo com navegador → LOOP-IA')
    parser.add_argument('--web-gemini', action='store_true', help='Modo Web com Gemini: login automático + análise IA de páginas protegidas')
    parser.add_argument('--usuario', help='Usuário para autenticação web (opcional)')
    parser.add_argument('--senha', help='Senha para autenticação web (opcional)')

    args = parser.parse_args()

    # Determinar modo de execução e credenciais (CLI simplificado)
    if args.web_gemini:
        modo_execucao = 'web_gemini'
    elif args.web_scan:
        modo_execucao = 'web'
    else:
        modo_execucao = 'rede'
    
    credenciais = None
    if args.usuario is not None and args.senha is not None:
        credenciais = {'usuario': args.usuario, 'senha': args.senha}

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

        # Executar pentest inteligente conforme modo selecionado
        resultados = orquestrador.executar_pentest_inteligente(
            args.alvo,
            modo=modo_execucao,
            credenciais_web=credenciais
        )

        # Gerar nomes de arquivos com timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        arquivo_json = f"dados/resultado_{timestamp}.json"
        arquivo_html = f"relatorios/relatorio_{timestamp}.html"

        # Sempre salvar resultados (via camada de persistência)
        salvar_json_resultados(resultados, arquivo_json)
        gerar_relatorio_automatico(resultados, arquivo_html)
        print('passou aqui 1');
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
                print('passou aqui 2');
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