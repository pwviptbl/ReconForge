#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main refatorado - Fase 1 da Refatoração

Novo main.py que utiliza:
- Container de Injeção de Dependência
- Configuração externa
- Interfaces bem definidas
- Separação de responsabilidades
"""

import sys
import argparse
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

# Garantir diretório raiz no path
sys.path.insert(0, str(Path(__file__).parent))

# Imports do novo sistema
from core.dependency_container import DependencyContainer
from core.service_configuration import create_configured_container
from interfaces import ILogger, ILoggerFactory, IPersistenceLayer, IReportGenerator
from utils.logger import obter_logger


class PentestApplication:
    """Aplicação principal do pentest - refatorada com DI"""
    
    def __init__(self, container: DependencyContainer):
        self.container = container
        self.logger = self._setup_logging()
        self.persistence = self._get_persistence()
        self.report_generator = self._get_report_generator()
    
    def _setup_logging(self) -> ILogger:
        """Configura sistema de logging via DI"""
        try:
            logger_factory = self.container.resolve(ILoggerFactory)
            return logger_factory.create_logger("PentestApp")
        except Exception as e:
            # Fallback para logger legado
            print(f"Aviso: Usando logger legado. Erro DI: {e}")
            return obter_logger("PentestApp")
    
    def _get_persistence(self) -> Optional[IPersistenceLayer]:
        """Obtém camada de persistência via DI"""
        try:
            return self.container.resolve(IPersistenceLayer)
        except Exception as e:
            self.logger.warning(f"Persistência via DI não disponível: {e}")
            return None
    
    def _get_report_generator(self) -> Optional[IReportGenerator]:
        """Obtém gerador de relatórios via DI"""
        try:
            return self.container.resolve(IReportGenerator)
        except Exception as e:
            self.logger.warning(f"Gerador de relatórios via DI não disponível: {e}")
            return None
    
    def execute_pentest(self, args: argparse.Namespace) -> int:
        """Executa pentest baseado nos argumentos"""
        try:
            self.logger.info(f"=== VarreduraIA - Pentest Inteligente ===")
            self.logger.info(f"Alvo: {args.alvo}")
            self.logger.info(f"Modo: {self._determine_mode(args)}")
            
            # Determinar estratégia de execução
            if args.web_gemini:
                return self._execute_web_gemini_mode(args)
            elif args.web_scan:
                return self._execute_web_mode(args)
            elif args.vuln_test:
                return self._execute_vulnerability_test_mode(args)
            else:
                return self._execute_network_mode(args)
                
        except KeyboardInterrupt:
            self.logger.error("\n✗ Operação cancelada pelo usuário")
            return 1
        except Exception as e:
            self.logger.error(f"✗ Erro inesperado: {str(e)}")
            if args.verbose:
                import traceback
                self.logger.error(f"Traceback: {traceback.format_exc()}")
            return 1
    
    def _determine_mode(self, args: argparse.Namespace) -> str:
        """Determina modo de execução baseado nos argumentos"""
        if args.web_gemini:
            return "web_gemini"
        elif args.web_scan:
            return "web"
        elif args.vuln_test:
            return "vulnerability_test"
        else:
            return "network"
    
    def _execute_network_mode(self, args: argparse.Namespace) -> int:
        """Executa modo rede usando Strategy Pattern (Fase 2) ou orquestrador legado"""
        try:
            # Tentar usar o novo sistema com Strategy Pattern primeiro
            if self._try_strategy_execution(args):
                return 0
            
            # Fallback para orquestrador legado (compatibilidade)
            self.logger.info("🔄 Fallback: Usando orquestrador legado (compatibilidade)")
            return self._execute_legacy_network_mode(args)
            
        except Exception as e:
            self.logger.error(f"Erro no modo rede: {e}")
            return 1
    
    def _try_strategy_execution(self, args: argparse.Namespace) -> bool:
        """
        Tenta executar usando Strategy Pattern (Fase 2)
        
        Returns:
            True se executou com sucesso, False se deve usar fallback
        """
        try:
            # Verificar se as estratégias estão registradas
            strategy_manager = self.container.get_strategy_manager()
            
            if not strategy_manager:
                self.logger.warning("⚠️  StrategyManager não disponível, usando fallback")
                return False
            
            self.logger.info("🚀 Executando com Strategy Pattern (Fase 2)")
            
            # Criar contexto do scan
            context = self.container.create_scan_context(
                target=args.alvo,
                user_preferences={
                    'verbose': getattr(args, 'verbose', False),
                    'timeout': getattr(args, 'timeout', 300),
                    'profile': getattr(args, 'profile', 'default'),
                    'modo': 'rede'
                }
            )
            
            # Executar estratégias
            results = strategy_manager.execute_strategies(args.alvo, context)
            
            # Processar resultados para formato compatível
            resultado_compativel = self._convert_strategy_results_to_legacy_format(results, context)
            
            # Salvar resultados usando sistema existente
            self._save_and_report_results(resultado_compativel, args)
            
            self.logger.info("✅ Execução com Strategy Pattern concluída")
            return True
            
        except Exception as e:
            self.logger.warning(f"⚠️  Erro no Strategy Pattern: {e}. Usando fallback.")
            return False
    
    def _execute_legacy_network_mode(self, args: argparse.Namespace) -> int:
        """Executa modo rede usando orquestrador legado"""
        try:
            from core.orquestrador_inteligente import OrquestradorInteligente
            from modulos.resolucao_dns import ResolucaoDNS
            from modulos.varredura_rustscan import VarreduraRustScan
            from modulos.varredura_nmap import VarreduraNmap
            from modulos.decisao_ia import DecisaoIA
            
            resolver_dns = ResolucaoDNS()
            scanner_portas = VarreduraRustScan()
            scanner_nmap = VarreduraNmap()
            decisao_ia = DecisaoIA()
            
            orquestrador = OrquestradorInteligente(
                resolver_dns, scanner_portas, scanner_nmap, decisao_ia, obter_logger
            )
            
            # Executar pentest
            resultado = orquestrador.executar_pentest_inteligente(
                args.alvo,
                modo='rede',
                credenciais_web=self._get_credentials(args)
            )
            
            # Salvar resultados usando novo sistema
            return self._save_and_report_results(resultado, args)
            
        except Exception as e:
            self.logger.error(f"Erro no orquestrador legado: {e}")
            return 1
    
    def _execute_web_mode(self, args: argparse.Namespace) -> int:
        """Executa modo web usando orquestrador"""
        try:
            # Usar orquestrador legado por enquanto
            from core.orquestrador_inteligente import OrquestradorInteligente
            from modulos.resolucao_dns import ResolucaoDNS
            from modulos.varredura_rustscan import VarreduraRustScan
            from modulos.varredura_nmap import VarreduraNmap
            from modulos.decisao_ia import DecisaoIA
            
            self.logger.info("🔄 Usando orquestrador legado para modo web")
            
            resolver_dns = ResolucaoDNS()
            scanner_portas = VarreduraRustScan()
            scanner_nmap = VarreduraNmap()
            decisao_ia = DecisaoIA()
            
            orquestrador = OrquestradorInteligente(
                resolver_dns, scanner_portas, scanner_nmap, decisao_ia, obter_logger
            )
            
            resultado = orquestrador.executar_pentest_inteligente(
                args.alvo,
                modo='web',
                credenciais_web=self._get_credentials(args)
            )
            
            return self._save_and_report_results(resultado, args)
            
        except Exception as e:
            self.logger.error(f"Erro no modo web: {e}")
            return 1
    
    def _execute_web_gemini_mode(self, args: argparse.Namespace) -> int:
        """Executa modo web com Gemini"""
        try:
            from core.orquestrador_inteligente import OrquestradorInteligente
            from modulos.resolucao_dns import ResolucaoDNS
            from modulos.varredura_rustscan import VarreduraRustScan
            from modulos.varredura_nmap import VarreduraNmap
            from modulos.decisao_ia import DecisaoIA
            
            self.logger.info("🔄 Usando orquestrador legado para modo web+Gemini")
            
            resolver_dns = ResolucaoDNS()
            scanner_portas = VarreduraRustScan()
            scanner_nmap = VarreduraNmap()
            decisao_ia = DecisaoIA()
            
            orquestrador = OrquestradorInteligente(
                resolver_dns, scanner_portas, scanner_nmap, decisao_ia, obter_logger
            )
            
            resultado = orquestrador.executar_pentest_inteligente(
                args.alvo,
                modo='web_gemini',
                credenciais_web=self._get_credentials(args)
            )
            
            return self._save_and_report_results(resultado, args)
            
        except Exception as e:
            self.logger.error(f"Erro no modo web+Gemini: {e}")
            return 1
    
    def _execute_vulnerability_test_mode(self, args: argparse.Namespace) -> int:
        """Executa testes específicos de vulnerabilidades"""
        try:
            from modulos.analisador_vulnerabilidades_web import AnalisadorVulnerabilidadesWeb
            
            self.logger.info("🔄 Executando testes de vulnerabilidades Python puro")
            
            # Preparar URL
            url_base = args.alvo
            if not url_base.startswith('http'):
                url_base = f"https://{url_base}"
            
            # Executar análise
            analisador = AnalisadorVulnerabilidadesWeb()
            resultado_bruto = analisador.analisar_url(
                url_base, 
                testes_completos=True, 
                testar_payloads=True
            )
            
            # Normalizar resultado
            resultado = {
                'alvo': args.alvo,
                'timestamp': datetime.now().isoformat(),
                'modo_execucao': 'vulnerability_test',
                'sucesso_geral': not bool(resultado_bruto.get('erro')),
                'resultados_modulos': {
                    'analisador_vulnerabilidades_web': resultado_bruto
                },
                'vulnerabilidades_encontradas': resultado_bruto.get('vulnerabilidades', []),
                'estatisticas': {
                    'vulnerabilidades_encontradas': len(resultado_bruto.get('vulnerabilidades', [])),
                    'tempo_total': resultado_bruto.get('tempo_execucao', 0)
                }
            }
            
            return self._save_and_report_results(resultado, args)
            
        except Exception as e:
            self.logger.error(f"Erro no teste de vulnerabilidades: {e}")
            return 1
    
    def _get_credentials(self, args: argparse.Namespace) -> Optional[Dict[str, str]]:
        """Extrai credenciais dos argumentos"""
        if args.usuario and args.senha:
            return {
                'usuario': args.usuario,
                'senha': args.senha
            }
        return None
    
    def _save_and_report_results(self, resultado: Dict[str, Any], args: argparse.Namespace) -> int:
        """Salva resultados e gera relatórios usando novo sistema"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            scan_id = f"scan_{timestamp}"
            
            # Salvar usando nova camada de persistência se disponível
            if self.persistence:
                self.logger.info("💾 Salvando via nova camada de persistência")
                success = self.persistence.save_scan_result(scan_id, resultado)
                if success:
                    self.logger.info(f"✅ Resultado salvo com ID: {scan_id}")
                else:
                    self.logger.warning("⚠️ Falha ao salvar via nova persistência, usando método legado")
                    self._save_legacy_format(resultado, timestamp)
            else:
                self.logger.info("💾 Salvando via método legado")
                self._save_legacy_format(resultado, timestamp)
            
            # Gerar relatório usando novo sistema se disponível
            if self.report_generator:
                self.logger.info("📊 Gerando relatório via novo sistema")
                from interfaces import ReportFormat
                
                html_path = f"relatorios/relatorio_{timestamp}.html"
                report_result = self.report_generator.generate_report(
                    resultado, 
                    ReportFormat.HTML, 
                    html_path
                )
                
                if report_result.get('success'):
                    self.logger.info(f"✅ Relatório HTML gerado: {html_path}")
                else:
                    self.logger.warning("⚠️ Falha ao gerar relatório via novo sistema, usando método legado")
                    self._generate_legacy_report(resultado, timestamp)
            else:
                self.logger.info("📊 Gerando relatório via método legado")
                self._generate_legacy_report(resultado, timestamp)
            
            # Exibir estatísticas
            self._display_statistics(resultado)
            
            return 0 if resultado.get('sucesso_geral') else 1
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar/reportar resultados: {e}")
            return 1
    
    def _save_legacy_format(self, resultado: Dict[str, Any], timestamp: str):
        """Salva usando formato legado como fallback"""
        try:
            from infra.persistencia import salvar_json_resultados
            arquivo_json = f"dados/resultado_{timestamp}.json"
            salvar_json_resultados(resultado, arquivo_json)
            self.logger.info(f"✅ Salvo em formato legado: {arquivo_json}")
        except Exception as e:
            self.logger.error(f"Erro ao salvar formato legado: {e}")
    
    def _generate_legacy_report(self, resultado: Dict[str, Any], timestamp: str):
        """Gera relatório usando método legado como fallback"""
        try:
            from relatorios.gerador_html import gerar_relatorio_automatico
            arquivo_html = f"relatorios/relatorio_{timestamp}.html"
            gerar_relatorio_automatico(resultado, arquivo_html)
            self.logger.info(f"✅ Relatório legado gerado: {arquivo_html}")
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório legado: {e}")
    
    def _display_statistics(self, resultado: Dict[str, Any]):
        """Exibe estatísticas do pentest"""
        try:
            if not resultado.get('sucesso_geral'):
                self.logger.error(f"✗ Pentest falhou: {resultado.get('erro', 'Erro desconhecido')}")
                return
            
            self.logger.info("✓ Pentest concluído com sucesso!")
            
            stats = resultado.get('estatisticas', {})
            self.logger.info(f"\n=== Estatísticas Finais ===")
            self.logger.info(f"  IPs descobertos: {stats.get('ips_descobertos', 0)}")
            self.logger.info(f"  Portas abertas: {stats.get('total_portas_abertas', 0)}")
            self.logger.info(f"  Serviços detectados: {stats.get('servicos_detectados', 0)}")
            self.logger.info(f"  Vulnerabilidades: {stats.get('vulnerabilidades_encontradas', 0)}")
            self.logger.info(f"  Módulos executados: {stats.get('modulos_executados', 0)}")
            self.logger.info(f"  Tempo total: {resultado.get('tempo_total', 'N/A')}")
            
            # Mostrar vulnerabilidades críticas se houver
            vulnerabilidades = resultado.get('vulnerabilidades_encontradas', [])
            if vulnerabilidades:
                criticas = [v for v in vulnerabilidades 
                           if v.get('severidade', '').lower() in ['critical', 'critica', 'alta', 'high']]
                if criticas:
                    self.logger.info(f"\n⚠️  {len(criticas)} vulnerabilidades críticas encontradas!")
                    for vuln in criticas[:3]:  # Mostrar até 3
                        tipo = vuln.get('tipo', 'N/A')
                        desc = vuln.get('descricao', 'N/A')[:100]
                        self.logger.info(f"   - {tipo}: {desc}...")
                        
        except Exception as e:
            self.logger.error(f"Erro ao exibir estatísticas: {e}")
    
    def _convert_strategy_results_to_legacy_format(self, results: List, context) -> Dict[str, Any]:
        """
        Converte resultados das estratégias para formato legado compatível
        
        Args:
            results: Lista de StrategyResult das estratégias executadas
            context: ScanContext com estado do scan
            
        Returns:
            Dicionário no formato esperado pelo sistema legado
        """
        try:
            from core.scan_context import ScanContext
            
            # Criar estrutura base compatível
            resultado_legado = {
                'sucesso_geral': True,
                'alvo': context.target,
                'timestamp': context.execution_start_time.isoformat() if context.execution_start_time else None,
                'dados_descoberta': {},
                'vulnerabilidades_encontradas': context.vulnerabilities,
                'estatisticas': {},
                'tempo_total': None,
                'modulos_executados': []
            }
            
            # Processar descobertas por tipo
            if context.discovered_hosts:
                resultado_legado['dados_descoberta']['hosts'] = context.discovered_hosts
            
            if context.open_ports:
                resultado_legado['dados_descoberta']['portas'] = context.open_ports
                
            if context.services:
                resultado_legado['dados_descoberta']['servicos'] = {}
                for host, services in context.services.items():
                    resultado_legado['dados_descoberta']['servicos'][host] = [
                        {
                            'porta': s.port,
                            'servico': s.service_name,
                            'versao': s.version,
                            'estado': s.state
                        } for s in services
                    ]
            
            # Calcular estatísticas
            total_hosts = len(context.discovered_hosts)
            total_ports = sum(len(ports) for ports in context.open_ports.values())
            total_services = sum(len(services) for services in context.services.values())
            total_vulns = len(context.vulnerabilities)
            
            resultado_legado['estatisticas'] = {
                'ips_descobertos': total_hosts,
                'total_portas_abertas': total_ports,
                'servicos_detectados': total_services,
                'vulnerabilidades_encontradas': total_vulns,
                'modulos_executados': len([r for r in results if r.success])
            }
            
            # Calcular tempo total se disponível
            if context.execution_start_time and context.execution_end_time:
                delta = context.execution_end_time - context.execution_start_time
                resultado_legado['tempo_total'] = f"{delta.total_seconds():.2f}s"
            
            # Adicionar informações dos módulos executados
            for result in results:
                if result.success:
                    resultado_legado['modulos_executados'].append({
                        'nome': result.strategy_name,
                        'sucesso': result.success,
                        'tempo_execucao': result.execution_time,
                        'confianca': result.confidence_score
                    })
            
            # Adicionar dados específicos das estratégias
            strategy_data = {}
            for result in results:
                if result.success and result.data:
                    strategy_data[result.strategy_name] = result.data
            
            if strategy_data:
                resultado_legado['dados_estrategias'] = strategy_data
            
            # Determinar sucesso geral
            resultado_legado['sucesso_geral'] = any(r.success for r in results)
            
            self.logger.debug(f"Convertidos resultados de {len(results)} estratégias para formato legado")
            return resultado_legado
            
        except Exception as e:
            self.logger.error(f"Erro ao converter resultados das estratégias: {e}")
            return {
                'sucesso_geral': False,
                'erro': f"Erro na conversão: {e}",
                'alvo': getattr(context, 'target', 'unknown')
            }


def parse_arguments() -> argparse.Namespace:
    """Parse argumentos da linha de comando"""
    parser = argparse.ArgumentParser(
        description='VarreduraIA - Pentest Inteligente Refatorado',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s --alvo google.com
  %(prog)s --alvo 192.168.1.208 --verbose
  %(prog)s --alvo example.com --web-scan --usuario admin --senha 123
  %(prog)s --alvo https://site.com --web-gemini
  %(prog)s --alvo https://app.com --vuln-test
        """
    )
    
    # Argumentos principais
    parser.add_argument('--alvo', required=True, 
                       help='Domínio, IP ou URL do alvo')
    parser.add_argument('--verbose', action='store_true',
                       help='Saída verbosa no console')
    
    # Modos de execução
    parser.add_argument('--web-scan', action='store_true',
                       help='Modo Web: análise com navegador')
    parser.add_argument('--web-gemini', action='store_true',
                       help='Modo Web com Gemini: login automático + análise IA')
    parser.add_argument('--vuln-test', action='store_true',
                       help='Modo de teste de vulnerabilidades específicas')
    
    # Credenciais para modos web
    parser.add_argument('--usuario', help='Usuário para autenticação web')
    parser.add_argument('--senha', help='Senha para autenticação web')
    
    # Configurações avançadas
    parser.add_argument('--profile', default='development',
                       choices=['development', 'production', 'testing'],
                       help='Perfil de configuração a usar')
    parser.add_argument('--config', help='Arquivo de configuração personalizado')
    
    return parser.parse_args()


def setup_console_logging(verbose: bool):
    """Configura logging do console baseado na verbosidade"""
    try:
        from utils.logger import log_manager
        log_manager.definir_console_verbose(verbose)
    except Exception as e:
        print(f"Aviso: Erro ao configurar logging: {e}")


def main() -> int:
    """Função principal refatorada"""
    try:
        # Parse argumentos
        args = parse_arguments()
        
        # Configurar logging do console
        setup_console_logging(args.verbose)
        
        # Criar container configurado
        container = create_configured_container(
            profile=args.profile,
            config_path=args.config
        )
        
        # Registrar estratégias da Fase 2
        try:
            container.register_strategies()
            print("✅ Estratégias da Fase 2 registradas com sucesso")
        except Exception as e:
            print(f"⚠️  Aviso: Erro ao registrar estratégias: {e}")
            print("   Continuando com sistema legado...")
        
        # Criar e executar aplicação
        app = PentestApplication(container)
        return app.execute_pentest(args)
        
    except Exception as e:
        print(f"✗ Erro crítico na inicialização: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
