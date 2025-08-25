#!/usr/bin/env python3
"""
Sistema de Pentest com Nmap e Análise IA
Script principal que integra varredura Nmap com análise inteligente usando IA
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

# Adicionar diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent))

# Imports dos módulos do sistema
from core.configuracao import config, GerenciadorConfiguracao
from modulos.varredura_nmap import VarreduraNmap
from modulos.analise_gemini import AnalisadorGemini
from utils.logger import obter_logger, log_manager
from cli.comandos import InterfaceCLI

class SistemaPentest:
    """Sistema principal de pentest com Nmap e IA"""
    
    def __init__(self):
        """Inicializa o sistema de pentest"""
        self.logger = obter_logger('SistemaPentest')
        self.varredura_nmap = VarreduraNmap()
        self.analisador_gemini = AnalisadorGemini()
        self.config_manager = config
        
        self.logger.info("Sistema de Pentest inicializado")
    
    def executar_varredura_com_analise(self, alvo: str, tipo_varredura: str = 'completo', 
                                     portas: Optional[str] = None, analisar_com_ia: bool = True) -> Dict[str, Any]:
        """
        Executa varredura completa com análise IA opcional
        Args:
            alvo (str): Alvo da varredura
            tipo_varredura (str): Tipo de varredura
            portas (str): Especificação de portas
            analisar_com_ia (bool): Se deve usar análise IA
        Returns:
            Dict[str, Any]: Resultados completos
        """
        self.logger.info(f"Iniciando varredura {tipo_varredura} em {alvo}")
        
        resultado_completo = {
            'timestamp_inicio': datetime.now().isoformat(),
            'alvo': alvo,
            'tipo_varredura': tipo_varredura,
            'configuracao_utilizada': self.config_manager.obter_todas_configuracoes(),
            'varredura_nmap': {},
            'analise_ia': {},
            'sucesso_geral': False
        }
        
        try:
            # 1. Executar varredura Nmap
            self.logger.info("Executando varredura Nmap...")
            
            if tipo_varredura == 'basico':
                resultado_nmap = self.varredura_nmap.varredura_basica(alvo, portas)
            elif tipo_varredura == 'completo':
                resultado_nmap = self.varredura_nmap.varredura_completa(alvo, portas)
            elif tipo_varredura == 'vulnerabilidades':
                resultado_nmap = self.varredura_nmap.varredura_vulnerabilidades(alvo, portas)
            elif tipo_varredura == 'web':
                resultado_nmap = self.varredura_nmap.varredura_servicos_web(alvo)
            elif tipo_varredura == 'smb':
                resultado_nmap = self.varredura_nmap.varredura_smb(alvo)
            elif tipo_varredura == 'descoberta':
                resultado_nmap = self.varredura_nmap.varredura_descoberta_rede(alvo)
            else:
                raise ValueError(f"Tipo de varredura não suportado: {tipo_varredura}")
            
            resultado_completo['varredura_nmap'] = resultado_nmap
            
            if not resultado_nmap.get('sucesso'):
                self.logger.error(f"Falha na varredura Nmap: {resultado_nmap.get('erro')}")
                resultado_completo['erro'] = f"Falha na varredura: {resultado_nmap.get('erro')}"
                return resultado_completo
            
            self.logger.info("Varredura Nmap concluída com sucesso")
            
            # 2. Análise IA (se solicitada)
            if analisar_com_ia:
                self.logger.info("Iniciando análise IA...")
                
                try:
                    # Conectar ao Gemini se necessário
                    if not self.analisador_gemini.conectado:
                        if not self.analisador_gemini.conectar():
                            self.logger.warning("Falha ao conectar com Gemini, pulando análise IA")
                            resultado_completo['analise_ia'] = {'erro': 'Falha na conexão com Gemini'}
                        else:
                            # Executar análises
                            analises = self._executar_analises_ia(resultado_nmap)
                            resultado_completo['analise_ia'] = analises
                            self.logger.info("Análise IA concluída")
                    else:
                        # Executar análises
                        analises = self._executar_analises_ia(resultado_nmap)
                        resultado_completo['analise_ia'] = analises
                        self.logger.info("Análise IA concluída")
                        
                except Exception as e:
                    self.logger.error(f"Erro na análise IA: {str(e)}")
                    resultado_completo['analise_ia'] = {'erro': f'Erro na análise IA: {str(e)}'}
            
            resultado_completo['sucesso_geral'] = True
            resultado_completo['timestamp_fim'] = datetime.now().isoformat()
            
            # Log da sessão
            log_manager.log_sessao_pentest('varredura_completa', {
                'alvo': alvo,
                'tipo': tipo_varredura,
                'sucesso_nmap': resultado_nmap.get('sucesso', False),
                'analise_ia_executada': analisar_com_ia and 'erro' not in resultado_completo['analise_ia'],
                'hosts_encontrados': len(resultado_nmap.get('dados', {}).get('hosts', [])),
                'vulnerabilidades': resultado_nmap.get('dados', {}).get('resumo', {}).get('vulnerabilidades', 0)
            })
            
            return resultado_completo
            
        except Exception as e:
            self.logger.error(f"Erro na execução: {str(e)}")
            resultado_completo['erro'] = f'Erro na execução: {str(e)}'
            resultado_completo['timestamp_fim'] = datetime.now().isoformat()
            return resultado_completo
    
    def _executar_analises_ia(self, resultado_nmap: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executa múltiplas análises IA nos resultados
        Args:
            resultado_nmap (Dict): Resultados da varredura Nmap
        Returns:
            Dict[str, Any]: Análises IA completas
        """
        analises = {}
        
        try:
            # Análise geral
            self.logger.info("Executando análise geral...")
            analises['analise_geral'] = self.analisador_gemini.analisar_varredura_completa(resultado_nmap)
            
            # Análise de vulnerabilidades
            self.logger.info("Executando análise de vulnerabilidades...")
            analises['vulnerabilidades'] = self.analisador_gemini.analisar_vulnerabilidades(resultado_nmap)
            
            # Análise de serviços
            self.logger.info("Executando análise de serviços...")
            analises['servicos'] = self.analisador_gemini.analisar_servicos(resultado_nmap)
            
            # Plano de pentest
            self.logger.info("Gerando plano de pentest...")
            analises['plano_pentest'] = self.analisador_gemini.gerar_plano_pentest(resultado_nmap)
            
            # Resumo consolidado
            analises['resumo_consolidado'] = self._consolidar_analises(analises)
            
        except Exception as e:
            self.logger.error(f"Erro nas análises IA: {str(e)}")
            analises['erro'] = f'Erro nas análises: {str(e)}'
        
        return analises
    
    def _consolidar_analises(self, analises: Dict[str, Any]) -> Dict[str, Any]:
        """
        Consolida todas as análises em um resumo
        Args:
            analises (Dict): Todas as análises executadas
        Returns:
            Dict[str, Any]: Resumo consolidado
        """
        consolidado = {
            'timestamp': datetime.now().isoformat(),
            'nivel_risco_maximo': 'Baixo',
            'vulnerabilidades_criticas': 0,
            'servicos_expostos': 0,
            'recomendacoes_prioritarias': [],
            'proximos_passos': []
        }
        
        try:
            # Determinar nível de risco máximo
            niveis_risco = []
            
            if 'analise_geral' in analises and 'nivel_risco_geral' in analises['analise_geral']:
                niveis_risco.append(analises['analise_geral']['nivel_risco_geral'])
            
            if 'vulnerabilidades' in analises and 'nivel_risco_geral' in analises['vulnerabilidades']:
                niveis_risco.append(analises['vulnerabilidades']['nivel_risco_geral'])
            
            if niveis_risco:
                ordem_risco = ['Crítico', 'Alto', 'Médio', 'Baixo']
                for nivel in ordem_risco:
                    if nivel in niveis_risco:
                        consolidado['nivel_risco_maximo'] = nivel
                        break
            
            # Contar vulnerabilidades críticas
            if 'vulnerabilidades' in analises:
                vuln_data = analises['vulnerabilidades']
                consolidado['vulnerabilidades_criticas'] = vuln_data.get('vulnerabilidades_encontradas', 0)
            
            # Contar serviços expostos
            if 'servicos' in analises:
                servicos_data = analises['servicos']
                consolidado['servicos_expostos'] = servicos_data.get('servicos_encontrados', 0)
            
            # Coletar recomendações
            for analise_tipo in ['analise_geral', 'vulnerabilidades', 'servicos']:
                if analise_tipo in analises and 'recomendacoes_prioritarias' in analises[analise_tipo]:
                    recom = analises[analise_tipo]['recomendacoes_prioritarias']
                    if isinstance(recom, list):
                        consolidado['recomendacoes_prioritarias'].extend(recom[:2])  # 2 por análise
            
            # Definir próximos passos baseado no risco
            if consolidado['nivel_risco_maximo'] == 'Crítico':
                consolidado['proximos_passos'] = [
                    'Priorizar correção imediata de vulnerabilidades críticas',
                    'Implementar monitoramento de segurança',
                    'Realizar pentest manual detalhado'
                ]
            elif consolidado['nivel_risco_maximo'] == 'Alto':
                consolidado['proximos_passos'] = [
                    'Corrigir vulnerabilidades de alto risco',
                    'Implementar hardening de serviços',
                    'Agendar pentest de verificação'
                ]
            else:
                consolidado['proximos_passos'] = [
                    'Implementar boas práticas de segurança',
                    'Monitorar logs de segurança',
                    'Agendar varreduras periódicas'
                ]
        
        except Exception as e:
            self.logger.error(f"Erro na consolidação: {str(e)}")
            consolidado['erro'] = f'Erro na consolidação: {str(e)}'
        
        return consolidado
    
    def salvar_resultados(self, resultados: Dict[str, Any], arquivo: str) -> bool:
        """
        Salva resultados em arquivo JSON
        Args:
            resultados (Dict): Resultados para salvar
            arquivo (str): Caminho do arquivo
        Returns:
            bool: True se salvou com sucesso
        """
        try:
            # Criar diretório se não existir
            Path(arquivo).parent.mkdir(parents=True, exist_ok=True)
            
            with open(arquivo, 'w', encoding='utf-8') as f:
                json.dump(resultados, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Resultados salvos em: {arquivo}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar resultados: {str(e)}")
            return False
    
    def gerar_relatorio_html(self, resultados: Dict[str, Any], arquivo_saida: str) -> bool:
        """
        Gera relatório HTML dos resultados
        Args:
            resultados (Dict): Resultados da varredura
            arquivo_saida (str): Arquivo de saída HTML
        Returns:
            bool: True se gerou com sucesso
        """
        try:
            from cli.comandos import InterfaceCLI
            cli = InterfaceCLI()
            
            html_content = cli._gerar_relatorio_html(resultados.get('varredura_nmap', {}))
            
            # Adicionar seção de análise IA se disponível
            if 'analise_ia' in resultados and 'erro' not in resultados['analise_ia']:
                analise_ia = resultados['analise_ia']
                
                html_ia = """
                    <div class="header" style="background-color: #8e44ad;">
                        <h2>Análise Inteligente (IA)</h2>
                    </div>
                """
                
                # Resumo consolidado
                if 'resumo_consolidado' in analise_ia:
                    resumo = analise_ia['resumo_consolidado']
                    html_ia += f"""
                        <div class="summary">
                            <h3>Resumo Consolidado</h3>
                            <table>
                                <tr><th>Nível de Risco Máximo</th><td>{resumo.get('nivel_risco_maximo', 'N/A')}</td></tr>
                                <tr><th>Vulnerabilidades Críticas</th><td>{resumo.get('vulnerabilidades_criticas', 0)}</td></tr>
                                <tr><th>Serviços Expostos</th><td>{resumo.get('servicos_expostos', 0)}</td></tr>
                            </table>
                            <h4>Próximos Passos Recomendados</h4>
                            <ul>
                    """
                    for passo in resumo.get('proximos_passos', []):
                        html_ia += f"<li>{passo}</li>"
                    
                    html_ia += "</ul></div>"
                
                # Inserir análise IA no HTML antes do fechamento
                html_content = html_content.replace('</body>', html_ia + '</body>')
            
            # Salvar arquivo HTML
            with open(arquivo_saida, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Relatório HTML gerado: {arquivo_saida}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório HTML: {str(e)}")
            return False
    
    def configuracao_inicial(self) -> bool:
        """
        Executa configuração inicial do sistema
        Returns:
            bool: True se configuração foi bem-sucedida
        """
        print("=== Configuração Inicial do Sistema de Pentest ===")
        print()
        
        try:
            # Verificar Nmap
            if not self.varredura_nmap.verificar_nmap():
                print("⚠ Nmap não encontrado!")
                print("Para Windows, instale via:")
                print("  1. Chocolatey: choco install nmap")
                print("  2. Download direto: https://nmap.org/download.html")
                print()
                
                continuar = input("Continuar sem Nmap? (s/n): ").strip().lower()
                if continuar not in ['s', 'sim', 'y', 'yes']:
                    return False
            else:
                print("✓ Nmap encontrado e funcional")
            
            # Configuração interativa
            print("\nConfigurando sistema...")
            self.config_manager.configuracao_interativa()
            
            # Testar conexão Gemini
            print("\nTestando conexão com Gemini...")
            if self.analisador_gemini.conectar():
                print("✓ Gemini conectado com sucesso")
            else:
                print("⚠ Falha na conexão com Gemini")
                print("  Verifique sua chave API em: https://aistudio.google.com/app/apikey")
            
            print("\n✓ Configuração inicial concluída!")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro na configuração inicial: {str(e)}")
            print(f"✗ Erro na configuração: {str(e)}")
            return False


def main():
    """Função principal"""
    parser = argparse.ArgumentParser(
        description='Sistema de Pentest com Nmap e Análise IA',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Exemplos de uso:
            %(prog)s --alvo 192.168.1.1 --tipo completo --ia
            %(prog)s --alvo scanme.nmap.org --tipo vulnerabilidades --salvar resultado.json
            %(prog)s --configurar
            %(prog)s --cli  # Usar interface CLI completa
                    """
    )
    
    # Modo de operação
    grupo_modo = parser.add_mutually_exclusive_group()
    grupo_modo.add_argument('--cli', action='store_true', help='Usar interface CLI completa')
    grupo_modo.add_argument('--configurar', action='store_true', help='Configuração inicial')
    
    # Parâmetros de varredura
    parser.add_argument('--alvo', help='IP, hostname ou rede CIDR')
    parser.add_argument('--tipo', choices=['basico', 'completo', 'vulnerabilidades', 'web', 'smb', 'descoberta'],
                       default='completo', help='Tipo de varredura')
    parser.add_argument('--portas', help='Especificação de portas')
    parser.add_argument('--ia', action='store_true', help='Usar análise IA')
    
    # Saída
    parser.add_argument('--salvar', help='Arquivo para salvar resultados JSON')
    parser.add_argument('--relatorio-html', help='Gerar relatório HTML')
    parser.add_argument('--verbose', action='store_true', help='Saída verbosa')
    
    args = parser.parse_args()
    
    # Configurar logging
    if args.verbose:
        log_manager.definir_nivel('DEBUG')
    
    try:
        sistema = SistemaPentest()
        
        # Modo CLI completo
        if args.cli:
            cli = InterfaceCLI()
            return cli.executar()
        
        # Configuração inicial
        elif args.configurar:
            return 0 if sistema.configuracao_inicial() else 1
        
        # Varredura
        elif args.alvo:
            print(f"Executando varredura {args.tipo} em {args.alvo}")
            if args.ia:
                print("Análise IA habilitada")
            
            resultados = sistema.executar_varredura_com_analise(
                alvo=args.alvo,
                tipo_varredura=args.tipo,
                portas=args.portas,
                analisar_com_ia=args.ia
            )
            
            if resultados.get('sucesso_geral'):
                print("✓ Varredura concluída com sucesso!")
                
                # Exibir resumo
                nmap_data = resultados.get('varredura_nmap', {}).get('dados', {})
                resumo = nmap_data.get('resumo', {})
                
                print(f"Hosts ativos: {resumo.get('hosts_ativos', 0)}")
                print(f"Portas abertas: {resumo.get('portas_abertas', 0)}")
                print(f"Serviços detectados: {resumo.get('servicos_detectados', 0)}")
                
                # Mostrar resumo IA se disponível
                if args.ia and 'analise_ia' in resultados:
                    analise = resultados['analise_ia']
                    if 'resumo_consolidado' in analise:
                        consolidado = analise['resumo_consolidado']
                        print(f"\nNível de risco: {consolidado.get('nivel_risco_maximo', 'N/A')}")
                        print(f"Vulnerabilidades: {consolidado.get('vulnerabilidades_criticas', 0)}")
                
                # Salvar resultados
                if args.salvar:
                    if sistema.salvar_resultados(resultados, args.salvar):
                        print(f"✓ Resultados salvos em: {args.salvar}")
                
                # Gerar relatório HTML
                if args.relatorio_html:
                    if sistema.gerar_relatorio_html(resultados, args.relatorio_html):
                        print(f"✓ Relatório HTML gerado: {args.relatorio_html}")
                
                return 0
            else:
                print(f"✗ Falha na varredura: {resultados.get('erro', 'Erro desconhecido')}")
                return 1
        
        else:
            parser.print_help()
            return 1
    
    except KeyboardInterrupt:
        print("\n✗ Operação cancelada pelo usuário")
        return 1
    except Exception as e:
        print(f"✗ Erro inesperado: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())