#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interface de linha de comando para o sistema de pentest
Comandos em português para varredura, configuração e relatórios
"""

import os
import sys
import argparse
import json
from typing import List, Dict, Any, Optional
from pathlib import Path

# Adicionar o diretório raiz ao path para imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.configuracao import config, GerenciadorConfiguracao
from modulos.varredura_nmap import VarreduraNmap
from utils.logger import obter_logger, log_manager

class InterfaceCLI:
    """Interface de linha de comando principal"""
    
    def __init__(self):
        """Inicializa a interface CLI"""
        self.logger = obter_logger('CLI')
        self.varredura_nmap = VarreduraNmap()
        self.config_manager = config
        
    def configurar_argumentos(self) -> argparse.ArgumentParser:
        """
        Configura os argumentos da linha de comando
        
        Returns:
            argparse.ArgumentParser: Parser configurado
        """
        parser = argparse.ArgumentParser(
            description='Sistema de Pentest com Nmap e Análise IA',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Exemplos de uso:
  %(prog)s varrer --alvo 192.168.1.1 --tipo basico
  %(prog)s varrer --alvo scanme.nmap.org --tipo completo --portas 1-1000
  %(prog)s varrer --alvo 192.168.1.0/24 --tipo descoberta
  %(prog)s configurar --interativo
  %(prog)s relatorio --arquivo resultado.json
  %(prog)s diagnostico --sistema
            """
        )
        
        # Subcomandos
        subparsers = parser.add_subparsers(dest='comando', help='Comandos disponíveis')
        
        # Comando: varrer
        parser_varrer = subparsers.add_parser('varrer', help='Executar varredura Nmap')
        parser_varrer.add_argument('--alvo', required=True, help='IP, hostname ou rede CIDR')
        parser_varrer.add_argument('--tipo', choices=['basico', 'completo', 'vulnerabilidades', 'web', 'smb', 'descoberta'],
                                 default='basico', help='Tipo de varredura')
        parser_varrer.add_argument('--portas', help='Especificação de portas (ex: 1-1000, 80,443)')
        parser_varrer.add_argument('--scripts', nargs='+', help='Scripts NSE específicos')
        parser_varrer.add_argument('--opcoes', nargs='+', help='Opções customizadas do Nmap')
        parser_varrer.add_argument('--salvar', help='Arquivo para salvar resultados JSON')
        parser_varrer.add_argument('--relatorio', action='store_true', help='Exibir relatório resumido')
        
        # Comando: configurar
        parser_config = subparsers.add_parser('configurar', help='Gerenciar configurações')
        parser_config.add_argument('--interativo', action='store_true', help='Configuração interativa')
        parser_config.add_argument('--listar', action='store_true', help='Listar configurações atuais')
        parser_config.add_argument('--definir', nargs=2, metavar=('CHAVE', 'VALOR'), help='Definir configuração')
        parser_config.add_argument('--obter', help='Obter valor de configuração')
        parser_config.add_argument('--validar', action='store_true', help='Validar configurações')
        
        # Comando: relatorio
        parser_relatorio = subparsers.add_parser('relatorio', help='Gerar relatórios')
        parser_relatorio.add_argument('--arquivo', help='Arquivo JSON com resultados')
        parser_relatorio.add_argument('--formato', choices=['texto', 'html', 'json'], default='texto',
                                    help='Formato do relatório')
        parser_relatorio.add_argument('--saida', help='Arquivo de saída do relatório')
        
        # Comando: diagnostico
        parser_diag = subparsers.add_parser('diagnostico', help='Diagnósticos do sistema')
        parser_diag.add_argument('--sistema', action='store_true', help='Verificar sistema')
        parser_diag.add_argument('--nmap', action='store_true', help='Verificar Nmap')
        parser_diag.add_argument('--api', action='store_true', help='Testar API Gemini')
        parser_diag.add_argument('--logs', action='store_true', help='Estatísticas de logs')
        
        # Comando: scripts
        parser_scripts = subparsers.add_parser('scripts', help='Gerenciar scripts NSE')
        parser_scripts.add_argument('--listar', nargs='?', const='all', help='Listar scripts NSE')
        parser_scripts.add_argument('--categoria', help='Filtrar por categoria')
        parser_scripts.add_argument('--buscar', help='Buscar scripts por palavra-chave')
        
        # Comando: sessao
        parser_sessao = subparsers.add_parser('sessao', help='Gerenciar sessões de pentest')
        parser_sessao.add_argument('--nova', help='Criar nova sessão')
        parser_sessao.add_argument('--listar', action='store_true', help='Listar sessões')
        parser_sessao.add_argument('--carregar', help='Carregar sessão por ID')
        
        # Opções globais
        parser.add_argument('--verbose', '-v', action='store_true', help='Saída verbosa')
        parser.add_argument('--quiet', '-q', action='store_true', help='Saída silenciosa')
        parser.add_argument('--config', help='Arquivo de configuração personalizado')
        
        return parser
    
    def executar_varredura(self, args) -> bool:
        """
        Executa varredura conforme argumentos
        
        Args:
            args: Argumentos da linha de comando
            
        Returns:
            bool: True se bem-sucedida
        """
        self.logger.info(f"Iniciando varredura {args.tipo} em {args.alvo}")
        
        try:
            # Determinar tipo de varredura
            if args.tipo == 'basico':
                resultado = self.varredura_nmap.varredura_basica(args.alvo, args.portas)
            elif args.tipo == 'completo':
                resultado = self.varredura_nmap.varredura_completa(args.alvo, args.portas)
            elif args.tipo == 'vulnerabilidades':
                resultado = self.varredura_nmap.varredura_vulnerabilidades(args.alvo, args.portas)
            elif args.tipo == 'web':
                resultado = self.varredura_nmap.varredura_servicos_web(args.alvo)
            elif args.tipo == 'smb':
                resultado = self.varredura_nmap.varredura_smb(args.alvo)
            elif args.tipo == 'descoberta':
                resultado = self.varredura_nmap.varredura_descoberta_rede(args.alvo)
            else:
                # Varredura personalizada
                opcoes = args.opcoes or []
                if args.portas:
                    opcoes.extend(['-p', args.portas])
                resultado = self.varredura_nmap.varredura_personalizada(args.alvo, opcoes, args.scripts)
            
            # Log do resultado
            log_manager.log_varredura_nmap(args.tipo, args.alvo, resultado)
            
            # Salvar resultados se solicitado
            if args.salvar:
                with open(args.salvar, 'w', encoding='utf-8') as arquivo:
                    json.dump(resultado, arquivo, indent=2, ensure_ascii=False)
                print(f"✓ Resultados salvos em: {args.salvar}")
            
            # Exibir relatório se solicitado
            if args.relatorio or not args.quiet:
                if resultado.get('sucesso'):
                    relatorio = self.varredura_nmap.gerar_relatorio_resumido(resultado)
                    print(relatorio)
                else:
                    print(f"✗ Erro na varredura: {resultado.get('erro', 'Erro desconhecido')}")
            
            return resultado.get('sucesso', False)
            
        except Exception as e:
            self.logger.error(f"Erro na execução da varredura: {str(e)}")
            print(f"✗ Erro: {str(e)}")
            return False
    
    def gerenciar_configuracao(self, args) -> bool:
        """
        Gerencia configurações do sistema
        
        Args:
            args: Argumentos da linha de comando
            
        Returns:
            bool: True se bem-sucedida
        """
        try:
            if args.interativo:
                self.config_manager.configuracao_interativa()
                return True
            
            elif args.listar:
                configuracoes = self.config_manager.obter_todas_configuracoes()
                print("=== Configurações Atuais ===")
                self._imprimir_configuracoes(configuracoes)
                return True
            
            elif args.definir:
                chave, valor = args.definir
                # Tentar converter valor para tipo apropriado
                try:
                    if valor.lower() in ['true', 'false']:
                        valor = valor.lower() == 'true'
                    elif valor.isdigit():
                        valor = int(valor)
                    elif '.' in valor and valor.replace('.', '').isdigit():
                        valor = float(valor)
                except:
                    pass  # Manter como string
                
                self.config_manager.definir_configuracao(chave, valor)
                print(f"✓ Configuração definida: {chave} = {valor}")
                return True
            
            elif args.obter:
                valor = self.config_manager.obter_configuracao(args.obter)
                print(f"{args.obter}: {valor}")
                return True
            
            elif args.validar:
                erros = self.config_manager.validar_configuracoes()
                if erros:
                    print("✗ Problemas encontrados:")
                    for erro, descricao in erros.items():
                        print(f"  {erro}: {descricao}")
                    return False
                else:
                    print("✓ Todas as configurações estão válidas!")
                    return True
            
            else:
                print("Especifique uma ação para configuração. Use --help para ajuda.")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro no gerenciamento de configuração: {str(e)}")
            print(f"✗ Erro: {str(e)}")
            return False
    
    def _imprimir_configuracoes(self, config_dict: Dict[str, Any], prefixo: str = ""):
        """
        Imprime configurações de forma hierárquica
        
        Args:
            config_dict (Dict): Dicionário de configurações
            prefixo (str): Prefixo para chaves aninhadas
        """
        for chave, valor in config_dict.items():
            chave_completa = f"{prefixo}.{chave}" if prefixo else chave
            
            if isinstance(valor, dict):
                print(f"{chave_completa}:")
                self._imprimir_configuracoes(valor, chave_completa)
            else:
                print(f"  {chave_completa}: {valor}")
    
    def gerar_relatorio(self, args) -> bool:
        """
        Gera relatórios de resultados
        
        Args:
            args: Argumentos da linha de comando
            
        Returns:
            bool: True se bem-sucedida
        """
        try:
            if not args.arquivo:
                print("✗ Especifique um arquivo de resultados com --arquivo")
                return False
            
            if not Path(args.arquivo).exists():
                print(f"✗ Arquivo não encontrado: {args.arquivo}")
                return False
            
            # Carregar resultados
            with open(args.arquivo, 'r', encoding='utf-8') as arquivo:
                resultado = json.load(arquivo)
            
            # Gerar relatório conforme formato
            if args.formato == 'texto':
                relatorio = self.varredura_nmap.gerar_relatorio_resumido(resultado)
            elif args.formato == 'json':
                relatorio = json.dumps(resultado, indent=2, ensure_ascii=False)
            elif args.formato == 'html':
                relatorio = self._gerar_relatorio_html(resultado)
            else:
                print(f"✗ Formato não suportado: {args.formato}")
                return False
            
            # Salvar ou exibir relatório
            if args.saida:
                with open(args.saida, 'w', encoding='utf-8') as arquivo:
                    arquivo.write(relatorio)
                print(f"✓ Relatório salvo em: {args.saida}")
            else:
                print(relatorio)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erro na geração de relatório: {str(e)}")
            print(f"✗ Erro: {str(e)}")
            return False
    
    def _gerar_relatorio_html(self, resultado: Dict[str, Any]) -> str:
        """
        Gera relatório em formato HTML
        
        Args:
            resultado (Dict): Resultado da varredura
            
        Returns:
            str: Relatório HTML
        """
        dados = resultado.get('dados', {})
        resumo = dados.get('resumo', {})
        
        html = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Pentest</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .host {{ border: 1px solid #bdc3c7; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .port {{ background-color: #f8f9fa; margin: 5px 0; padding: 10px; border-left: 4px solid #3498db; }}
        .vulnerability {{ border-left: 4px solid #e74c3c; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Relatório de Pentest</h1>
        <p>Tipo: {resultado.get('tipo_varredura', 'N/A')}</p>
        <p>Timestamp: {resultado.get('timestamp', 'N/A')}</p>
    </div>
    
    <div class="summary">
        <h2>Resumo</h2>
        <table>
            <tr><th>Métrica</th><th>Valor</th></tr>
            <tr><td>Hosts Total</td><td>{resumo.get('hosts_total', 0)}</td></tr>
            <tr><td>Hosts Ativos</td><td>{resumo.get('hosts_ativos', 0)}</td></tr>
            <tr><td>Portas Abertas</td><td>{resumo.get('portas_abertas', 0)}</td></tr>
            <tr><td>Serviços Detectados</td><td>{resumo.get('servicos_detectados', 0)}</td></tr>
            <tr><td>Vulnerabilidades</td><td>{resumo.get('vulnerabilidades', 0)}</td></tr>
        </table>
    </div>
    
    <h2>Detalhes dos Hosts</h2>
"""
        
        # Adicionar detalhes dos hosts
        for host in dados.get('hosts', []):
            html += f"""
    <div class="host">
        <h3>Host: {host.get('endereco', 'N/A')}</h3>
        <p><strong>Status:</strong> {host.get('status', 'N/A')}</p>
        {f'<p><strong>Hostname:</strong> {host["hostname"]}</p>' if host.get('hostname') else ''}
        {f'<p><strong>OS:</strong> {host["os"]["nome"]} ({host["os"].get("precisao", "N/A")}%)</p>' if host.get('os', {}).get('nome') else ''}
        
        <h4>Portas Abertas</h4>
"""
            
            # Adicionar portas
            portas_abertas = [p for p in host.get('portas', []) if p.get('estado') == 'open']
            if portas_abertas:
                for porta in portas_abertas:
                    classe_vuln = 'vulnerability' if any('vuln' in s.get('id', '') for s in porta.get('scripts', [])) else ''
                    html += f"""
        <div class="port {classe_vuln}">
            <strong>{porta['numero']}/{porta['protocolo']}</strong> - {porta.get('servico', 'unknown')}
            {f' ({porta["produto"]} {porta["versao"]})' if porta.get('produto') else ''}
        </div>
"""
            else:
                html += "<p>Nenhuma porta aberta encontrada.</p>"
            
            html += "</div>"
        
        html += """
</body>
</html>
"""
        return html
    
    def executar_diagnostico(self, args) -> bool:
        """
        Executa diagnósticos do sistema
        
        Args:
            args: Argumentos da linha de comando
            
        Returns:
            bool: True se bem-sucedida
        """
        try:
            if args.sistema:
                print("=== Diagnóstico do Sistema ===")
                
                # Verificar Python
                print(f"Python: {sys.version}")
                
                # Verificar diretórios
                diretorios = ['logs', 'dados', 'relatorios', 'config']
                for diretorio in diretorios:
                    existe = Path(diretorio).exists()
                    print(f"Diretório {diretorio}: {'✓' if existe else '✗'}")
                
                # Verificar configurações
                erros_config = self.config_manager.validar_configuracoes()
                print(f"Configurações: {'✓' if not erros_config else '✗'}")
                
                return True
            
            elif args.nmap:
                print("=== Diagnóstico do Nmap ===")
                disponivel = self.varredura_nmap.verificar_nmap()
                print(f"Nmap disponível: {'✓' if disponivel else '✗'}")
                
                if disponivel:
                    scripts = self.varredura_nmap.listar_scripts_nse('discovery')
                    print(f"Scripts NSE disponíveis: {len(scripts)}")
                
                return disponivel
            
            elif args.api:
                print("=== Diagnóstico da API Gemini ===")
                try:
                    from cliente_gemini import ClienteGemini
                    cliente = ClienteGemini()
                    conectado = cliente.conectar()
                    print(f"API Gemini: {'✓' if conectado else '✗'}")
                    return conectado
                except ImportError:
                    print("✗ Módulo cliente_gemini não encontrado")
                    return False
            
            elif args.logs:
                print("=== Estatísticas de Logs ===")
                stats = log_manager.obter_estatisticas_log()
                for chave, valor in stats.items():
                    print(f"{chave}: {valor}")
                return True
            
            else:
                print("Especifique um tipo de diagnóstico. Use --help para ajuda.")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro no diagnóstico: {str(e)}")
            print(f"✗ Erro: {str(e)}")
            return False
    
    def gerenciar_scripts(self, args) -> bool:
        """
        Gerencia scripts NSE
        
        Args:
            args: Argumentos da linha de comando
            
        Returns:
            bool: True se bem-sucedida
        """
        try:
            if args.listar:
                categoria = args.categoria or (args.listar if args.listar != 'all' else None)
                # Garantir que categoria seja None ou string válida
                if categoria == 'all':
                    categoria = None
                scripts = self.varredura_nmap.listar_scripts_nse(categoria)
                
                print(f"=== Scripts NSE {'(' + categoria + ')' if categoria else ''} ===")
                for script in scripts:
                    print(f"  {script}")
                
                print(f"\nTotal: {len(scripts)} scripts")
                return True
            
            else:
                print("Especifique uma ação para scripts. Use --help para ajuda.")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro no gerenciamento de scripts: {str(e)}")
            print(f"✗ Erro: {str(e)}")
            return False
    
    def executar(self):
        """Executa a interface CLI"""
        parser = self.configurar_argumentos()
        args = parser.parse_args()
        
        # Configurar nível de logging
        if args.verbose:
            log_manager.definir_nivel('DEBUG')
        elif args.quiet:
            log_manager.definir_nivel('ERROR')
        
        # Carregar configuração personalizada se especificada
        if args.config:
            self.config_manager = GerenciadorConfiguracao(args.config)
        
        # Executar comando
        sucesso = False
        
        if args.comando == 'varrer':
            sucesso = self.executar_varredura(args)
        elif args.comando == 'configurar':
            sucesso = self.gerenciar_configuracao(args)
        elif args.comando == 'relatorio':
            sucesso = self.gerar_relatorio(args)
        elif args.comando == 'diagnostico':
            sucesso = self.executar_diagnostico(args)
        elif args.comando == 'scripts':
            sucesso = self.gerenciar_scripts(args)
        elif args.comando == 'sessao':
            print("Gerenciamento de sessões não implementado ainda.")
            sucesso = False
        else:
            parser.print_help()
            sucesso = False
        
        return 0 if sucesso else 1


def main():
    """Função principal"""
    try:
        cli = InterfaceCLI()
        return cli.executar()
    except KeyboardInterrupt:
        print("\n✗ Operação cancelada pelo usuário")
        return 1
    except Exception as e:
        print(f"✗ Erro inesperado: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())