#!/usr/bin/env python3
"""
Orquestrador Inteligente de Varreduras - Fase 1: Resolução DNS
Script principal focado na primeira etapa: resolução DNS para IP
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
from modulos.resolucao_dns import ResolucaoDNS
from utils.logger import obter_logger, log_manager

class OrquestradorDNS:
    """Orquestrador focado na resolução DNS - Primeira etapa"""
    
    def __init__(self):
        """Inicializa o orquestrador DNS"""
        self.logger = obter_logger('OrquestradorDNS')
        self.resolver_dns = ResolucaoDNS()
        
        self.logger.info("Orquestrador DNS inicializado")
    
    def executar_resolucao_dns(self, alvo: str) -> Dict[str, Any]:
        """
        Executa resolução DNS do alvo
        Args:
            alvo (str): Alvo (domínio ou IP) para resolver
        Returns:
            Dict[str, Any]: Resultados da resolução DNS
        """
        self.logger.info(f"Iniciando resolução DNS para {alvo}")
        
        resultado_completo = {
            'timestamp_inicio': datetime.now().isoformat(),
            'alvo_original': alvo,
            'fase': 'resolucao_dns',
            'resolucao_dns': {},
            'sucesso_geral': False
        }
        
        try:
            # Executar resolução DNS
            self.logger.info("Executando resolução DNS...")
            resultado_dns = self.resolver_dns.resolver_dns(alvo)
            resultado_completo['resolucao_dns'] = resultado_dns
            
            if not resultado_dns.get('sucesso'):
                self.logger.error(f"Falha na resolução DNS: {resultado_dns.get('erro')}")
                resultado_completo['erro'] = f"Falha na resolução DNS: {resultado_dns.get('erro')}"
                return resultado_completo
            
            self.logger.info("Resolução DNS concluída com sucesso")
            
            resultado_completo['sucesso_geral'] = True
            resultado_completo['timestamp_fim'] = datetime.now().isoformat()
            
            # Gerar resumo
            resumo = self.resolver_dns.gerar_resumo(resultado_dns)
            resultado_completo['resumo'] = resumo
            
            # Log da sessão
            log_manager.log_sessao_pentest('resolucao_dns', {
                'alvo': alvo,
                'tipo_alvo': resultado_dns.get('tipo_alvo', 'desconhecido'),
                'sucesso': resultado_dns.get('sucesso', False),
                'ips_encontrados': len(resumo.get('ips_encontrados', [])) if resumo.get('ips_encontrados') else 0,
                'dominios_encontrados': len(resumo.get('dominios_encontrados', [])) if resumo.get('dominios_encontrados') else 0
            })
            
            return resultado_completo
            
        except Exception as e:
            self.logger.error(f"Erro na execução: {str(e)}")
            resultado_completo['erro'] = f'Erro na execução: {str(e)}'
            resultado_completo['timestamp_fim'] = datetime.now().isoformat()
            return resultado_completo

    
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
            # Garantir que o arquivo vai para a pasta dados
            if not arquivo.startswith('dados/'):
                # Se não especificou pasta, usar dados/
                arquivo = f"dados/{Path(arquivo).name}"
            
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
        Gera relatório HTML dos resultados de resolução DNS
        Args:
            resultados (Dict): Resultados da resolução DNS
            arquivo_saida (str): Arquivo de saída HTML
        Returns:
            bool: True se gerou com sucesso
        """
        try:
            # Garantir que o arquivo vai para a pasta relatorios
            if not arquivo_saida.startswith('relatorios/'):
                # Se não especificou pasta, usar relatorios/
                arquivo_saida = f"relatorios/{Path(arquivo_saida).name}"
            
            # Criar diretório se não existir
            Path(arquivo_saida).parent.mkdir(parents=True, exist_ok=True)
            
            html_content = self._criar_html_dns(resultados)
            
            # Salvar arquivo HTML
            with open(arquivo_saida, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Relatório HTML gerado: {arquivo_saida}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório HTML: {str(e)}")
            return False
    
    def _criar_html_dns(self, resultados: Dict[str, Any]) -> str:
        """
        Cria HTML específico para resultados de DNS
        Args:
            resultados (Dict): Resultados da resolução DNS
        Returns:
            str: Conteúdo HTML
        """
        resumo = resultados.get('resumo', {})
        dns_data = resultados.get('resolucao_dns', {}).get('dados', {})
        
        html = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Resolução DNS - {resultados.get('alvo_original', 'N/A')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; margin: -20px -20px 20px -20px; border-radius: 8px 8px 0 0; }}
        .summary {{ background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .section {{ margin-bottom: 30px; }}
        .section h3 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #3498db; color: white; }}
        .status-success {{ color: #27ae60; font-weight: bold; }}
        .status-error {{ color: #e74c3c; font-weight: bold; }}
        .info-box {{ background-color: #d5dbdb; padding: 10px; border-left: 4px solid #3498db; margin: 10px 0; }}
        ul {{ margin: 10px 0; padding-left: 20px; }}
        li {{ margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Relatório de Resolução DNS</h1>
            <p>Alvo: <strong>{resultados.get('alvo_original', 'N/A')}</strong></p>
            <p>Data: <strong>{resultados.get('timestamp_inicio', 'N/A')}</strong></p>
        </div>
        
        <div class="summary">
            <h2>Resumo Executivo</h2>
            <table>
                <tr><th>Status</th><td class="{'status-success' if resultados.get('sucesso_geral') else 'status-error'}">{'Sucesso' if resultados.get('sucesso_geral') else 'Falha'}</td></tr>
                <tr><th>Tipo de Alvo</th><td>{resumo.get('tipo_alvo', 'N/A').title()}</td></tr>"""
        
        if resumo.get('tipo_alvo') == 'dominio':
            html += f"""
                <tr><th>IP Principal</th><td>{resumo.get('ip_principal', 'N/A')}</td></tr>
                <tr><th>Total de IPs</th><td>{resumo.get('total_ips', 0)}</td></tr>
                <tr><th>Possui IPv6</th><td>{'Sim' if resumo.get('possui_ipv6') else 'Não'}</td></tr>
                <tr><th>Possui MX</th><td>{'Sim' if resumo.get('possui_mx') else 'Não'}</td></tr>"""
        else:
            html += f"""
                <tr><th>Hostname Principal</th><td>{resumo.get('hostname_principal', 'N/A')}</td></tr>
                <tr><th>Total de Domínios</th><td>{resumo.get('total_dominios', 0)}</td></tr>
                <tr><th>Resolução Reversa</th><td>{'Sim' if resumo.get('possui_resolucao_reversa') else 'Não'}</td></tr>"""
        
        html += """
            </table>
        </div>"""
        
        if resultados.get('sucesso_geral'):
            # Seção de detalhes
            if resumo.get('tipo_alvo') == 'dominio':
                html += f"""
        <div class="section">
            <h3>Endereços IP Encontrados</h3>
            <ul>"""
                for ip in resumo.get('ips_encontrados', []):
                    html += f"<li>{ip}</li>"
                
                html += """
            </ul>
        </div>"""
                
                # Registros DNS
                registros_dns = dns_data.get('registros_dns', {})
                if registros_dns:
                    html += """
        <div class="section">
            <h3>Registros DNS</h3>"""
                    
                    for tipo, valores in registros_dns.items():
                        if valores:
                            html += f"""
            <div class="info-box">
                <strong>Registros {tipo}:</strong>
                <ul>"""
                            for valor in valores:
                                html += f"<li>{valor}</li>"
                            html += """
                </ul>
            </div>"""
                    
                    html += """
        </div>"""
            
            else:  # IP
                html += f"""
        <div class="section">
            <h3>Domínios Encontrados</h3>
            <ul>"""
                for dominio in resumo.get('dominios_encontrados', []):
                    html += f"<li>{dominio}</li>"
                
                html += """
            </ul>
        </div>"""
        
        else:
            # Seção de erro
            html += f"""
        <div class="section">
            <h3>Erro na Resolução</h3>
            <div class="info-box" style="border-left-color: #e74c3c;">
                <strong>Erro:</strong> {resultados.get('erro', 'Erro desconhecido')}
            </div>
        </div>"""
        
        # Próximos passos
        html += """
        <div class="section">
            <h3>Próximos Passos Recomendados</h3>
            <ul>"""
        
        if resultados.get('sucesso_geral'):
            if resumo.get('tipo_alvo') == 'dominio':
                html += """
                <li>Executar varredura de portas nos IPs descobertos</li>
                <li>Verificar subdomínios se aplicável</li>
                <li>Analisar registros DNS para informações adicionais</li>"""
            else:
                html += """
                <li>Executar varredura de portas no IP</li>
                <li>Investigar domínios associados se encontrados</li>
                <li>Verificar outros IPs na mesma rede</li>"""
        else:
            html += """
                <li>Verificar conectividade de rede</li>
                <li>Confirmar se o alvo está correto</li>
                <li>Tentar resolução manual</li>"""
        
        html += """
            </ul>
        </div>
        
        <div class="section">
            <h3>Informações Técnicas</h3>
            <div class="info-box">
                <p><strong>Timestamp Início:</strong> {timestamp_inicio}</p>
                <p><strong>Timestamp Fim:</strong> {timestamp_fim}</p>
                <p><strong>Fase:</strong> {fase}</p>
            </div>
        </div>
    </div>
</body>
</html>""".format(
            timestamp_inicio=resultados.get('timestamp_inicio', 'N/A'),
            timestamp_fim=resultados.get('timestamp_fim', 'N/A'),
            fase=resultados.get('fase', 'N/A')
        )
        
        return html

def main():
    """Função principal - Fase 1: Resolução DNS"""
    parser = argparse.ArgumentParser(
        description='Orquestrador Inteligente - Fase 1: Resolução DNS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Exemplos de uso:
            %(prog)s --alvo google.com
            %(prog)s --alvo 8.8.8.8 --salvar resultado_dns.json
            %(prog)s --alvo example.com --relatorio-html relatorio.html
                    """
    )
    
    # Parâmetros principais
    parser.add_argument('--alvo', required=True, help='Domínio ou IP para resolver')
    
    # Saída
    parser.add_argument('--salvar', help='Arquivo para salvar resultados JSON')
    parser.add_argument('--relatorio-html', help='Gerar relatório HTML')
    parser.add_argument('--verbose', action='store_true', help='Saída verbosa')
    
    args = parser.parse_args()
    
    # Configurar logging
    if args.verbose:
        log_manager.definir_nivel('DEBUG')
    
    try:
        orquestrador = OrquestradorDNS()
        
        print(f"=== Orquestrador Inteligente - Fase 1: Resolução DNS ===")
        print(f"Alvo: {args.alvo}")
        print()
        
        # Executar resolução DNS
        resultados = orquestrador.executar_resolucao_dns(args.alvo)
        
        if resultados.get('sucesso_geral'):
            print("✓ Resolução DNS concluída com sucesso!")
            
            # Exibir resumo
            resumo = resultados.get('resumo', {})
            
            print(f"\nResumo:")
            print(f"  Tipo de alvo: {resumo.get('tipo_alvo', 'N/A').title()}")
            
            if resumo.get('tipo_alvo') == 'dominio':
                print(f"  IP principal: {resumo.get('ip_principal', 'N/A')}")
                print(f"  Total de IPs: {resumo.get('total_ips', 0)}")
                if resumo.get('ips_encontrados'):
                    print(f"  IPs encontrados: {', '.join(resumo['ips_encontrados'])}")
                print(f"  Possui IPv6: {'Sim' if resumo.get('possui_ipv6') else 'Não'}")
                print(f"  Possui MX: {'Sim' if resumo.get('possui_mx') else 'Não'}")
            else:
                print(f"  Hostname principal: {resumo.get('hostname_principal', 'N/A')}")
                print(f"  Total de domínios: {resumo.get('total_dominios', 0)}")
                if resumo.get('dominios_encontrados'):
                    print(f"  Domínios encontrados: {', '.join(resumo['dominios_encontrados'])}")
                print(f"  Resolução reversa: {'Sim' if resumo.get('possui_resolucao_reversa') else 'Não'}")
            
            # Salvar resultados
            if args.salvar:
                if orquestrador.salvar_resultados(resultados, args.salvar):
                    print(f"\n✓ Resultados salvos em: {args.salvar}")
            
            # Gerar relatório HTML
            if args.relatorio_html:
                if orquestrador.gerar_relatorio_html(resultados, args.relatorio_html):
                    print(f"✓ Relatório HTML gerado: {args.relatorio_html}")
            
            print(f"\n=== Próximos Passos ===")
            if resumo.get('tipo_alvo') == 'dominio':
                print("1. Executar varredura de portas nos IPs descobertos")
                print("2. Verificar subdomínios")
                print("3. Analisar registros DNS para informações adicionais")
            else:
                print("1. Executar varredura de portas no IP")
                print("2. Investigar domínios associados")
                print("3. Verificar outros IPs na mesma rede")
            
            return 0
        else:
            print(f"✗ Falha na resolução DNS: {resultados.get('erro', 'Erro desconhecido')}")
            return 1
    
    except KeyboardInterrupt:
        print("\n✗ Operação cancelada pelo usuário")
        return 1
    except Exception as e:
        print(f"✗ Erro inesperado: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())