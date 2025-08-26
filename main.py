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
from typing import Dict, Any, Optional, List

# Adicionar diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent))

# Imports dos módulos do sistema serão feitos após configurar logging

class OrquestradorPentest:
    """Orquestrador de Pentest - DNS + Scan de Portas"""
    
    def __init__(self, resolver_dns, scanner_portas, scanner_nmap, decisao_ia, logger_func):
        """Inicializa o orquestrador"""
        self.logger = logger_func('OrquestradorPentest')
        self.resolver_dns = resolver_dns
        self.scanner_portas = scanner_portas
        self.scanner_nmap = scanner_nmap
        self.decisao_ia = decisao_ia
        
        self.logger.info("Orquestrador Pentest inicializado")
    
    def executar_pentest_inicial(self, alvo: str) -> Dict[str, Any]:
        """
        Executa pentest inicial: DNS + Scan de Portas
        Args:
            alvo (str): Alvo (domínio ou IP) para analisar
        Returns:
            Dict[str, Any]: Resultados completos
        """
        self.logger.info(f"Iniciando pentest inicial para {alvo}")
        
        resultado_completo = {
            'timestamp_inicio': datetime.now().isoformat(),
            'alvo_original': alvo,
            'fase': 'pentest_inicial',
            'resolucao_dns': {},
            'scan_portas': {},
            'sucesso_geral': False
        }
        
        try:
            #Resolução DNS
            self.logger.info("=== Resolução DNS ===")
            resultado_dns = self.resolver_dns.resolver_dns(alvo)
            resultado_completo['resolucao_dns'] = resultado_dns
            
            if not resultado_dns.get('sucesso'):
                self.logger.error(f"Falha na resolução DNS: {resultado_dns.get('erro')}")
                resultado_completo['erro'] = f"Falha na resolução DNS: {resultado_dns.get('erro')}"
                return resultado_completo
            
            self.logger.info("Resolução DNS concluída com sucesso")
            
            # Obter IPs para scan
            ips_para_scan = self._extrair_ips_para_scan(resultado_dns)
            
            if not ips_para_scan:
                self.logger.error("Nenhum IP encontrado para scan de portas")
                resultado_completo['erro'] = "Nenhum IP encontrado para scan de portas"
                return resultado_completo
            
            #Scan de Portas
            self.logger.info("=== Scan de Portas ===")
            resultados_scan = {}
            
            for ip in ips_para_scan:
                self.logger.info(f"Executando scan de portas em {ip}")
                resultado_scan = self.scanner_portas.executar_scan_portas(ip)
                resultados_scan[ip] = resultado_scan
                
                if resultado_scan.get('sucesso'):
                    resumo_scan = self.scanner_portas.gerar_resumo(resultado_scan)
                    self.logger.info(f"Scan concluído em {ip}: {resumo_scan.get('portas_abertas', 0)} portas abertas")
                else:
                    self.logger.warning(f"Falha no scan de {ip}: {resultado_scan.get('erro')}")
            
            resultado_completo['scan_portas'] = resultados_scan
            resultado_completo['sucesso_geral'] = True
            resultado_completo['timestamp_fim'] = datetime.now().isoformat()
            
            # Gerar resumos
            resumo_dns = self.resolver_dns.gerar_resumo(resultado_dns)
            resultado_completo['resumo_dns'] = resumo_dns
            
            resumo_scan = self._gerar_resumo_scan_completo(resultados_scan)
            resultado_completo['resumo_scan'] = resumo_scan
            
            # Etapa 3: Decisão IA para próximos passos
            self.logger.info("=== Análise IA e Decisão ===")
            decisao_ia = self.decisao_ia.decidir_proximos_passos(resultado_completo)
            resultado_completo['decisao_ia'] = decisao_ia
            
            # Executar Nmap avançado se recomendado
            if decisao_ia.get('executar_nmap_avancado', False):
                self.logger.info("=== Execução Nmap Avançado ===")
                resultados_nmap_avancado = self._executar_nmap_avancado(
                    ips_para_scan, 
                    decisao_ia.get('modulos_recomendados', []),
                    decisao_ia.get('portas_prioritarias', [])
                )
                resultado_completo['nmap_avancado'] = resultados_nmap_avancado
            else:
                self.logger.info("IA decidiu não executar Nmap avançado")
                resultado_completo['nmap_avancado'] = {
                    'executado': False,
                    'motivo': decisao_ia.get('justificativa_ia', 'IA não recomendou análise adicional')
                }
            
            # Log da sessão
            log_manager.log_sessao_pentest('pentest_inicial', {
                'alvo': alvo,
                'tipo_alvo': resultado_dns.get('tipo_alvo', 'desconhecido'),
                'ips_scaneados': len(ips_para_scan),
                'total_portas_abertas': resumo_scan.get('total_portas_abertas', 0),
                'hosts_ativos': resumo_scan.get('hosts_ativos', 0),
                'ia_recomendou_nmap': decisao_ia.get('executar_nmap_avancado', False),
                'modulos_ia_recomendados': len(decisao_ia.get('modulos_recomendados', []))
            })
            
            return resultado_completo
            
        except Exception as e:
            self.logger.error(f"Erro na execução: {str(e)}")
            resultado_completo['erro'] = f'Erro na execução: {str(e)}'
            resultado_completo['timestamp_fim'] = datetime.now().isoformat()
            return resultado_completo
    
    def _extrair_ips_para_scan(self, resultado_dns: Dict[str, Any]) -> List[str]:
        """
        Extrai IPs do resultado DNS para scan de portas
        Args:
            resultado_dns (Dict): Resultado da resolução DNS
        Returns:
            List[str]: Lista de IPs para scan
        """
        ips = []
        dados = resultado_dns.get('dados', {})
        tipo_alvo = resultado_dns.get('tipo_alvo', 'desconhecido')
        
        if tipo_alvo == 'dominio':
            # Se é domínio, pegar IPs resolvidos
            ips_resolvidos = dados.get('ips_resolvidos', [])
            ips.extend(ips_resolvidos)
        else:
            # Se já é IP, usar o próprio IP
            ip_original = dados.get('ip')
            if ip_original:
                ips.append(ip_original)
        
        # Remover duplicatas e IPs inválidos
        ips_unicos = list(set(ips))
        ips_validos = [ip for ip in ips_unicos if self._validar_ip(ip)]
        
        self.logger.info(f"IPs extraídos para scan: {ips_validos}")
        return ips_validos
    
    def _validar_ip(self, ip: str) -> bool:
        """
        Valida se é um IP válido
        Args:
            ip (str): IP para validar
        Returns:
            bool: True se válido
        """
        import socket
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def _gerar_resumo_scan_completo(self, resultados_scan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera resumo completo dos scans de portas
        Args:
            resultados_scan (Dict): Resultados de todos os scans
        Returns:
            Dict[str, Any]: Resumo consolidado
        """
        resumo = {
            'total_ips_scaneados': len(resultados_scan),
            'hosts_ativos': 0,
            'total_portas_abertas': 0,
            'hosts_com_portas_abertas': [],
            'resumo_por_host': {}
        }
        
        for ip, resultado in resultados_scan.items():
            if resultado.get('sucesso'):
                resumo_host = self.scanner_portas.gerar_resumo(resultado)
                resumo['resumo_por_host'][ip] = resumo_host
                
                if resumo_host.get('hosts_ativos', 0) > 0:
                    resumo['hosts_ativos'] += 1
                
                portas_abertas = resumo_host.get('portas_abertas', 0)
                resumo['total_portas_abertas'] += portas_abertas
                
                if portas_abertas > 0:
                    host_info = {
                        'ip': ip,
                        'portas_abertas': portas_abertas,
                        'portas': []
                    }
                    
                    # Extrair portas abertas
                    for host_detalhe in resumo_host.get('hosts_detalhes', []):
                        if host_detalhe.get('portas_abertas'):
                            host_info['portas'] = host_detalhe['portas_abertas']
                            break
                    
                    resumo['hosts_com_portas_abertas'].append(host_info)
        
        return resumo
    
    def _executar_nmap_avancado(self, ips: List[str], modulos_recomendados: List[str], 
                               portas_prioritarias: List[str]) -> Dict[str, Any]:
        """
        Executa varreduras Nmap avançadas baseadas na recomendação da IA
        Args:
            ips (List[str]): Lista de IPs para varredura
            modulos_recomendados (List[str]): Módulos recomendados pela IA
            portas_prioritarias (List[str]): Portas prioritárias para análise
        Returns:
            Dict[str, Any]: Resultados das varreduras avançadas
        """
        resultados_nmap = {
            'timestamp_inicio': datetime.now().isoformat(),
            'ips_analisados': ips,
            'modulos_executados': [],
            'resultados_por_modulo': {},
            'resumo_geral': {},
            'sucesso_geral': False
        }
        
        try:
            # Mapear nomes de módulos para métodos
            mapa_modulos = {
                'varredura_basica': self.scanner_nmap.varredura_basica,
                'varredura_completa': self.scanner_nmap.varredura_completa,
                'varredura_vulnerabilidades': self.scanner_nmap.varredura_vulnerabilidades,
                'varredura_servicos_web': self.scanner_nmap.varredura_servicos_web,
                'varredura_smb': self.scanner_nmap.varredura_smb,
                'varredura_descoberta_rede': self.scanner_nmap.varredura_descoberta_rede
            }
            
            # Preparar portas para varredura
            portas_str = ','.join(map(str, portas_prioritarias)) if portas_prioritarias else None
            
            # Executar cada módulo recomendado
            for modulo in modulos_recomendados:
                if modulo in mapa_modulos:
                    self.logger.info(f"Executando módulo: {modulo}")
                    
                    resultados_modulo = {}
                    
                    # Executar para cada IP
                    for ip in ips:
                        try:
                            if modulo == 'varredura_descoberta_rede':
                                # Para descoberta de rede, usar notação CIDR
                                rede = f"{'.'.join(ip.split('.')[:-1])}.0/24"
                                resultado = mapa_modulos[modulo](rede)
                            else:
                                # Para outros módulos, usar IP específico
                                if modulo in ['varredura_basica', 'varredura_completa', 'varredura_vulnerabilidades']:
                                    resultado = mapa_modulos[modulo](ip, portas_str)
                                else:
                                    resultado = mapa_modulos[modulo](ip)
                            
                            resultados_modulo[ip] = resultado
                            
                            if resultado.get('sucesso'):
                                self.logger.info(f"Módulo {modulo} executado com sucesso em {ip}")
                            else:
                                self.logger.warning(f"Falha no módulo {modulo} em {ip}: {resultado.get('erro')}")
                                
                        except Exception as e:
                            self.logger.error(f"Erro ao executar {modulo} em {ip}: {str(e)}")
                            resultados_modulo[ip] = {
                                'sucesso': False,
                                'erro': f'Erro na execução: {str(e)}',
                                'timestamp': datetime.now().isoformat()
                            }
                    
                    resultados_nmap['resultados_por_modulo'][modulo] = resultados_modulo
                    resultados_nmap['modulos_executados'].append(modulo)
                    
                else:
                    self.logger.warning(f"Módulo desconhecido: {modulo}")
            
            # Gerar resumo geral
            resultados_nmap['resumo_geral'] = self._gerar_resumo_nmap_avancado(resultados_nmap)
            resultados_nmap['sucesso_geral'] = len(resultados_nmap['modulos_executados']) > 0
            resultados_nmap['timestamp_fim'] = datetime.now().isoformat()
            
            self.logger.info(f"Nmap avançado concluído: {len(resultados_nmap['modulos_executados'])} módulos executados")
            
        except Exception as e:
            self.logger.error(f"Erro na execução do Nmap avançado: {str(e)}")
            resultados_nmap['erro'] = f'Erro na execução: {str(e)}'
            resultados_nmap['timestamp_fim'] = datetime.now().isoformat()
        
        return resultados_nmap
    
    def _gerar_resumo_nmap_avancado(self, resultados_nmap: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera resumo dos resultados do Nmap avançado
        Args:
            resultados_nmap (Dict): Resultados do Nmap avançado
        Returns:
            Dict[str, Any]: Resumo consolidado
        """
        resumo = {
            'modulos_executados': len(resultados_nmap.get('modulos_executados', [])),
            'ips_analisados': len(resultados_nmap.get('ips_analisados', [])),
            'total_vulnerabilidades': 0,
            'total_servicos_detectados': 0,
            'hosts_com_vulnerabilidades': [],
            'servicos_criticos_encontrados': [],
            'resumo_por_modulo': {}
        }
        
        # Analisar resultados por módulo
        for modulo, resultados_modulo in resultados_nmap.get('resultados_por_modulo', {}).items():
            resumo_modulo = {
                'ips_processados': 0,
                'sucessos': 0,
                'falhas': 0,
                'vulnerabilidades_encontradas': 0,
                'servicos_encontrados': 0
            }
            
            for ip, resultado in resultados_modulo.items():
                resumo_modulo['ips_processados'] += 1
                
                if resultado.get('sucesso'):
                    resumo_modulo['sucessos'] += 1
                    
                    # Contar vulnerabilidades e serviços
                    dados = resultado.get('dados', {})
                    resumo_dados = dados.get('resumo', {})
                    
                    vulns = resumo_dados.get('vulnerabilidades', 0)
                    servicos = resumo_dados.get('servicos_detectados', 0)
                    
                    resumo_modulo['vulnerabilidades_encontradas'] += vulns
                    resumo_modulo['servicos_encontrados'] += servicos
                    
                    resumo['total_vulnerabilidades'] += vulns
                    resumo['total_servicos_detectados'] += servicos
                    
                    # Identificar hosts com vulnerabilidades
                    if vulns > 0 and ip not in resumo['hosts_com_vulnerabilidades']:
                        resumo['hosts_com_vulnerabilidades'].append(ip)
                    
                else:
                    resumo_modulo['falhas'] += 1
            
            resumo['resumo_por_modulo'][modulo] = resumo_modulo
        
        return resumo

    
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
    
    # Logging centralizado controlado pelo utils.logger
    
    # Agora importar os módulos
    from modulos.resolucao_dns import ResolucaoDNS
    from modulos.varredura_rustscan import VarreduraRustScan
    from modulos.varredura_nmap import VarreduraNmap
    from modulos.decisao_ia import DecisaoIA
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
        
        orquestrador = OrquestradorPentest(resolver_dns, scanner_portas, scanner_nmap, decisao_ia, obter_logger)
        
        cli_logger.info(f"=== Orquestrador Inteligente - Pentest Inicial ===")
        cli_logger.info(f"Alvo: {args.alvo}")
        cli_logger.info("")
        
        # Executar pentest inicial
        resultados = orquestrador.executar_pentest_inicial(args.alvo)
        
        # Gerar nomes de arquivos com timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        arquivo_json = f"dados/resultado_{timestamp}.json"
        arquivo_html = f"relatorios/relatorio_{timestamp}.html"
        
        # Sempre salvar resultados
        orquestrador.salvar_resultados(resultados, arquivo_json)
        orquestrador.gerar_relatorio_html(resultados, arquivo_html)
        
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
            decisao_ia = resultados.get('decisao_ia', {})
            cli_logger.info(f"\n=== Análise IA ===")
            cli_logger.info(f"  Fonte da decisão: {decisao_ia.get('fonte_decisao', 'N/A')}")
            cli_logger.info(f"  Executar Nmap avançado: {'Sim' if decisao_ia.get('executar_nmap_avancado') else 'Não'}")
            cli_logger.info(f"  Prioridade: {decisao_ia.get('prioridade', 'N/A').title()}")
            cli_logger.info(f"  Justificativa: {decisao_ia.get('justificativa_ia', 'N/A')}")
            
            modulos_recomendados = decisao_ia.get('modulos_recomendados', [])
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
            
            cli_logger.info(f"\n=== Próximos Passos ===")
            if decisao_ia.get('executar_nmap_avancado') and nmap_avancado.get('executado', True):
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
            cli_logger.error(f"✗ Falha no pentest inicial: {resultados.get('erro', 'Erro desconhecido')}")
            return 1
    
    except KeyboardInterrupt:
        cli_logger.error("\n✗ Operação cancelada pelo usuário")
        return 1
    except Exception as e:
        cli_logger.error(f"✗ Erro inesperado: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())