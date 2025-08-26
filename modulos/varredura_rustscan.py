#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de varredura RustScan
Realiza varreduras de portas rápidas usando RustScan
"""

import os
import subprocess
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime

from utils.logger import obter_logger

class VarreduraRustScan:
    """Classe para executar varreduras RustScan"""
    
    def __init__(self):
        """Inicializa o módulo de varredura RustScan"""
        self.logger = obter_logger('VarreduraRustScan')
        self.binario_rustscan = 'rustscan'
        self.binario_nmap = 'nmap'
        self.timeout_padrao = 300
        self.threads_padrao = 500
        self.batch_size_padrao = 4500
        
        # Verificar ferramentas disponíveis
        self.rustscan_disponivel = self.verificar_rustscan()
        self.nmap_disponivel = self.verificar_nmap()
        
        if not self.rustscan_disponivel and not self.nmap_disponivel:
            self.logger.error("Nenhuma ferramenta de scan disponível (rustscan ou nmap)")
        elif not self.rustscan_disponivel:
            self.logger.info("RustScan não disponível, usando nmap como fallback")
    
    def verificar_rustscan(self) -> bool:
        """
        Verifica se o RustScan está instalado e acessível
        Returns:
            bool: True se RustScan está disponível, False caso contrário
        """
        try:
            resultado = subprocess.run(
                [self.binario_rustscan, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                versao = resultado.stdout.strip()
                self.logger.info(f"RustScan encontrado: {versao}")
                return True
            else:
                self.logger.debug("RustScan não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.debug(f"Binário RustScan não encontrado: {self.binario_rustscan}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.debug("Timeout ao verificar versão do RustScan")
            return False
        except Exception as e:
            self.logger.debug(f"Erro ao verificar RustScan: {str(e)}")
            return False
    
    def verificar_nmap(self) -> bool:
        """
        Verifica se o Nmap está instalado e acessível
        Returns:
            bool: True se Nmap está disponível, False caso contrário
        """
        try:
            resultado = subprocess.run(
                [self.binario_nmap, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                versao = resultado.stdout.split('\n')[0]
                self.logger.info(f"Nmap encontrado: {versao}")
                return True
            else:
                self.logger.debug("Nmap não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.debug(f"Binário Nmap não encontrado: {self.binario_nmap}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.debug("Timeout ao verificar versão do Nmap")
            return False
        except Exception as e:
            self.logger.debug(f"Erro ao verificar Nmap: {str(e)}")
            return False
    
    def executar_scan_portas(self, alvo: str) -> Dict[str, Any]:
        """
        Executa scan de portas no alvo (método principal para integração)
        Args:
            alvo (str): Endereço IP para varredura
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        self.logger.info(f"Iniciando scan de portas em {alvo}")
        
        if self.rustscan_disponivel:
            # Usar RustScan se disponível
            resultado = self.varredura_top_ports(alvo, 1000)
        elif self.nmap_disponivel:
            # Usar Nmap como fallback
            resultado = self.varredura_nmap_top_ports(alvo, 1000)
        else:
            return {
                'sucesso': False,
                'erro': 'Nenhuma ferramenta de scan disponível (rustscan ou nmap)',
                'timestamp': datetime.now().isoformat(),
                'dados': {}
            }
        
        if resultado.get('sucesso'):
            self.logger.info(f"Scan de portas concluído para {alvo}")
        else:
            self.logger.error(f"Falha no scan de portas: {resultado.get('erro')}")
        
        return resultado
    
    def varredura_top_ports(self, alvo: str, top: int = 1000) -> Dict[str, Any]:
        """
        Executa varredura das portas mais comuns
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            top (int): Número de portas mais comuns para varrer
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_rustscan,
            '-a', alvo,
            '--accessible',
            '-t', str(self.threads_padrao),
            '-b', str(self.batch_size_padrao),
            '--top-ports', str(top)
        ]
        
        return self._executar_varredura(comando, "varredura_top_ports")
    
    def varredura_rapida(self, alvo: str, portas: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura rápida de portas no alvo
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            portas (str): Especificação de portas (ex: '1-1000', '80,443,22')
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_rustscan,
            '-a', alvo,
            '--accessible',
            '-t', str(self.threads_padrao),
            '-b', str(self.batch_size_padrao)
        ]
        
        if portas:
            comando.extend(['-p', portas])
        
        return self._executar_varredura(comando, "varredura_rapida")
    
    def varredura_completa(self, alvo: str) -> Dict[str, Any]:
        """
        Executa varredura completa de todas as portas
        Args:
            alvo (str): Endereço IP ou hostname do alvo
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_rustscan,
            '-a', alvo,
            '--accessible',
            '-t', str(self.threads_padrao),
            '-b', str(self.batch_size_padrao),
            '-p', '1-65535'
        ]
        
        return self._executar_varredura(comando, "varredura_completa")
    
    def varredura_nmap_top_ports(self, alvo: str, top: int = 1000) -> Dict[str, Any]:
        """
        Executa varredura das portas mais comuns usando Nmap
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            top (int): Número de portas mais comuns para varrer
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nmap,
            '-sT',  # TCP connect scan (não precisa root)
            '--top-ports', str(top),
            '-T4',  # Timing agressivo
            '--open',  # Apenas portas abertas
            alvo
        ]
        
        return self._executar_varredura_nmap(comando, "varredura_nmap_top_ports")
    
    def varredura_nmap_rapida(self, alvo: str, portas: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura rápida usando Nmap
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            portas (str): Especificação de portas (ex: '1-1000', '80,443,22')
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nmap,
            '-sT',  # TCP connect scan (não precisa root)
            '-T4',  # Timing agressivo
            '--open',  # Apenas portas abertas
        ]
        
        if portas:
            comando.extend(['-p', portas])
        else:
            comando.extend(['--top-ports', '1000'])
        
        comando.append(alvo)
        
        return self._executar_varredura_nmap(comando, "varredura_nmap_rapida")
    
    def _executar_varredura(self, comando: List[str], tipo_varredura: str) -> Dict[str, Any]:
        """
        Executa comando RustScan e processa resultados
        Args:
            comando (List[str]): Comando completo do RustScan
            tipo_varredura (str): Tipo da varredura para logging
        Returns:
            Dict[str, Any]: Resultados processados da varredura
        """
        resultado = {
            'sucesso': False,
            'tipo_varredura': tipo_varredura,
            'comando': ' '.join(comando),
            'timestamp': datetime.now().isoformat(),
            'dados': {},
            'erro': None
        }
        
        try:
            self.logger.info(f"Executando {tipo_varredura}: {' '.join(comando)}")
            
            # Executar comando RustScan
            processo = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=self.timeout_padrao
            )
            
            resultado['codigo_saida'] = processo.returncode
            resultado['saida_padrao'] = processo.stdout
            resultado['saida_erro'] = processo.stderr
            
            if processo.returncode == 0:
                # Processar saída do RustScan
                resultado['dados'] = self._processar_saida_rustscan(processo.stdout)
                resultado['sucesso'] = True
                self.logger.info(f"{tipo_varredura} concluída com sucesso")
            else:
                resultado['erro'] = f"RustScan retornou código {processo.returncode}: {processo.stderr}"
                self.logger.error(resultado['erro'])
            
        except subprocess.TimeoutExpired:
            resultado['erro'] = f"Timeout na execução da varredura ({self.timeout_padrao}s)"
            self.logger.error(resultado['erro'])
        except Exception as e:
            resultado['erro'] = f"Erro na execução: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def _executar_varredura_nmap(self, comando: List[str], tipo_varredura: str) -> Dict[str, Any]:
        """
        Executa comando Nmap e processa resultados
        Args:
            comando (List[str]): Comando completo do Nmap
            tipo_varredura (str): Tipo da varredura para logging
        Returns:
            Dict[str, Any]: Resultados processados da varredura
        """
        resultado = {
            'sucesso': False,
            'tipo_varredura': tipo_varredura,
            'comando': ' '.join(comando),
            'timestamp': datetime.now().isoformat(),
            'dados': {},
            'erro': None
        }
        
        try:
            self.logger.info(f"Executando {tipo_varredura}: {' '.join(comando)}")
            
            # Executar comando Nmap
            processo = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=self.timeout_padrao
            )
            
            resultado['codigo_saida'] = processo.returncode
            resultado['saida_padrao'] = processo.stdout
            resultado['saida_erro'] = processo.stderr
            
            if processo.returncode == 0:
                # Processar saída do Nmap
                resultado['dados'] = self._processar_saida_nmap(processo.stdout)
                resultado['sucesso'] = True
                self.logger.info(f"{tipo_varredura} concluída com sucesso")
            else:
                resultado['erro'] = f"Nmap retornou código {processo.returncode}: {processo.stderr}"
                self.logger.error(resultado['erro'])
            
        except subprocess.TimeoutExpired:
            resultado['erro'] = f"Timeout na execução da varredura ({self.timeout_padrao}s)"
            self.logger.error(resultado['erro'])
        except Exception as e:
            resultado['erro'] = f"Erro na execução: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def _processar_saida_rustscan(self, saida: str) -> Dict[str, Any]:
        """
        Processa saída do RustScan
        Args:
            saida (str): Saída do comando RustScan
        Returns:
            Dict[str, Any]: Dados estruturados da varredura
        """
        dados = {
            'hosts': [],
            'resumo': {
                'hosts_total': 0,
                'hosts_ativos': 0,
                'portas_abertas': 0,
                'tempo_execucao': ''
            }
        }
        
        try:
            linhas = saida.split('\n')
            host_atual = None
            portas_encontradas = []
            
            for linha in linhas:
                linha = linha.strip()
                
                # Detectar portas abertas - formato RustScan
                if 'Open' in linha and ':' in linha:
                    # Formato: "Open 192.168.1.1:80"
                    partes = linha.split()
                    if len(partes) >= 2:
                        endereco_porta = partes[1]
                        if ':' in endereco_porta:
                            endereco, porta = endereco_porta.split(':')
                            
                            if host_atual != endereco:
                                # Salvar host anterior se existir
                                if host_atual and portas_encontradas:
                                    dados['hosts'].append({
                                        'endereco': host_atual,
                                        'status': 'up',
                                        'portas': portas_encontradas.copy()
                                    })
                                
                                # Iniciar novo host
                                host_atual = endereco
                                portas_encontradas = []
                            
                            # Adicionar porta
                            try:
                                portas_encontradas.append({
                                    'numero': int(porta),
                                    'protocolo': 'tcp',
                                    'estado': 'open'
                                })
                            except ValueError:
                                self.logger.warning(f"Porta inválida encontrada: {porta}")
                
                # Detectar tempo de execução
                elif 'finished' in linha.lower() or 'completed' in linha.lower():
                    if 'in' in linha:
                        tempo_match = linha.split('in')[-1].strip()
                        dados['resumo']['tempo_execucao'] = tempo_match
            
            # Adicionar último host se existir
            if host_atual and portas_encontradas:
                dados['hosts'].append({
                    'endereco': host_atual,
                    'status': 'up',
                    'portas': portas_encontradas
                })
            
            # Calcular resumo
            dados['resumo']['hosts_total'] = len(dados['hosts'])
            dados['resumo']['hosts_ativos'] = len([h for h in dados['hosts'] if h['status'] == 'up'])
            dados['resumo']['portas_abertas'] = sum(len(h['portas']) for h in dados['hosts'])
            
        except Exception as e:
            self.logger.error(f"Erro ao processar saída RustScan: {str(e)}")
        
        return dados
    
    def _processar_saida_nmap(self, saida: str) -> Dict[str, Any]:
        """
        Processa saída do Nmap
        Args:
            saida (str): Saída do comando Nmap
        Returns:
            Dict[str, Any]: Dados estruturados da varredura
        """
        dados = {
            'hosts': [],
            'resumo': {
                'hosts_total': 0,
                'hosts_ativos': 0,
                'portas_abertas': 0,
                'tempo_execucao': ''
            }
        }
        
        try:
            linhas = saida.split('\n')
            host_atual = None
            portas_encontradas = []
            
            for linha in linhas:
                linha = linha.strip()
                
                # Detectar início de host
                if 'Nmap scan report for' in linha:
                    # Salvar host anterior se existir
                    if host_atual and portas_encontradas:
                        dados['hosts'].append({
                            'endereco': host_atual,
                            'status': 'up',
                            'portas': portas_encontradas.copy()
                        })
                    
                    # Extrair endereço do host
                    partes = linha.split()
                    if len(partes) >= 5:
                        host_atual = partes[4]
                    else:
                        host_atual = partes[-1]
                    
                    # Limpar parênteses se existir
                    if '(' in host_atual and ')' in host_atual:
                        host_atual = host_atual.split('(')[1].split(')')[0]
                    
                    portas_encontradas = []
                
                # Detectar portas abertas
                elif '/tcp' in linha and 'open' in linha:
                    partes = linha.split()
                    if len(partes) >= 3:
                        porta_info = partes[0]
                        if '/' in porta_info:
                            porta = porta_info.split('/')[0]
                            try:
                                portas_encontradas.append({
                                    'numero': int(porta),
                                    'protocolo': 'tcp',
                                    'estado': 'open',
                                    'servico': partes[2] if len(partes) > 2 else 'unknown'
                                })
                            except ValueError:
                                self.logger.warning(f"Porta inválida encontrada: {porta}")
                
                elif '/udp' in linha and 'open' in linha:
                    partes = linha.split()
                    if len(partes) >= 3:
                        porta_info = partes[0]
                        if '/' in porta_info:
                            porta = porta_info.split('/')[0]
                            try:
                                portas_encontradas.append({
                                    'numero': int(porta),
                                    'protocolo': 'udp',
                                    'estado': 'open',
                                    'servico': partes[2] if len(partes) > 2 else 'unknown'
                                })
                            except ValueError:
                                self.logger.warning(f"Porta inválida encontrada: {porta}")
                
                # Detectar tempo de execução
                elif 'Nmap done' in linha:
                    if 'in' in linha:
                        tempo_match = linha.split('in')[-1].strip()
                        dados['resumo']['tempo_execucao'] = tempo_match
            
            # Adicionar último host se existir
            if host_atual and portas_encontradas:
                dados['hosts'].append({
                    'endereco': host_atual,
                    'status': 'up',
                    'portas': portas_encontradas
                })
            
            # Calcular resumo
            dados['resumo']['hosts_total'] = len(dados['hosts'])
            dados['resumo']['hosts_ativos'] = len([h for h in dados['hosts'] if h['status'] == 'up'])
            dados['resumo']['portas_abertas'] = sum(len(h['portas']) for h in dados['hosts'])
            
        except Exception as e:
            self.logger.error(f"Erro ao processar saída Nmap: {str(e)}")
        
        return dados
    
    def gerar_resumo(self, resultados: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera resumo dos resultados de varredura
        Args:
            resultados (Dict): Resultado da varredura
        Returns:
            Dict[str, Any]: Resumo formatado
        """
        if not resultados.get('sucesso'):
            return {
                'status': 'falha',
                'erro': resultados.get('erro', 'Erro desconhecido'),
                'timestamp': resultados.get('timestamp')
            }
        
        dados = resultados.get('dados', {})
        resumo_dados = dados.get('resumo', {})
        
        resumo = {
            'status': 'sucesso',
            'timestamp': resultados.get('timestamp'),
            'tipo_varredura': resultados.get('tipo_varredura'),
            'hosts_total': resumo_dados.get('hosts_total', 0),
            'hosts_ativos': resumo_dados.get('hosts_ativos', 0),
            'portas_abertas': resumo_dados.get('portas_abertas', 0),
            'tempo_execucao': resumo_dados.get('tempo_execucao', 'N/A')
        }
        
        # Adicionar detalhes dos hosts
        hosts_detalhes = []
        for host in dados.get('hosts', []):
            host_info = {
                'endereco': host.get('endereco'),
                'status': host.get('status'),
                'total_portas': len(host.get('portas', [])),
                'portas_abertas': [p['numero'] for p in host.get('portas', []) if p.get('estado') == 'open']
            }
            hosts_detalhes.append(host_info)
        
        resumo['hosts_detalhes'] = hosts_detalhes
        
        return resumo


if __name__ == "__main__":
    # Teste do módulo
    logger = obter_logger('VarreduraRustScanCLI')
    varredura = VarreduraRustScan()
    
    if varredura.verificar_rustscan():
        logger.info("RustScan está disponível!")
        
        # Exemplo de varredura
        alvo = input("\nDigite o IP para varredura: ").strip()
        if alvo:
            logger.info(f"Executando scan de portas em {alvo}...")
            resultado = varredura.executar_scan_portas(alvo)
            
            if resultado['sucesso']:
                resumo = varredura.gerar_resumo(resultado)
                logger.info(f"\nResultados:")
                logger.info(f"  Hosts ativos: {resumo['hosts_ativos']}")
                logger.info(f"  Portas abertas: {resumo['portas_abertas']}")
                
                for host in resumo['hosts_detalhes']:
                    if host['portas_abertas']:
                        logger.info(f"  {host['endereco']}: {', '.join(map(str, host['portas_abertas']))}")
            else:
                logger.error(f"Erro na varredura: {resultado['erro']}")
    else:
        logger.error("RustScan não está disponível. Instale o RustScan para continuar.")