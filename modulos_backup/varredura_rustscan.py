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
import tempfile

from utils.logger import obter_logger

class VarreduraRustScan:
    """Classe para executar varreduras RustScan"""
    
    def __init__(self):
        """Inicializa o módulo de varredura RustScan"""
        self.logger = obter_logger('VarreduraRustScan')
        self.binario_rustscan = 'rustscan'
        self.timeout_padrao = 300
        self.threads_padrao = 500
        self.batch_size_padrao = 4500
        
        # Verificar se o RustScan está disponível
        self.verificar_rustscan()
    
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
                self.logger.error("RustScan não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.error(f"Binário RustScan não encontrado: {self.binario_rustscan}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout ao verificar versão do RustScan")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar RustScan: {str(e)}")
            return False
    
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
    
    def varredura_com_nmap(self, alvo: str, portas: Optional[str] = None, 
                          scripts_nmap: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Executa varredura RustScan seguida de Nmap para detalhamento
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            portas (str): Especificação de portas
            scripts_nmap (List[str]): Scripts Nmap para executar
        Returns:
            Dict[str, Any]: Resultados da varredura combinada
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
        
        # Adicionar comando Nmap
        nmap_cmd = ['nmap', '-sV', '-sC']
        if scripts_nmap:
            nmap_cmd.extend(['--script', ','.join(scripts_nmap)])
        
        comando.extend(['--', ' '.join(nmap_cmd)])
        
        return self._executar_varredura(comando, "varredura_com_nmap")
    
    def varredura_stealth(self, alvo: str, portas: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura stealth com configurações mais discretas
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            portas (str): Especificação de portas
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_rustscan,
            '-a', alvo,
            '--accessible',
            '-t', '100',  # Menos threads para ser mais discreto
            '-b', '1000',  # Batch size menor
            '--timeout', '3000'  # Timeout maior
        ]
        
        if portas:
            comando.extend(['-p', portas])
        else:
            comando.extend(['-p', '1-1000'])  # Apenas portas comuns
        
        return self._executar_varredura(comando, "varredura_stealth")
    
    def varredura_personalizada(self, alvo: str, opcoes: List[str]) -> Dict[str, Any]:
        """
        Executa varredura personalizada com opções específicas
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            opcoes (List[str]): Lista de opções do RustScan
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [self.binario_rustscan, '-a', alvo] + opcoes
        
        return self._executar_varredura(comando, "varredura_personalizada")
    
    def varredura_multiplos_alvos(self, alvos: List[str], portas: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura em múltiplos alvos
        Args:
            alvos (List[str]): Lista de endereços IP ou hostnames
            portas (str): Especificação de portas
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_rustscan,
            '--accessible',
            '-t', str(self.threads_padrao),
            '-b', str(self.batch_size_padrao)
        ]
        
        # Adicionar alvos
        for alvo in alvos:
            comando.extend(['-a', alvo])
        
        if portas:
            comando.extend(['-p', portas])
        
        return self._executar_varredura(comando, "varredura_multiplos_alvos")
    
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
                
                # Detectar início de host
                if 'Open' in linha and '->' in linha:
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
                            portas_encontradas.append({
                                'numero': int(porta),
                                'protocolo': 'tcp',
                                'estado': 'open'
                            })
                
                # Detectar tempo de execução
                elif 'Nmap done' in linha or 'finished' in linha.lower():
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
    
    def gerar_relatorio_resumido(self, resultados: Dict[str, Any]) -> str:
        """
        Gera relatório resumido da varredura
        Args:
            resultados (Dict[str, Any]): Resultados da varredura
        Returns:
            str: Relatório em formato texto
        """
        if not resultados.get('sucesso'):
            return f"Erro na varredura: {resultados.get('erro', 'Erro desconhecido')}"
        
        dados = resultados.get('dados', {})
        resumo = dados.get('resumo', {})
        
        relatorio = []
        relatorio.append("=" * 60)
        relatorio.append(f"RELATÓRIO RUSTSCAN - {resultados['tipo_varredura'].upper()}")
        relatorio.append("=" * 60)
        relatorio.append(f"Timestamp: {resultados['timestamp']}")
        relatorio.append(f"Comando: {resultados['comando']}")
        relatorio.append("")
        
        # Resumo
        relatorio.append("RESUMO:")
        relatorio.append(f"  Hosts Total: {resumo.get('hosts_total', 0)}")
        relatorio.append(f"  Hosts Ativos: {resumo.get('hosts_ativos', 0)}")
        relatorio.append(f"  Portas Abertas: {resumo.get('portas_abertas', 0)}")
        if resumo.get('tempo_execucao'):
            relatorio.append(f"  Tempo de Execução: {resumo['tempo_execucao']}")
        relatorio.append("")
        
        # Detalhes dos hosts
        for host in dados.get('hosts', []):
            relatorio.append(f"HOST: {host.get('endereco', 'N/A')}")
            relatorio.append(f"  Status: {host.get('status', 'N/A')}")
            
            # Portas abertas
            portas_abertas = [p for p in host.get('portas', []) if p.get('estado') == 'open']
            if portas_abertas:
                relatorio.append(f"  Portas Abertas ({len(portas_abertas)}):")
                portas_str = ', '.join([f"{p['numero']}/{p['protocolo']}" for p in portas_abertas])
                relatorio.append(f"    {portas_str}")
            
            relatorio.append("")
        
        return "\n".join(relatorio)
    
    def obter_configuracoes_otimizadas(self, tipo_rede: str = 'local') -> Dict[str, Any]:
        """
        Retorna configurações otimizadas para diferentes tipos de rede
        Args:
            tipo_rede (str): Tipo de rede ('local', 'wan', 'stealth')
        Returns:
            Dict[str, Any]: Configurações otimizadas
        """
        configuracoes = {
            'local': {
                'threads': 1000,
                'batch_size': 5000,
                'timeout': 1500,
                'descricao': 'Configuração para redes locais - máxima velocidade'
            },
            'wan': {
                'threads': 500,
                'batch_size': 4500,
                'timeout': 3000,
                'descricao': 'Configuração para redes WAN - balanceada'
            },
            'stealth': {
                'threads': 100,
                'batch_size': 1000,
                'timeout': 5000,
                'descricao': 'Configuração stealth - mais discreta'
            }
        }
        
        return configuracoes.get(tipo_rede, configuracoes['wan'])


if __name__ == "__main__":
    # Teste do módulo
    varredura = VarreduraRustScan()
    
    if varredura.verificar_rustscan():
        print("RustScan está disponível!")
        
        # Mostrar configurações otimizadas
        print("\nConfigurações disponíveis:")
        for tipo in ['local', 'wan', 'stealth']:
            config = varredura.obter_configuracoes_otimizadas(tipo)
            print(f"  {tipo.upper()}: {config['descricao']}")
        
        # Exemplo de varredura
        alvo = input("\nDigite o IP ou hostname para varredura: ").strip()
        if alvo:
            print(f"Executando varredura rápida em {alvo}...")
            resultado = varredura.varredura_rapida(alvo, "1-1000")
            
            if resultado['sucesso']:
                print("\nRelatório da Varredura:")
                print(varredura.gerar_relatorio_resumido(resultado))
            else:
                print(f"Erro na varredura: {resultado['erro']}")
    else:
        print("RustScan não está disponível. Instale o RustScan para continuar.")
        print("Instalação: https://github.com/RustScan/RustScan")