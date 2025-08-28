#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de varredura Sublist3r
Enumera subdomínios usando Sublist3r
"""

import os
import subprocess
import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
import tempfile

from core.configuracao import obter_config
from utils.logger import obter_logger

class VarreduraSublist3r:
    """Classe para executar varreduras Sublist3r"""
    
    def __init__(self):
        """Inicializa o módulo de varredura Sublist3r"""
        self.logger = logging.getLogger(__name__)
        self.binario_sublist3r = obter_config('sublist3r.binario', 'sublist3r')
        self.timeout_padrao = obter_config('sublist3r.timeout_padrao', 600)
        self.threads_padrao = obter_config('sublist3r.threads_padrao', 40)
        self.opcoes_padrao = obter_config('sublist3r.opcoes_padrao', [])
        
        # Verificar se o Sublist3r está disponível
        self.verificar_sublist3r()
    
    def verificar_sublist3r(self) -> bool:
        """
        Verifica se o Sublist3r está instalado e acessível
        Returns:
            bool: True se Sublist3r está disponível, False caso contrário
        """
        try:
            resultado = subprocess.run(
                [self.binario_sublist3r, '-h'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                self.logger.info("Sublist3r encontrado")
                return True
            else:
                self.logger.error("Sublist3r não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.error(f"Binário Sublist3r não encontrado: {self.binario_sublist3r}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout ao verificar Sublist3r")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar Sublist3r: {str(e)}")
            return False
    
    def enumerar_subdominios(self, dominio: str, bruteforce: bool = False) -> Dict[str, Any]:
        """
        Enumera subdomínios do domínio alvo
        Args:
            dominio (str): Domínio alvo
            bruteforce (bool): Usar bruteforce
        Returns:
            Dict[str, Any]: Resultados da enumeração
        """
        # Criar arquivo temporário para saída
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
            arquivo_saida = temp_file.name
        
        comando = [
            self.binario_sublist3r,
            '-d', dominio,
            '-t', str(self.threads_padrao),
            '-o', arquivo_saida
        ]
        
        if bruteforce:
            comando.append('-b')
        
        try:
            resultado = self._executar_varredura(comando, "enumerar_subdominios", arquivo_saida)
        finally:
            # Limpar arquivo temporário
            try:
                os.unlink(arquivo_saida)
            except:
                pass
        
        return resultado
    
    def enumerar_com_engines(self, dominio: str, engines: List[str]) -> Dict[str, Any]:
        """
        Enumera subdomínios usando engines específicos
        Args:
            dominio (str): Domínio alvo
            engines (List[str]): Lista de engines para usar
        Returns:
            Dict[str, Any]: Resultados da enumeração
        """
        # Criar arquivo temporário para saída
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
            arquivo_saida = temp_file.name
        
        comando = [
            self.binario_sublist3r,
            '-d', dominio,
            '-t', str(self.threads_padrao),
            '-o', arquivo_saida,
            '-e', ','.join(engines)
        ]
        
        try:
            resultado = self._executar_varredura(comando, "enumerar_com_engines", arquivo_saida)
        finally:
            # Limpar arquivo temporário
            try:
                os.unlink(arquivo_saida)
            except:
                pass
        
        return resultado
    
    def enumerar_com_wordlist(self, dominio: str, wordlist: str) -> Dict[str, Any]:
        """
        Enumera subdomínios usando wordlist personalizada
        Args:
            dominio (str): Domínio alvo
            wordlist (str): Caminho para wordlist
        Returns:
            Dict[str, Any]: Resultados da enumeração
        """
        if not os.path.exists(wordlist):
            return {
                'sucesso': False,
                'erro': f'Wordlist não encontrada: {wordlist}',
                'timestamp': datetime.now().isoformat()
            }
        
        # Criar arquivo temporário para saída
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
            arquivo_saida = temp_file.name
        
        comando = [
            self.binario_sublist3r,
            '-d', dominio,
            '-t', str(self.threads_padrao),
            '-o', arquivo_saida,
            '-b',
            '-w', wordlist
        ]
        
        try:
            resultado = self._executar_varredura(comando, "enumerar_com_wordlist", arquivo_saida)
        finally:
            # Limpar arquivo temporário
            try:
                os.unlink(arquivo_saida)
            except:
                pass
        
        return resultado
    
    def enumerar_silencioso(self, dominio: str) -> Dict[str, Any]:
        """
        Enumera subdomínios em modo silencioso
        Args:
            dominio (str): Domínio alvo
        Returns:
            Dict[str, Any]: Resultados da enumeração
        """
        # Criar arquivo temporário para saída
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
            arquivo_saida = temp_file.name
        
        comando = [
            self.binario_sublist3r,
            '-d', dominio,
            '-t', str(self.threads_padrao),
            '-o', arquivo_saida,
            '-v'  # Verbose para capturar mais informações
        ]
        
        try:
            resultado = self._executar_varredura(comando, "enumerar_silencioso", arquivo_saida)
        finally:
            # Limpar arquivo temporário
            try:
                os.unlink(arquivo_saida)
            except:
                pass
        
        return resultado
    
    def _executar_varredura(self, comando: List[str], tipo_varredura: str, arquivo_saida: str) -> Dict[str, Any]:
        """
        Executa comando Sublist3r e processa resultados
        Args:
            comando (List[str]): Comando completo do Sublist3r
            tipo_varredura (str): Tipo da varredura para logging
            arquivo_saida (str): Arquivo de saída dos subdomínios
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
            
            processo = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=self.timeout_padrao
            )
            
            resultado['codigo_saida'] = processo.returncode
            resultado['saida_padrao'] = processo.stdout
            resultado['saida_erro'] = processo.stderr
            
            # Sublist3r pode retornar código != 0 mas ainda ter sucesso
            if os.path.exists(arquivo_saida):
                resultado['dados'] = self._processar_saida_sublist3r(arquivo_saida, processo.stdout)
                resultado['sucesso'] = True
                self.logger.info(f"{tipo_varredura} concluída com sucesso")
            else:
                resultado['erro'] = f"Arquivo de saída não encontrado: {processo.stderr}"
                self.logger.error(resultado['erro'])
            
        except subprocess.TimeoutExpired:
            resultado['erro'] = f"Timeout na execução da varredura ({self.timeout_padrao}s)"
            self.logger.error(resultado['erro'])
        except Exception as e:
            resultado['erro'] = f"Erro na execução: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def _processar_saida_sublist3r(self, arquivo_saida: str, saida_stdout: str) -> Dict[str, Any]:
        """
        Processa saída do Sublist3r
        Args:
            arquivo_saida (str): Arquivo com subdomínios encontrados
            saida_stdout (str): Saída padrão do comando
        Returns:
            Dict[str, Any]: Dados estruturados da varredura
        """
        dados = {
            'subdominios': [],
            'resumo': {
                'total_subdominios': 0,
                'engines_utilizados': [],
                'tempo_execucao': '',
                'bruteforce_usado': False
            }
        }
        
        try:
            # Ler subdomínios do arquivo
            if os.path.exists(arquivo_saida):
                with open(arquivo_saida, 'r') as f:
                    for linha in f:
                        subdominio = linha.strip()
                        if subdominio and subdominio not in dados['subdominios']:
                            dados['subdominios'].append(subdominio)
            
            # Processar informações da saída padrão
            linhas_stdout = saida_stdout.split('\n')
            for linha in linhas_stdout:
                linha = linha.strip()
                
                # Detectar engines utilizados
                if 'Searching now in' in linha:
                    engine = linha.split('Searching now in')[-1].strip()
                    if engine not in dados['resumo']['engines_utilizados']:
                        dados['resumo']['engines_utilizados'].append(engine)
                
                # Detectar uso de bruteforce
                elif 'Starting bruteforce' in linha:
                    dados['resumo']['bruteforce_usado'] = True
                
                # Detectar tempo de execução
                elif 'Total time:' in linha:
                    dados['resumo']['tempo_execucao'] = linha.split('Total time:')[-1].strip()
            
            dados['resumo']['total_subdominios'] = len(dados['subdominios'])
            
        except Exception as e:
            self.logger.error(f"Erro ao processar saída Sublist3r: {str(e)}")
        
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
        relatorio.append(f"RELATÓRIO SUBLIST3R - {resultados['tipo_varredura'].upper()}")
        relatorio.append("=" * 60)
        relatorio.append(f"Timestamp: {resultados['timestamp']}")
        relatorio.append(f"Comando: {resultados['comando']}")
        relatorio.append("")
        
        # Resumo
        relatorio.append("RESUMO:")
        relatorio.append(f"  Subdomínios Encontrados: {resumo.get('total_subdominios', 0)}")
        relatorio.append(f"  Bruteforce Usado: {'Sim' if resumo.get('bruteforce_usado') else 'Não'}")
        
        if resumo.get('tempo_execucao'):
            relatorio.append(f"  Tempo de Execução: {resumo['tempo_execucao']}")
        
        if resumo.get('engines_utilizados'):
            relatorio.append(f"  Engines Utilizados: {', '.join(resumo['engines_utilizados'])}")
        
        relatorio.append("")
        
        # Lista de subdomínios
        subdominios = dados.get('subdominios', [])
        if subdominios:
            relatorio.append("SUBDOMÍNIOS ENCONTRADOS:")
            for subdominio in subdominios[:20]:  # Máximo 20
                relatorio.append(f"  • {subdominio}")
            
            if len(subdominios) > 20:
                relatorio.append(f"  ... e mais {len(subdominios) - 20} subdomínios")
        
        return "\n".join(relatorio)
    
    def obter_engines_disponiveis(self) -> List[str]:
        """
        Retorna lista de engines disponíveis
        Returns:
            List[str]: Lista de engines
        """
        return [
            'baidu', 'yahoo', 'google', 'bing', 'ask', 'netcraft',
            'virustotal', 'threatcrowd', 'ssl', 'passivedns'
        ]


if __name__ == "__main__":
    # Teste do módulo
    logger = obter_logger('VarreduraSublist3rCLI')
    varredura = VarreduraSublist3r()
    
    if varredura.verificar_sublist3r():
        logger.info("Sublist3r está disponível!")
        
        logger.info("Engines disponíveis: " + ', '.join(varredura.obter_engines_disponiveis()))
        
        dominio = input("Digite o domínio para enumeração: ").strip()
        if dominio:
            logger.info(f"Enumerando subdomínios de {dominio}...")
            resultado = varredura.enumerar_subdominios(dominio)
            
            if resultado['sucesso']:
                logger.info("\nRelatório da Enumeração:")
                logger.info(varredura.gerar_relatorio_resumido(resultado))
            else:
                logger.error(f"Erro na enumeração: {resultado['erro']}")
    else:
        logger.error("Sublist3r não está disponível. Instale o Sublist3r para continuar.")