#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de varredura Feroxbuster
Realiza descoberta de diretórios e arquivos web usando Feroxbuster
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

class VarreduraFeroxbuster:
    """Classe para executar varreduras Feroxbuster"""
    
    def __init__(self):
        """Inicializa o módulo de varredura Feroxbuster"""
        self.logger = logging.getLogger(__name__)
        self.binario_feroxbuster = obter_config('feroxbuster.binario', 'feroxbuster')
        self.timeout_padrao = obter_config('feroxbuster.timeout_padrao', 1800)
        self.threads_padrao = obter_config('feroxbuster.threads_padrao', 50)
        self.wordlist_padrao = obter_config('feroxbuster.wordlist_padrao', '/usr/share/wordlists/dirb/common.txt')
        self.opcoes_padrao = obter_config('feroxbuster.opcoes_padrao', ['--silent'])
        
        # Verificar se o Feroxbuster está disponível
        self.verificar_feroxbuster()
    
    def verificar_feroxbuster(self) -> bool:
        """
        Verifica se o Feroxbuster está instalado e acessível
        Returns:
            bool: True se Feroxbuster está disponível, False caso contrário
        """
        try:
            resultado = subprocess.run(
                [self.binario_feroxbuster, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                versao = resultado.stdout.strip()
                self.logger.info(f"Feroxbuster encontrado: {versao}")
                return True
            else:
                self.logger.error("Feroxbuster não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.error(f"Binário Feroxbuster não encontrado: {self.binario_feroxbuster}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout ao verificar versão do Feroxbuster")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar Feroxbuster: {str(e)}")
            return False
    
    def varredura_basica(self, alvo: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura básica de diretórios
        Args:
            alvo (str): URL do alvo
            wordlist (str): Caminho para wordlist personalizada
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_feroxbuster,
            '-u', alvo,
            '-t', str(self.threads_padrao),
            '--json',
            '--silent'
        ]
        
        if wordlist and os.path.exists(wordlist):
            comando.extend(['-w', wordlist])
        elif os.path.exists(self.wordlist_padrao):
            comando.extend(['-w', self.wordlist_padrao])
        
        return self._executar_varredura(comando, "varredura_basica")
    
    def varredura_recursiva(self, alvo: str, profundidade: int = 4, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura recursiva de diretórios
        Args:
            alvo (str): URL do alvo
            profundidade (int): Profundidade da recursão
            wordlist (str): Caminho para wordlist personalizada
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_feroxbuster,
            '-u', alvo,
            '-t', str(self.threads_padrao),
            '--json',
            '--silent',
            '-d', str(profundidade)
        ]
        
        if wordlist and os.path.exists(wordlist):
            comando.extend(['-w', wordlist])
        elif os.path.exists(self.wordlist_padrao):
            comando.extend(['-w', self.wordlist_padrao])
        
        return self._executar_varredura(comando, "varredura_recursiva")
    
    def varredura_extensoes(self, alvo: str, extensoes: List[str], wordlist: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura com extensões específicas
        Args:
            alvo (str): URL do alvo
            extensoes (List[str]): Lista de extensões (ex: ['php', 'html', 'txt'])
            wordlist (str): Caminho para wordlist personalizada
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_feroxbuster,
            '-u', alvo,
            '-t', str(self.threads_padrao),
            '--json',
            '--silent',
            '-x', ','.join(extensoes)
        ]
        
        if wordlist and os.path.exists(wordlist):
            comando.extend(['-w', wordlist])
        elif os.path.exists(self.wordlist_padrao):
            comando.extend(['-w', self.wordlist_padrao])
        
        return self._executar_varredura(comando, "varredura_extensoes")
    
    def varredura_stealth(self, alvo: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura stealth com configurações discretas
        Args:
            alvo (str): URL do alvo
            wordlist (str): Caminho para wordlist personalizada
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_feroxbuster,
            '-u', alvo,
            '-t', '10',  # Menos threads
            '--json',
            '--silent',
            '--rate-limit', '10',  # Rate limiting
            '--random-agent'
        ]
        
        if wordlist and os.path.exists(wordlist):
            comando.extend(['-w', wordlist])
        elif os.path.exists(self.wordlist_padrao):
            comando.extend(['-w', self.wordlist_padrao])
        
        return self._executar_varredura(comando, "varredura_stealth")
    
    def varredura_personalizada(self, alvo: str, opcoes: List[str]) -> Dict[str, Any]:
        """
        Executa varredura personalizada com opções específicas
        Args:
            alvo (str): URL do alvo
            opcoes (List[str]): Lista de opções do Feroxbuster
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [self.binario_feroxbuster, '-u', alvo, '--json', '--silent'] + opcoes
        
        return self._executar_varredura(comando, "varredura_personalizada")
    
    def _executar_varredura(self, comando: List[str], tipo_varredura: str) -> Dict[str, Any]:
        """
        Executa comando Feroxbuster e processa resultados
        Args:
            comando (List[str]): Comando completo do Feroxbuster
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
            
            processo = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=self.timeout_padrao
            )
            
            resultado['codigo_saida'] = processo.returncode
            resultado['saida_padrao'] = processo.stdout
            resultado['saida_erro'] = processo.stderr
            
            if processo.returncode == 0 or processo.stdout:
                resultado['dados'] = self._processar_saida_feroxbuster(processo.stdout)
                resultado['sucesso'] = True
                self.logger.info(f"{tipo_varredura} concluída com sucesso")
            else:
                resultado['erro'] = f"Feroxbuster retornou código {processo.returncode}: {processo.stderr}"
                self.logger.error(resultado['erro'])
            
        except subprocess.TimeoutExpired:
            resultado['erro'] = f"Timeout na execução da varredura ({self.timeout_padrao}s)"
            self.logger.error(resultado['erro'])
        except Exception as e:
            resultado['erro'] = f"Erro na execução: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def _processar_saida_feroxbuster(self, saida: str) -> Dict[str, Any]:
        """
        Processa saída JSON do Feroxbuster
        Args:
            saida (str): Saída JSON do comando Feroxbuster
        Returns:
            Dict[str, Any]: Dados estruturados da varredura
        """
        dados = {
            'diretorios_encontrados': [],
            'arquivos_encontrados': [],
            'resumo': {
                'total_diretorios': 0,
                'total_arquivos': 0,
                'codigos_status': {},
                'tamanhos_interessantes': []
            }
        }
        
        try:
            linhas = saida.strip().split('\n')
            
            for linha in linhas:
                linha = linha.strip()
                if not linha:
                    continue
                
                try:
                    item_data = json.loads(linha)
                    
                    if item_data.get('type') == 'response':
                        item = {
                            'url': item_data.get('url', ''),
                            'status': item_data.get('status', 0),
                            'tamanho': item_data.get('content_length', 0),
                            'palavras': item_data.get('word_count', 0),
                            'linhas': item_data.get('line_count', 0),
                            'tipo': 'diretorio' if item_data.get('url', '').endswith('/') else 'arquivo'
                        }
                        
                        if item['tipo'] == 'diretorio':
                            dados['diretorios_encontrados'].append(item)
                        else:
                            dados['arquivos_encontrados'].append(item)
                        
                        # Atualizar resumo
                        status = item['status']
                        if status not in dados['resumo']['codigos_status']:
                            dados['resumo']['codigos_status'][status] = 0
                        dados['resumo']['codigos_status'][status] += 1
                        
                        # Tamanhos interessantes (muito grandes ou muito pequenos)
                        if item['tamanho'] > 100000 or item['tamanho'] == 0:
                            dados['resumo']['tamanhos_interessantes'].append(item)
                
                except json.JSONDecodeError:
                    continue
            
            dados['resumo']['total_diretorios'] = len(dados['diretorios_encontrados'])
            dados['resumo']['total_arquivos'] = len(dados['arquivos_encontrados'])
            
        except Exception as e:
            self.logger.error(f"Erro ao processar saída Feroxbuster: {str(e)}")
        
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
        relatorio.append(f"RELATÓRIO FEROXBUSTER - {resultados['tipo_varredura'].upper()}")
        relatorio.append("=" * 60)
        relatorio.append(f"Timestamp: {resultados['timestamp']}")
        relatorio.append(f"Comando: {resultados['comando']}")
        relatorio.append("")
        
        # Resumo
        relatorio.append("RESUMO:")
        relatorio.append(f"  Diretórios Encontrados: {resumo.get('total_diretorios', 0)}")
        relatorio.append(f"  Arquivos Encontrados: {resumo.get('total_arquivos', 0)}")
        relatorio.append("")
        
        # Códigos de status
        codigos = resumo.get('codigos_status', {})
        if codigos:
            relatorio.append("CÓDIGOS DE STATUS:")
            for codigo, count in sorted(codigos.items()):
                relatorio.append(f"  {codigo}: {count}")
            relatorio.append("")
        
        # Diretórios interessantes
        diretorios = dados.get('diretorios_encontrados', [])
        if diretorios:
            relatorio.append("DIRETÓRIOS ENCONTRADOS:")
            for diretorio in diretorios[:10]:  # Máximo 10
                relatorio.append(f"  {diretorio['url']} (Status: {diretorio['status']}, Tamanho: {diretorio['tamanho']})")
            relatorio.append("")
        
        # Arquivos interessantes
        arquivos = dados.get('arquivos_encontrados', [])
        if arquivos:
            relatorio.append("ARQUIVOS ENCONTRADOS:")
            for arquivo in arquivos[:10]:  # Máximo 10
                relatorio.append(f"  {arquivo['url']} (Status: {arquivo['status']}, Tamanho: {arquivo['tamanho']})")
            relatorio.append("")
        
        return "\n".join(relatorio)


if __name__ == "__main__":
    # Teste do módulo
    logger = obter_logger('VarreduraFeroxbusterCLI')
    varredura = VarreduraFeroxbuster()
    
    if varredura.verificar_feroxbuster():
        logger.info("Feroxbuster está disponível!")
        
        alvo = input("Digite a URL para varredura: ").strip()
        if alvo:
            logger.info(f"Executando varredura básica em {alvo}...")
            resultado = varredura.varredura_basica(alvo)
            
            if resultado['sucesso']:
                logger.info("\nRelatório da Varredura:")
                logger.info(varredura.gerar_relatorio_resumido(resultado))
            else:
                logger.error(f"Erro na varredura: {resultado['erro']}")
    else:
        logger.error("Feroxbuster não está disponível. Instale o Feroxbuster para continuar.")