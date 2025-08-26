#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de varredura WhatWeb
Identifica tecnologias web usando WhatWeb
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

class VarreduraWhatWeb:
    """Classe para executar varreduras WhatWeb"""
    
    def __init__(self):
        """Inicializa o módulo de varredura WhatWeb"""
        self.logger = logging.getLogger(__name__)
        self.binario_whatweb = obter_config('whatweb.binario', 'whatweb')
        self.timeout_padrao = obter_config('whatweb.timeout_padrao', 300)
        self.threads_padrao = obter_config('whatweb.threads_padrao', 25)
        self.opcoes_padrao = obter_config('whatweb.opcoes_padrao', ['--color=never'])
        
        # Verificar se o WhatWeb está disponível
        self.verificar_whatweb()
    
    def verificar_whatweb(self) -> bool:
        """
        Verifica se o WhatWeb está instalado e acessível
        Returns:
            bool: True se WhatWeb está disponível, False caso contrário
        """
        try:
            resultado = subprocess.run(
                [self.binario_whatweb, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                versao = resultado.stdout.strip()
                self.logger.info(f"WhatWeb encontrado: {versao}")
                return True
            else:
                self.logger.error("WhatWeb não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.error(f"Binário WhatWeb não encontrado: {self.binario_whatweb}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout ao verificar versão do WhatWeb")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar WhatWeb: {str(e)}")
            return False
    
    def identificar_tecnologias(self, alvo: str, agressividade: int = 1) -> Dict[str, Any]:
        """
        Identifica tecnologias web no alvo
        Args:
            alvo (str): URL do alvo
            agressividade (int): Nível de agressividade (1-4)
        Returns:
            Dict[str, Any]: Resultados da identificação
        """
        comando = [
            self.binario_whatweb,
            '--log-json=-',
            f'--aggression={agressividade}',
            '--color=never',
            alvo
        ]
        
        return self._executar_varredura(comando, "identificar_tecnologias")
    
    def varredura_passiva(self, alvo: str) -> Dict[str, Any]:
        """
        Executa varredura passiva (agressividade 1)
        Args:
            alvo (str): URL do alvo
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_whatweb,
            '--log-json=-',
            '--aggression=1',
            '--color=never',
            alvo
        ]
        
        return self._executar_varredura(comando, "varredura_passiva")
    
    def varredura_agressiva(self, alvo: str) -> Dict[str, Any]:
        """
        Executa varredura agressiva (agressividade 3)
        Args:
            alvo (str): URL do alvo
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_whatweb,
            '--log-json=-',
            '--aggression=3',
            '--color=never',
            alvo
        ]
        
        return self._executar_varredura(comando, "varredura_agressiva")
    
    def varredura_multiplos_alvos(self, alvos: List[str], agressividade: int = 1) -> Dict[str, Any]:
        """
        Executa varredura em múltiplos alvos
        Args:
            alvos (List[str]): Lista de URLs
            agressividade (int): Nível de agressividade
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        # Criar arquivo temporário com alvos
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
            for alvo in alvos:
                temp_file.write(f"{alvo}\n")
            arquivo_alvos = temp_file.name
        
        comando = [
            self.binario_whatweb,
            '--log-json=-',
            f'--aggression={agressividade}',
            '--color=never',
            '-i', arquivo_alvos
        ]
        
        try:
            resultado = self._executar_varredura(comando, "varredura_multiplos_alvos")
        finally:
            # Limpar arquivo temporário
            try:
                os.unlink(arquivo_alvos)
            except:
                pass
        
        return resultado
    
    def varredura_com_plugins(self, alvo: str, plugins: List[str]) -> Dict[str, Any]:
        """
        Executa varredura com plugins específicos
        Args:
            alvo (str): URL do alvo
            plugins (List[str]): Lista de plugins para usar
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_whatweb,
            '--log-json=-',
            '--color=never',
            '--plugins', ','.join(plugins),
            alvo
        ]
        
        return self._executar_varredura(comando, "varredura_com_plugins")
    
    def listar_plugins(self) -> List[str]:
        """
        Lista plugins disponíveis do WhatWeb
        Returns:
            List[str]: Lista de plugins
        """
        try:
            comando = [self.binario_whatweb, '--list-plugins']
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            plugins = []
            if resultado.returncode == 0:
                linhas = resultado.stdout.split('\n')
                for linha in linhas:
                    linha = linha.strip()
                    if linha and not linha.startswith('[') and not linha.startswith('Plugin'):
                        plugins.append(linha.split()[0])
            
            self.logger.info(f"Encontrados {len(plugins)} plugins")
            return plugins
            
        except Exception as e:
            self.logger.error(f"Erro ao listar plugins: {str(e)}")
            return []
    
    def _executar_varredura(self, comando: List[str], tipo_varredura: str) -> Dict[str, Any]:
        """
        Executa comando WhatWeb e processa resultados
        Args:
            comando (List[str]): Comando completo do WhatWeb
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
                resultado['dados'] = self._processar_saida_whatweb(processo.stdout)
                resultado['sucesso'] = True
                self.logger.info(f"{tipo_varredura} concluída com sucesso")
            else:
                resultado['erro'] = f"WhatWeb retornou código {processo.returncode}: {processo.stderr}"
                self.logger.error(resultado['erro'])
            
        except subprocess.TimeoutExpired:
            resultado['erro'] = f"Timeout na execução da varredura ({self.timeout_padrao}s)"
            self.logger.error(resultado['erro'])
        except Exception as e:
            resultado['erro'] = f"Erro na execução: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def _processar_saida_whatweb(self, saida: str) -> Dict[str, Any]:
        """
        Processa saída JSON do WhatWeb
        Args:
            saida (str): Saída JSON do comando WhatWeb
        Returns:
            Dict[str, Any]: Dados estruturados da varredura
        """
        dados = {
            'alvos_analisados': [],
            'resumo': {
                'total_alvos': 0,
                'tecnologias_encontradas': set(),
                'servidores_web': set(),
                'linguagens': set(),
                'frameworks': set(),
                'cms': set()
            }
        }
        
        try:
            linhas = saida.strip().split('\n')
            
            for linha in linhas:
                linha = linha.strip()
                if not linha:
                    continue
                
                try:
                    alvo_data = json.loads(linha)
                    
                    alvo_info = {
                        'target': alvo_data.get('target', ''),
                        'http_status': alvo_data.get('http_status', 0),
                        'request_config': alvo_data.get('request_config', {}),
                        'plugins': {},
                        'tecnologias': []
                    }
                    
                    # Processar plugins
                    plugins = alvo_data.get('plugins', {})
                    for plugin_name, plugin_data in plugins.items():
                        alvo_info['plugins'][plugin_name] = plugin_data
                        alvo_info['tecnologias'].append(plugin_name)
                        
                        # Categorizar tecnologias
                        dados['resumo']['tecnologias_encontradas'].add(plugin_name)
                        
                        # Identificar servidores web
                        if plugin_name.lower() in ['apache', 'nginx', 'iis', 'lighttpd']:
                            dados['resumo']['servidores_web'].add(plugin_name)
                        
                        # Identificar linguagens
                        elif plugin_name.lower() in ['php', 'asp', 'jsp', 'python', 'ruby']:
                            dados['resumo']['linguagens'].add(plugin_name)
                        
                        # Identificar frameworks
                        elif plugin_name.lower() in ['jquery', 'bootstrap', 'angular', 'react']:
                            dados['resumo']['frameworks'].add(plugin_name)
                        
                        # Identificar CMS
                        elif plugin_name.lower() in ['wordpress', 'drupal', 'joomla']:
                            dados['resumo']['cms'].add(plugin_name)
                    
                    dados['alvos_analisados'].append(alvo_info)
                
                except json.JSONDecodeError:
                    continue
            
            dados['resumo']['total_alvos'] = len(dados['alvos_analisados'])
            dados['resumo']['tecnologias_encontradas'] = len(dados['resumo']['tecnologias_encontradas'])
            dados['resumo']['servidores_web'] = list(dados['resumo']['servidores_web'])
            dados['resumo']['linguagens'] = list(dados['resumo']['linguagens'])
            dados['resumo']['frameworks'] = list(dados['resumo']['frameworks'])
            dados['resumo']['cms'] = list(dados['resumo']['cms'])
            
        except Exception as e:
            self.logger.error(f"Erro ao processar saída WhatWeb: {str(e)}")
        
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
        relatorio.append(f"RELATÓRIO WHATWEB - {resultados['tipo_varredura'].upper()}")
        relatorio.append("=" * 60)
        relatorio.append(f"Timestamp: {resultados['timestamp']}")
        relatorio.append(f"Comando: {resultados['comando']}")
        relatorio.append("")
        
        # Resumo
        relatorio.append("RESUMO:")
        relatorio.append(f"  Alvos Analisados: {resumo.get('total_alvos', 0)}")
        relatorio.append(f"  Tecnologias Encontradas: {resumo.get('tecnologias_encontradas', 0)}")
        relatorio.append("")
        
        # Tecnologias por categoria
        if resumo.get('servidores_web'):
            relatorio.append("SERVIDORES WEB:")
            for servidor in resumo['servidores_web']:
                relatorio.append(f"  • {servidor}")
            relatorio.append("")
        
        if resumo.get('linguagens'):
            relatorio.append("LINGUAGENS:")
            for linguagem in resumo['linguagens']:
                relatorio.append(f"  • {linguagem}")
            relatorio.append("")
        
        if resumo.get('frameworks'):
            relatorio.append("FRAMEWORKS:")
            for framework in resumo['frameworks']:
                relatorio.append(f"  • {framework}")
            relatorio.append("")
        
        if resumo.get('cms'):
            relatorio.append("CMS:")
            for cms in resumo['cms']:
                relatorio.append(f"  • {cms}")
            relatorio.append("")
        
        # Detalhes dos alvos
        alvos = dados.get('alvos_analisados', [])
        if alvos:
            relatorio.append("DETALHES DOS ALVOS:")
            for alvo in alvos[:5]:  # Máximo 5 alvos
                relatorio.append(f"\nAlvo: {alvo.get('target', 'N/A')}")
                relatorio.append(f"  Status HTTP: {alvo.get('http_status', 'N/A')}")
                relatorio.append(f"  Tecnologias: {', '.join(alvo.get('tecnologias', [])[:10])}")
        
        return "\n".join(relatorio)


if __name__ == "__main__":
    # Teste do módulo
    logger = obter_logger('VarreduraWhatWebCLI')
    varredura = VarreduraWhatWeb()
    
    if varredura.verificar_whatweb():
        logger.info("WhatWeb está disponível!")
        
        alvo = input("Digite a URL para análise: ").strip()
        if alvo:
            logger.info(f"Identificando tecnologias em {alvo}...")
            resultado = varredura.identificar_tecnologias(alvo)
            
            if resultado['sucesso']:
                logger.info("\nRelatório da Análise:")
                logger.info(varredura.gerar_relatorio_resumido(resultado))
            else:
                logger.error(f"Erro na análise: {resultado['erro']}")
    else:
        logger.error("WhatWeb não está disponível. Instale o WhatWeb para continuar.")