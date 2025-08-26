#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de varredura Subfinder
Enumera subdomínios usando Subfinder
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

class VarreduraSubfinder:
    """Classe para executar varreduras Subfinder"""
    
    def __init__(self):
        """Inicializa o módulo de varredura Subfinder"""
        self.logger = logging.getLogger(__name__)
        self.binario_subfinder = obter_config('subfinder.binario', 'subfinder')
        self.timeout_padrao = obter_config('subfinder.timeout_padrao', 300)
        self.threads_padrao = obter_config('subfinder.threads_padrao', 10)
        self.opcoes_padrao = obter_config('subfinder.opcoes_padrao', ['-silent'])
        
        # Verificar se o Subfinder está disponível
        self.verificar_subfinder()
    
    def verificar_subfinder(self) -> bool:
        """
        Verifica se o Subfinder está instalado e acessível
        Returns:
            bool: True se Subfinder está disponível, False caso contrário
        """
        try:
            resultado = subprocess.run(
                [self.binario_subfinder, '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                versao = resultado.stdout.strip()
                self.logger.info(f"Subfinder encontrado: {versao}")
                return True
            else:
                self.logger.error("Subfinder não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.error(f"Binário Subfinder não encontrado: {self.binario_subfinder}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout ao verificar versão do Subfinder")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar Subfinder: {str(e)}")
            return False
    
    def enumerar_subdominios(self, dominio: str, resolver_dns: bool = True) -> Dict[str, Any]:
        """
        Enumera subdomínios do domínio alvo
        Args:
            dominio (str): Domínio alvo
            resolver_dns (bool): Resolver DNS dos subdomínios
        Returns:
            Dict[str, Any]: Resultados da enumeração
        """
        comando = [
            self.binario_subfinder,
            '-d', dominio,
            '-silent',
            '-t', str(self.threads_padrao)
        ]
        
        if resolver_dns:
            comando.append('-nW')  # No wildcard
        else:
            comando.append('-nC')  # No color
        
        return self._executar_varredura(comando, "enumerar_subdominios")
    
    def enumerar_com_sources(self, dominio: str, sources: List[str]) -> Dict[str, Any]:
        """
        Enumera subdomínios usando sources específicas
        Args:
            dominio (str): Domínio alvo
            sources (List[str]): Lista de sources para usar
        Returns:
            Dict[str, Any]: Resultados da enumeração
        """
        comando = [
            self.binario_subfinder,
            '-d', dominio,
            '-silent',
            '-t', str(self.threads_padrao),
            '-sources', ','.join(sources)
        ]
        
        return self._executar_varredura(comando, "enumerar_com_sources")
    
    def enumerar_passivo(self, dominio: str) -> Dict[str, Any]:
        """
        Enumera subdomínios usando apenas sources passivas
        Args:
            dominio (str): Domínio alvo
        Returns:
            Dict[str, Any]: Resultados da enumeração
        """
        comando = [
            self.binario_subfinder,
            '-d', dominio,
            '-silent',
            '-t', str(self.threads_padrao),
            '-passive'
        ]
        
        return self._executar_varredura(comando, "enumerar_passivo")
    
    def enumerar_multiplos_dominios(self, dominios: List[str]) -> Dict[str, Any]:
        """
        Enumera subdomínios para múltiplos domínios
        Args:
            dominios (List[str]): Lista de domínios
        Returns:
            Dict[str, Any]: Resultados da enumeração
        """
        # Criar arquivo temporário com domínios
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
            for dominio in dominios:
                temp_file.write(f"{dominio}\n")
            arquivo_dominios = temp_file.name
        
        comando = [
            self.binario_subfinder,
            '-dL', arquivo_dominios,
            '-silent',
            '-t', str(self.threads_padrao)
        ]
        
        try:
            resultado = self._executar_varredura(comando, "enumerar_multiplos_dominios")
        finally:
            # Limpar arquivo temporário
            try:
                os.unlink(arquivo_dominios)
            except:
                pass
        
        return resultado
    
    def enumerar_com_config(self, dominio: str, arquivo_config: str) -> Dict[str, Any]:
        """
        Enumera subdomínios usando arquivo de configuração
        Args:
            dominio (str): Domínio alvo
            arquivo_config (str): Caminho para arquivo de configuração
        Returns:
            Dict[str, Any]: Resultados da enumeração
        """
        if not os.path.exists(arquivo_config):
            return {
                'sucesso': False,
                'erro': f'Arquivo de configuração não encontrado: {arquivo_config}',
                'timestamp': datetime.now().isoformat()
            }
        
        comando = [
            self.binario_subfinder,
            '-d', dominio,
            '-silent',
            '-t', str(self.threads_padrao),
            '-config', arquivo_config
        ]
        
        return self._executar_varredura(comando, "enumerar_com_config")
    
    def _executar_varredura(self, comando: List[str], tipo_varredura: str) -> Dict[str, Any]:
        """
        Executa comando Subfinder e processa resultados
        Args:
            comando (List[str]): Comando completo do Subfinder
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
                resultado['dados'] = self._processar_saida_subfinder(processo.stdout)
                resultado['sucesso'] = True
                self.logger.info(f"{tipo_varredura} concluída com sucesso")
            else:
                resultado['erro'] = f"Subfinder retornou código {processo.returncode}: {processo.stderr}"
                self.logger.error(resultado['erro'])
            
        except subprocess.TimeoutExpired:
            resultado['erro'] = f"Timeout na execução da varredura ({self.timeout_padrao}s)"
            self.logger.error(resultado['erro'])
        except Exception as e:
            resultado['erro'] = f"Erro na execução: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def _processar_saida_subfinder(self, saida: str) -> Dict[str, Any]:
        """
        Processa saída do Subfinder
        Args:
            saida (str): Saída do comando Subfinder
        Returns:
            Dict[str, Any]: Dados estruturados da varredura
        """
        dados = {
            'subdominios': [],
            'resumo': {
                'total_subdominios': 0,
                'dominios_unicos': set(),
                'subdominios_por_nivel': {}
            }
        }
        
        try:
            linhas = saida.strip().split('\n')
            
            for linha in linhas:
                linha = linha.strip()
                if not linha:
                    continue
                
                # Cada linha é um subdomínio
                subdominio = linha
                if subdominio and subdominio not in dados['subdominios']:
                    dados['subdominios'].append(subdominio)
                    
                    # Extrair domínio principal
                    partes = subdominio.split('.')
                    if len(partes) >= 2:
                        dominio_principal = '.'.join(partes[-2:])
                        dados['resumo']['dominios_unicos'].add(dominio_principal)
                        
                        # Contar níveis de subdomínio
                        nivel = len(partes) - 2
                        if nivel not in dados['resumo']['subdominios_por_nivel']:
                            dados['resumo']['subdominios_por_nivel'][nivel] = 0
                        dados['resumo']['subdominios_por_nivel'][nivel] += 1
            
            dados['resumo']['total_subdominios'] = len(dados['subdominios'])
            dados['resumo']['dominios_unicos'] = list(dados['resumo']['dominios_unicos'])
            
        except Exception as e:
            self.logger.error(f"Erro ao processar saída Subfinder: {str(e)}")
        
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
        relatorio.append(f"RELATÓRIO SUBFINDER - {resultados['tipo_varredura'].upper()}")
        relatorio.append("=" * 60)
        relatorio.append(f"Timestamp: {resultados['timestamp']}")
        relatorio.append(f"Comando: {resultados['comando']}")
        relatorio.append("")
        
        # Resumo
        relatorio.append("RESUMO:")
        relatorio.append(f"  Subdomínios Encontrados: {resumo.get('total_subdominios', 0)}")
        relatorio.append(f"  Domínios Únicos: {len(resumo.get('dominios_unicos', []))}")
        relatorio.append("")
        
        # Distribuição por nível
        por_nivel = resumo.get('subdominios_por_nivel', {})
        if por_nivel:
            relatorio.append("DISTRIBUIÇÃO POR NÍVEL:")
            for nivel, count in sorted(por_nivel.items()):
                nivel_desc = f"{nivel} nível{'is' if nivel > 1 else ''}"
                relatorio.append(f"  {nivel_desc}: {count}")
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
    
    def obter_sources_disponiveis(self) -> List[str]:
        """
        Retorna lista de sources disponíveis
        Returns:
            List[str]: Lista de sources
        """
        return [
            'alienvault', 'anubis', 'bufferover', 'censys', 'certspotter',
            'crtsh', 'dnsdb', 'hackertarget', 'passivetotal', 'securitytrails',
            'shodan', 'spyse', 'threatcrowd', 'virustotal', 'waybackarchive'
        ]


if __name__ == "__main__":
    # Teste do módulo
    logger = obter_logger('VarreduraSubfinderCLI')
    varredura = VarreduraSubfinder()
    
    if varredura.verificar_subfinder():
        logger.info("Subfinder está disponível!")
        
        logger.info("Sources disponíveis: " + ', '.join(varredura.obter_sources_disponiveis()))
        
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
        logger.error("Subfinder não está disponível. Instale o Subfinder para continuar.")