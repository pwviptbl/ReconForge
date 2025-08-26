#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de varredura SQLMap
Testa vulnerabilidades de SQL Injection usando SQLMap
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

class VarreduraSQLMap:
    """Classe para executar varreduras SQLMap"""
    
    def __init__(self):
        """Inicializa o módulo de varredura SQLMap"""
        self.logger = logging.getLogger(__name__)
        self.binario_sqlmap = obter_config('sqlmap.binario', 'sqlmap')
        self.timeout_padrao = obter_config('sqlmap.timeout_padrao', 1800)
        self.threads_padrao = obter_config('sqlmap.threads_padrao', 1)
        self.opcoes_padrao = obter_config('sqlmap.opcoes_padrao', ['--batch'])
        
        # Verificar se o SQLMap está disponível
        self.verificar_sqlmap()
    
    def verificar_sqlmap(self) -> bool:
        """
        Verifica se o SQLMap está instalado e acessível
        Returns:
            bool: True se SQLMap está disponível, False caso contrário
        """
        try:
            resultado = subprocess.run(
                [self.binario_sqlmap, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                versao = resultado.stdout.strip()
                self.logger.info(f"SQLMap encontrado: {versao}")
                return True
            else:
                self.logger.error("SQLMap não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.error(f"Binário SQLMap não encontrado: {self.binario_sqlmap}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout ao verificar versão do SQLMap")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar SQLMap: {str(e)}")
            return False
    
    def testar_url(self, url: str, parametros: Optional[str] = None) -> Dict[str, Any]:
        """
        Testa URL para SQL Injection
        Args:
            url (str): URL para testar
            parametros (str): Parâmetros específicos para testar
        Returns:
            Dict[str, Any]: Resultados do teste
        """
        comando = [
            self.binario_sqlmap,
            '-u', url,
            '--batch',
            '--threads', str(self.threads_padrao)
        ]
        
        if parametros:
            comando.extend(['-p', parametros])
        
        return self._executar_varredura(comando, "testar_url")
    
    def testar_formulario(self, url: str, dados_post: Optional[str] = None) -> Dict[str, Any]:
        """
        Testa formulário para SQL Injection
        Args:
            url (str): URL do formulário
            dados_post (str): Dados POST para enviar
        Returns:
            Dict[str, Any]: Resultados do teste
        """
        comando = [
            self.binario_sqlmap,
            '-u', url,
            '--batch',
            '--forms',
            '--threads', str(self.threads_padrao)
        ]
        
        if dados_post:
            comando.extend(['--data', dados_post])
        
        return self._executar_varredura(comando, "testar_formulario")
    
    def testar_com_cookies(self, url: str, cookies: str) -> Dict[str, Any]:
        """
        Testa URL com cookies específicos
        Args:
            url (str): URL para testar
            cookies (str): String de cookies
        Returns:
            Dict[str, Any]: Resultados do teste
        """
        comando = [
            self.binario_sqlmap,
            '-u', url,
            '--batch',
            '--cookie', cookies,
            '--threads', str(self.threads_padrao)
        ]
        
        return self._executar_varredura(comando, "testar_com_cookies")
    
    def testar_com_headers(self, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Testa URL com headers personalizados
        Args:
            url (str): URL para testar
            headers (Dict[str, str]): Headers HTTP
        Returns:
            Dict[str, Any]: Resultados do teste
        """
        comando = [
            self.binario_sqlmap,
            '-u', url,
            '--batch',
            '--threads', str(self.threads_padrao)
        ]
        
        for header, valor in headers.items():
            comando.extend(['--header', f'{header}: {valor}'])
        
        return self._executar_varredura(comando, "testar_com_headers")
    
    def testar_nivel_risco(self, url: str, nivel: int = 1, risco: int = 1) -> Dict[str, Any]:
        """
        Testa URL com nível e risco específicos
        Args:
            url (str): URL para testar
            nivel (int): Nível de teste (1-5)
            risco (int): Nível de risco (1-3)
        Returns:
            Dict[str, Any]: Resultados do teste
        """
        comando = [
            self.binario_sqlmap,
            '-u', url,
            '--batch',
            '--level', str(nivel),
            '--risk', str(risco),
            '--threads', str(self.threads_padrao)
        ]
        
        return self._executar_varredura(comando, "testar_nivel_risco")
    
    def enumerar_bases_dados(self, url: str) -> Dict[str, Any]:
        """
        Enumera bases de dados disponíveis
        Args:
            url (str): URL vulnerável
        Returns:
            Dict[str, Any]: Resultados da enumeração
        """
        comando = [
            self.binario_sqlmap,
            '-u', url,
            '--batch',
            '--dbs',
            '--threads', str(self.threads_padrao)
        ]
        
        return self._executar_varredura(comando, "enumerar_bases_dados")
    
    def enumerar_tabelas(self, url: str, base_dados: str) -> Dict[str, Any]:
        """
        Enumera tabelas de uma base de dados
        Args:
            url (str): URL vulnerável
            base_dados (str): Nome da base de dados
        Returns:
            Dict[str, Any]: Resultados da enumeração
        """
        comando = [
            self.binario_sqlmap,
            '-u', url,
            '--batch',
            '-D', base_dados,
            '--tables',
            '--threads', str(self.threads_padrao)
        ]
        
        return self._executar_varredura(comando, "enumerar_tabelas")
    
    def enumerar_colunas(self, url: str, base_dados: str, tabela: str) -> Dict[str, Any]:
        """
        Enumera colunas de uma tabela
        Args:
            url (str): URL vulnerável
            base_dados (str): Nome da base de dados
            tabela (str): Nome da tabela
        Returns:
            Dict[str, Any]: Resultados da enumeração
        """
        comando = [
            self.binario_sqlmap,
            '-u', url,
            '--batch',
            '-D', base_dados,
            '-T', tabela,
            '--columns',
            '--threads', str(self.threads_padrao)
        ]
        
        return self._executar_varredura(comando, "enumerar_colunas")
    
    def extrair_dados(self, url: str, base_dados: str, tabela: str, colunas: Optional[str] = None) -> Dict[str, Any]:
        """
        Extrai dados de uma tabela
        Args:
            url (str): URL vulnerável
            base_dados (str): Nome da base de dados
            tabela (str): Nome da tabela
            colunas (str): Colunas específicas para extrair
        Returns:
            Dict[str, Any]: Resultados da extração
        """
        comando = [
            self.binario_sqlmap,
            '-u', url,
            '--batch',
            '-D', base_dados,
            '-T', tabela,
            '--dump',
            '--threads', str(self.threads_padrao)
        ]
        
        if colunas:
            comando.extend(['-C', colunas])
        
        return self._executar_varredura(comando, "extrair_dados")
    
    def testar_arquivo_requisicoes(self, arquivo_burp: str) -> Dict[str, Any]:
        """
        Testa arquivo de requisições do Burp Suite
        Args:
            arquivo_burp (str): Caminho para arquivo de requisições
        Returns:
            Dict[str, Any]: Resultados do teste
        """
        if not os.path.exists(arquivo_burp):
            return {
                'sucesso': False,
                'erro': f'Arquivo não encontrado: {arquivo_burp}',
                'timestamp': datetime.now().isoformat()
            }
        
        comando = [
            self.binario_sqlmap,
            '-r', arquivo_burp,
            '--batch',
            '--threads', str(self.threads_padrao)
        ]
        
        return self._executar_varredura(comando, "testar_arquivo_requisicoes")
    
    def _executar_varredura(self, comando: List[str], tipo_varredura: str) -> Dict[str, Any]:
        """
        Executa comando SQLMap e processa resultados
        Args:
            comando (List[str]): Comando completo do SQLMap
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
            
            # SQLMap pode retornar código != 0 mas ainda ter resultados úteis
            if processo.stdout:
                resultado['dados'] = self._processar_saida_sqlmap(processo.stdout)
                resultado['sucesso'] = True
                self.logger.info(f"{tipo_varredura} concluída com sucesso")
            else:
                resultado['erro'] = f"SQLMap retornou código {processo.returncode}: {processo.stderr}"
                self.logger.error(resultado['erro'])
            
        except subprocess.TimeoutExpired:
            resultado['erro'] = f"Timeout na execução da varredura ({self.timeout_padrao}s)"
            self.logger.error(resultado['erro'])
        except Exception as e:
            resultado['erro'] = f"Erro na execução: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def _processar_saida_sqlmap(self, saida: str) -> Dict[str, Any]:
        """
        Processa saída do SQLMap
        Args:
            saida (str): Saída do comando SQLMap
        Returns:
            Dict[str, Any]: Dados estruturados da varredura
        """
        dados = {
            'vulnerabilidades_encontradas': [],
            'bases_dados': [],
            'tabelas': [],
            'colunas': [],
            'dados_extraidos': [],
            'resumo': {
                'vulneravel': False,
                'sgbd_detectado': '',
                'parametros_vulneraveis': [],
                'tecnicas_injecao': [],
                'nivel_risco': ''
            }
        }
        
        try:
            linhas = saida.split('\n')
            
            for linha in linhas:
                linha = linha.strip()
                
                # Detectar vulnerabilidade
                if 'is vulnerable' in linha.lower():
                    dados['resumo']['vulneravel'] = True
                    dados['vulnerabilidades_encontradas'].append(linha)
                
                # Detectar SGBD
                elif 'back-end DBMS:' in linha:
                    sgbd = linha.split('back-end DBMS:')[-1].strip()
                    dados['resumo']['sgbd_detectado'] = sgbd
                
                # Detectar parâmetros vulneráveis
                elif 'Parameter:' in linha:
                    parametro = linha.split('Parameter:')[-1].strip()
                    if parametro not in dados['resumo']['parametros_vulneraveis']:
                        dados['resumo']['parametros_vulneraveis'].append(parametro)
                
                # Detectar técnicas de injeção
                elif 'Type:' in linha and 'Title:' in linha:
                    tecnica = linha.split('Type:')[-1].split('Title:')[0].strip()
                    if tecnica not in dados['resumo']['tecnicas_injecao']:
                        dados['resumo']['tecnicas_injecao'].append(tecnica)
                
                # Detectar bases de dados
                elif 'available databases' in linha.lower():
                    # Próximas linhas contêm as bases de dados
                    continue
                elif linha.startswith('[*] ') and not any(char in linha for char in [':', '(', ')']):
                    possivel_bd = linha.replace('[*] ', '').strip()
                    if possivel_bd and possivel_bd not in dados['bases_dados']:
                        dados['bases_dados'].append(possivel_bd)
                
                # Detectar tabelas
                elif 'tables' in linha.lower() and 'database' in linha.lower():
                    continue
                elif linha.startswith('| ') and linha.endswith(' |'):
                    possivel_tabela = linha.strip('| ').strip()
                    if possivel_tabela and possivel_tabela not in dados['tabelas']:
                        dados['tabelas'].append(possivel_tabela)
            
            # Determinar nível de risco
            if dados['resumo']['vulneravel']:
                if any('union' in t.lower() for t in dados['resumo']['tecnicas_injecao']):
                    dados['resumo']['nivel_risco'] = 'Alto'
                elif any('boolean' in t.lower() for t in dados['resumo']['tecnicas_injecao']):
                    dados['resumo']['nivel_risco'] = 'Médio'
                else:
                    dados['resumo']['nivel_risco'] = 'Baixo'
            else:
                dados['resumo']['nivel_risco'] = 'Nenhum'
            
        except Exception as e:
            self.logger.error(f"Erro ao processar saída SQLMap: {str(e)}")
        
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
        relatorio.append(f"RELATÓRIO SQLMAP - {resultados['tipo_varredura'].upper()}")
        relatorio.append("=" * 60)
        relatorio.append(f"Timestamp: {resultados['timestamp']}")
        relatorio.append(f"Comando: {resultados['comando']}")
        relatorio.append("")
        
        # Resumo
        relatorio.append("RESUMO:")
        relatorio.append(f"  Vulnerável: {'SIM' if resumo.get('vulneravel') else 'NÃO'}")
        relatorio.append(f"  Nível de Risco: {resumo.get('nivel_risco', 'N/A')}")
        
        if resumo.get('sgbd_detectado'):
            relatorio.append(f"  SGBD Detectado: {resumo['sgbd_detectado']}")
        
        relatorio.append("")
        
        # Parâmetros vulneráveis
        parametros = resumo.get('parametros_vulneraveis', [])
        if parametros:
            relatorio.append("PARÂMETROS VULNERÁVEIS:")
            for parametro in parametros:
                relatorio.append(f"  • {parametro}")
            relatorio.append("")
        
        # Técnicas de injeção
        tecnicas = resumo.get('tecnicas_injecao', [])
        if tecnicas:
            relatorio.append("TÉCNICAS DE INJEÇÃO:")
            for tecnica in tecnicas:
                relatorio.append(f"  • {tecnica}")
            relatorio.append("")
        
        # Bases de dados encontradas
        bases_dados = dados.get('bases_dados', [])
        if bases_dados:
            relatorio.append("BASES DE DADOS ENCONTRADAS:")
            for bd in bases_dados[:10]:  # Máximo 10
                relatorio.append(f"  • {bd}")
            relatorio.append("")
        
        # Tabelas encontradas
        tabelas = dados.get('tabelas', [])
        if tabelas:
            relatorio.append("TABELAS ENCONTRADAS:")
            for tabela in tabelas[:10]:  # Máximo 10
                relatorio.append(f"  • {tabela}")
            relatorio.append("")
        
        return "\n".join(relatorio)
    
    def obter_opcoes_nivel_risco(self) -> Dict[str, str]:
        """
        Retorna opções de nível e risco
        Returns:
            Dict[str, str]: Dicionário com opções
        """
        return {
            'niveis': {
                '1': 'Básico (GET/POST)',
                '2': 'Cookies',
                '3': 'User-Agent/Referer',
                '4': 'Headers HTTP',
                '5': 'Todos os headers'
            },
            'riscos': {
                '1': 'Baixo (queries seguras)',
                '2': 'Médio (queries de tempo)',
                '3': 'Alto (queries destrutivas)'
            }
        }


if __name__ == "__main__":
    # Teste do módulo
    logger = obter_logger('VarreduraSQLMapCLI')
    varredura = VarreduraSQLMap()
    
    if varredura.verificar_sqlmap():
        logger.info("SQLMap está disponível!")
        
        opcoes = varredura.obter_opcoes_nivel_risco()
        logger.info("Níveis disponíveis:")
        for nivel, desc in opcoes['niveis'].items():
            logger.info(f"  {nivel}: {desc}")
        
        url = input("Digite a URL para teste de SQL Injection: ").strip()
        if url:
            logger.info(f"Testando SQL Injection em {url}...")
            resultado = varredura.testar_url(url)
            
            if resultado['sucesso']:
                logger.info("\nRelatório do Teste:")
                logger.info(varredura.gerar_relatorio_resumido(resultado))
            else:
                logger.error(f"Erro no teste: {resultado['erro']}")
    else:
        logger.error("SQLMap não está disponível. Instale o SQLMap para continuar.")