#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de varredura Nuclei
Realiza varreduras de vulnerabilidades usando templates Nuclei
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

class VarreduraNuclei:
    """Classe para executar varreduras Nuclei"""
    
    def __init__(self):
        """Inicializa o módulo de varredura Nuclei"""
        self.logger = logging.getLogger(__name__)
        self.binario_nuclei = obter_config('nuclei.binario', 'nuclei')
        self.timeout_padrao = obter_config('nuclei.timeout_padrao', 600)
        self.threads_padrao = obter_config('nuclei.threads_padrao', 25)
        self.rate_limit_padrao = obter_config('nuclei.rate_limit_padrao', 150)
        self.opcoes_padrao = obter_config('nuclei.opcoes_padrao', ['-silent'])
        
        # Verificar se o Nuclei está disponível
        self.verificar_nuclei()
    
    def verificar_nuclei(self) -> bool:
        """
        Verifica se o Nuclei está instalado e acessível
        Returns:
            bool: True se Nuclei está disponível, False caso contrário
        """
        try:
            resultado = subprocess.run(
                [self.binario_nuclei, '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                versao = resultado.stdout.strip()
                self.logger.info(f"Nuclei encontrado: {versao}")
                return True
            else:
                self.logger.error("Nuclei não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.error(f"Binário Nuclei não encontrado: {self.binario_nuclei}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout ao verificar versão do Nuclei")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar Nuclei: {str(e)}")
            return False
    
    def atualizar_templates(self) -> Dict[str, Any]:
        """
        Atualiza templates do Nuclei
        Returns:
            Dict[str, Any]: Resultado da atualização
        """
        comando = [self.binario_nuclei, '-update-templates']
        
        resultado = {
            'sucesso': False,
            'timestamp': datetime.now().isoformat(),
            'comando': ' '.join(comando),
            'erro': None
        }
        
        try:
            self.logger.info("Atualizando templates do Nuclei...")
            
            processo = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            resultado['codigo_saida'] = processo.returncode
            resultado['saida_padrao'] = processo.stdout
            resultado['saida_erro'] = processo.stderr
            
            if processo.returncode == 0:
                resultado['sucesso'] = True
                self.logger.info("Templates atualizados com sucesso")
            else:
                resultado['erro'] = f"Erro na atualização: {processo.stderr}"
                self.logger.error(resultado['erro'])
                
        except Exception as e:
            resultado['erro'] = f"Erro na atualização: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def listar_templates(self, categoria: Optional[str] = None) -> List[str]:
        """
        Lista templates disponíveis
        Args:
            categoria (str): Categoria de templates (ex: 'cve', 'misconfiguration', 'exposed-panels')
        Returns:
            List[str]: Lista de templates
        """
        try:
            comando = [self.binario_nuclei, '-tl']
            if categoria:
                comando.extend(['-tags', categoria])
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            templates = []
            if resultado.returncode == 0:
                linhas = resultado.stdout.split('\n')
                for linha in linhas:
                    linha = linha.strip()
                    if linha and not linha.startswith('[') and '.yaml' in linha:
                        templates.append(linha)
            
            self.logger.info(f"Encontrados {len(templates)} templates")
            return templates
            
        except Exception as e:
            self.logger.error(f"Erro ao listar templates: {str(e)}")
            return []
    
    def scan(self, alvo: str, **kwargs) -> Dict[str, Any]:
        """
        Método padrão de execução para o orquestrador
        Args:
            alvo (str): URL ou IP do alvo
            **kwargs: Parâmetros adicionais
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        severidade = kwargs.get('severidade', 'medium')
        return self.varredura_basica(alvo, severidade)
    
    def varredura_basica(self, alvo: str, severidade: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura básica no alvo
        Args:
            alvo (str): URL ou IP do alvo
            severidade (str): Severidade mínima ('info', 'low', 'medium', 'high', 'critical')
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nuclei,
            '-target', alvo,
            '-json',
            '-silent',
            '-c', str(self.threads_padrao),
            '-rl', str(self.rate_limit_padrao)
        ]
        
        if severidade:
            comando.extend(['-severity', severidade])
        
        return self._executar_varredura(comando, "varredura_basica")
    
    def varredura_cve(self, alvo: str, ano: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura focada em CVEs
        Args:
            alvo (str): URL ou IP do alvo
            ano (str): Ano específico de CVEs (ex: '2023', '2024')
        Returns:
            Dict[str, Any]: Resultados da varredura de CVEs
        """
        comando = [
            self.binario_nuclei,
            '-target', alvo,
            '-tags', 'cve',
            '-json',
            '-silent',
            '-c', str(self.threads_padrao),
            '-rl', str(self.rate_limit_padrao)
        ]
        
        if ano:
            comando.extend(['-tags', f'cve{ano}'])
        
        return self._executar_varredura(comando, "varredura_cve")
    
    def varredura_tecnologias(self, alvo: str, tecnologia: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura focada em tecnologias específicas
        Args:
            alvo (str): URL ou IP do alvo
            tecnologia (str): Tecnologia específica (ex: 'apache', 'nginx', 'wordpress')
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nuclei,
            '-target', alvo,
            '-json',
            '-silent',
            '-c', str(self.threads_padrao),
            '-rl', str(self.rate_limit_padrao)
        ]
        
        if tecnologia:
            comando.extend(['-tags', tecnologia])
        else:
            comando.extend(['-tags', 'tech'])
        
        return self._executar_varredura(comando, "varredura_tecnologias")
    
    def varredura_paineis_expostos(self, alvo: str) -> Dict[str, Any]:
        """
        Executa varredura para painéis administrativos expostos
        Args:
            alvo (str): URL ou IP do alvo
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nuclei,
            '-target', alvo,
            '-tags', 'exposed-panels,panel,login',
            '-json',
            '-silent',
            '-c', str(self.threads_padrao),
            '-rl', str(self.rate_limit_padrao)
        ]
        
        return self._executar_varredura(comando, "varredura_paineis_expostos")
    
    def varredura_configuracao(self, alvo: str) -> Dict[str, Any]:
        """
        Executa varredura para problemas de configuração
        Args:
            alvo (str): URL ou IP do alvo
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nuclei,
            '-target', alvo,
            '-tags', 'misconfiguration,config,default-login',
            '-json',
            '-silent',
            '-c', str(self.threads_padrao),
            '-rl', str(self.rate_limit_padrao)
        ]
        
        return self._executar_varredura(comando, "varredura_configuracao")
    
    def varredura_personalizada(self, alvo: str, templates: List[str], opcoes: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Executa varredura personalizada com templates específicos
        Args:
            alvo (str): URL ou IP do alvo
            templates (List[str]): Lista de templates ou tags
            opcoes (List[str]): Opções adicionais
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nuclei,
            '-target', alvo,
            '-json',
            '-silent',
            '-c', str(self.threads_padrao),
            '-rl', str(self.rate_limit_padrao)
        ]
        
        # Adicionar templates
        if templates:
            for template in templates:
                if template.endswith('.yaml'):
                    comando.extend(['-t', template])
                else:
                    comando.extend(['-tags', template])
        
        # Adicionar opções personalizadas
        if opcoes:
            comando.extend(opcoes)
        
        return self._executar_varredura(comando, "varredura_personalizada")
    
    def varredura_multiplos_alvos(self, alvos: List[str], severidade: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura em múltiplos alvos
        Args:
            alvos (List[str]): Lista de URLs ou IPs
            severidade (str): Severidade mínima
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        # Criar arquivo temporário com alvos
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
            for alvo in alvos:
                temp_file.write(f"{alvo}\n")
            arquivo_alvos = temp_file.name
        
        comando = [
            self.binario_nuclei,
            '-list', arquivo_alvos,
            '-json',
            '-silent',
            '-c', str(self.threads_padrao),
            '-rl', str(self.rate_limit_padrao)
        ]
        
        if severidade:
            comando.extend(['-severity', severidade])
        
        try:
            resultado = self._executar_varredura(comando, "varredura_multiplos_alvos")
        finally:
            # Limpar arquivo temporário
            try:
                os.unlink(arquivo_alvos)
            except:
                pass
        
        return resultado
    
    def _executar_varredura(self, comando: List[str], tipo_varredura: str) -> Dict[str, Any]:
        """
        Executa comando Nuclei e processa resultados
        Args:
            comando (List[str]): Comando completo do Nuclei
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
            
            # Executar comando Nuclei
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
                # Processar saída JSON do Nuclei
                resultado['dados'] = self._processar_saida_nuclei(processo.stdout)
                resultado['sucesso'] = True
                self.logger.info(f"{tipo_varredura} concluída com sucesso")
            else:
                resultado['erro'] = f"Nuclei retornou código {processo.returncode}: {processo.stderr}"
                self.logger.error(resultado['erro'])
            
        except subprocess.TimeoutExpired:
            resultado['erro'] = f"Timeout na execução da varredura ({self.timeout_padrao}s)"
            self.logger.error(resultado['erro'])
        except Exception as e:
            resultado['erro'] = f"Erro na execução: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def _processar_saida_nuclei(self, saida: str) -> Dict[str, Any]:
        """
        Processa saída JSON do Nuclei
        Args:
            saida (str): Saída JSON do comando Nuclei
        Returns:
            Dict[str, Any]: Dados estruturados da varredura
        """
        dados = {
            'vulnerabilidades': [],
            'resumo': {
                'total_vulnerabilidades': 0,
                'severidades': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                },
                'templates_executados': set(),
                'alvos_testados': set()
            }
        }
        
        try:
            linhas = saida.strip().split('\n')
            
            for linha in linhas:
                linha = linha.strip()
                if not linha:
                    continue
                
                try:
                    # Cada linha é um JSON válido
                    vuln_data = json.loads(linha)
                    
                    # Extrair informações da vulnerabilidade
                    vulnerabilidade = {
                        'template_id': vuln_data.get('template-id', ''),
                        'template_name': vuln_data.get('info', {}).get('name', ''),
                        'severidade': vuln_data.get('info', {}).get('severity', 'info'),
                        'descricao': vuln_data.get('info', {}).get('description', ''),
                        'referencias': vuln_data.get('info', {}).get('reference', []),
                        'tags': vuln_data.get('info', {}).get('tags', []),
                        'alvo': vuln_data.get('host', ''),
                        'url_matched': vuln_data.get('matched-at', ''),
                        'timestamp': vuln_data.get('timestamp', ''),
                        'request': vuln_data.get('request', ''),
                        'response': vuln_data.get('response', ''),
                        'curl_command': vuln_data.get('curl-command', ''),
                        'extracted_results': vuln_data.get('extracted-results', [])
                    }
                    
                    dados['vulnerabilidades'].append(vulnerabilidade)
                    
                    # Atualizar resumo
                    severidade = vulnerabilidade['severidade'].lower()
                    if severidade in dados['resumo']['severidades']:
                        dados['resumo']['severidades'][severidade] += 1
                    
                    dados['resumo']['templates_executados'].add(vulnerabilidade['template_id'])
                    dados['resumo']['alvos_testados'].add(vulnerabilidade['alvo'])
                    
                except json.JSONDecodeError:
                    # Linha não é JSON válido, ignorar
                    continue
            
            # Finalizar resumo
            dados['resumo']['total_vulnerabilidades'] = len(dados['vulnerabilidades'])
            dados['resumo']['templates_executados'] = len(dados['resumo']['templates_executados'])
            dados['resumo']['alvos_testados'] = len(dados['resumo']['alvos_testados'])
            
        except Exception as e:
            self.logger.error(f"Erro ao processar saída Nuclei: {str(e)}")
        
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
        relatorio.append(f"RELATÓRIO NUCLEI - {resultados['tipo_varredura'].upper()}")
        relatorio.append("=" * 60)
        relatorio.append(f"Timestamp: {resultados['timestamp']}")
        relatorio.append(f"Comando: {resultados['comando']}")
        relatorio.append("")
        
        # Resumo
        relatorio.append("RESUMO:")
        relatorio.append(f"  Total de Vulnerabilidades: {resumo.get('total_vulnerabilidades', 0)}")
        relatorio.append(f"  Templates Executados: {resumo.get('templates_executados', 0)}")
        relatorio.append(f"  Alvos Testados: {resumo.get('alvos_testados', 0)}")
        relatorio.append("")
        
        # Severidades
        severidades = resumo.get('severidades', {})
        if any(severidades.values()):
            relatorio.append("DISTRIBUIÇÃO POR SEVERIDADE:")
            for sev, count in severidades.items():
                if count > 0:
                    relatorio.append(f"  {sev.upper()}: {count}")
            relatorio.append("")
        
        # Vulnerabilidades encontradas
        vulnerabilidades = dados.get('vulnerabilidades', [])
        if vulnerabilidades:
            relatorio.append("VULNERABILIDADES ENCONTRADAS:")
            
            # Agrupar por severidade
            por_severidade = {}
            for vuln in vulnerabilidades:
                sev = vuln['severidade'].upper()
                if sev not in por_severidade:
                    por_severidade[sev] = []
                por_severidade[sev].append(vuln)
            
            # Mostrar por ordem de severidade
            ordem_severidade = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            for sev in ordem_severidade:
                if sev in por_severidade:
                    relatorio.append(f"\n  {sev}:")
                    for vuln in por_severidade[sev][:5]:  # Máximo 5 por severidade
                        relatorio.append(f"    • {vuln['template_name']}")
                        relatorio.append(f"      Alvo: {vuln['alvo']}")
                        if vuln['url_matched']:
                            relatorio.append(f"      URL: {vuln['url_matched']}")
                        relatorio.append("")
        
        return "\n".join(relatorio)
    
    def obter_estatisticas_templates(self) -> Dict[str, Any]:
        """
        Obtém estatísticas dos templates disponíveis
        Returns:
            Dict[str, Any]: Estatísticas dos templates
        """
        try:
            comando = [self.binario_nuclei, '-stats']
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if resultado.returncode == 0:
                # Processar saída de estatísticas
                linhas = resultado.stdout.split('\n')
                stats = {}
                
                for linha in linhas:
                    if ':' in linha:
                        chave, valor = linha.split(':', 1)
                        stats[chave.strip()] = valor.strip()
                
                return {
                    'sucesso': True,
                    'estatisticas': stats,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {
                    'sucesso': False,
                    'erro': 'Erro ao obter estatísticas'
                }
                
        except Exception as e:
            return {
                'sucesso': False,
                'erro': f'Erro ao obter estatísticas: {str(e)}'
            }


if __name__ == "__main__":
    # Teste do módulo
    logger = obter_logger('VarreduraNucleiCLI')
    varredura = VarreduraNuclei()
    
    if varredura.verificar_nuclei():
        logger.info("Nuclei está disponível!")
        
        # Mostrar estatísticas
        stats = varredura.obter_estatisticas_templates()
        if stats['sucesso']:
            logger.info("\nEstatísticas dos Templates:")
            for chave, valor in stats['estatisticas'].items():
                logger.info(f"  {chave}: {valor}")
        
        # Exemplo de varredura
        alvo = input("\nDigite a URL para varredura: ").strip()
        if alvo:
            logger.info(f"Executando varredura básica em {alvo}...")
            resultado = varredura.varredura_basica(alvo, "medium")
            
            if resultado['sucesso']:
                logger.info("\nRelatório da Varredura:")
                logger.info(varredura.gerar_relatorio_resumido(resultado))
            else:
                logger.error(f"Erro na varredura: {resultado['erro']}")
    else:
        logger.error("Nuclei não está disponível. Instale o Nuclei para continuar.")
        logger.error("Instalação: https://github.com/projectdiscovery/nuclei")