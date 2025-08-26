#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de varredura Nikto
Realiza varreduras de vulnerabilidades web usando Nikto
"""

import os
import subprocess
import json
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
import tempfile
import re

from core.configuracao import obter_config
from utils.logger import obter_logger

class VarreduraNikto:
    """Classe para executar varreduras Nikto"""
    
    def __init__(self):
        """Inicializa o módulo de varredura Nikto"""
        self.logger = logging.getLogger(__name__)
        self.binario_nikto = obter_config('nikto.binario', 'nikto')
        self.timeout_padrao = obter_config('nikto.timeout_padrao', 1800)  # 30 minutos
        self.opcoes_padrao = obter_config('nikto.opcoes_padrao', ['-ask', 'no'])
        self.user_agent_padrao = obter_config('nikto.user_agent', 'Mozilla/5.0 (compatible; Nikto)')
        
        # Verificar se o Nikto está disponível
        self.verificar_nikto()
    
    def verificar_nikto(self) -> bool:
        """
        Verifica se o Nikto está instalado e acessível
        Returns:
            bool: True se Nikto está disponível, False caso contrário
        """
        try:
            resultado = subprocess.run(
                [self.binario_nikto, '-Version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                versao = resultado.stdout.strip()
                self.logger.info(f"Nikto encontrado: {versao}")
                return True
            else:
                self.logger.error("Nikto não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.error(f"Binário Nikto não encontrado: {self.binario_nikto}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout ao verificar versão do Nikto")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar Nikto: {str(e)}")
            return False
    
    def atualizar_base_dados(self) -> Dict[str, Any]:
        """
        Atualiza base de dados do Nikto
        Returns:
            Dict[str, Any]: Resultado da atualização
        """
        comando = [self.binario_nikto, '-update']
        
        resultado = {
            'sucesso': False,
            'timestamp': datetime.now().isoformat(),
            'comando': ' '.join(comando),
            'erro': None
        }
        
        try:
            self.logger.info("Atualizando base de dados do Nikto...")
            
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
                self.logger.info("Base de dados atualizada com sucesso")
            else:
                resultado['erro'] = f"Erro na atualização: {processo.stderr}"
                self.logger.error(resultado['erro'])
                
        except Exception as e:
            resultado['erro'] = f"Erro na atualização: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def listar_plugins(self) -> List[str]:
        """
        Lista plugins disponíveis do Nikto
        Returns:
            List[str]: Lista de plugins
        """
        try:
            comando = [self.binario_nikto, '-list-plugins']
            
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
                    if linha and not linha.startswith('-') and not linha.startswith('Plugin'):
                        plugins.append(linha)
            
            self.logger.info(f"Encontrados {len(plugins)} plugins")
            return plugins
            
        except Exception as e:
            self.logger.error(f"Erro ao listar plugins: {str(e)}")
            return []
    
    def varredura_basica(self, alvo: str, porta: Optional[int] = None, ssl: bool = False) -> Dict[str, Any]:
        """
        Executa varredura básica no alvo
        Args:
            alvo (str): URL ou IP do alvo
            porta (int): Porta específica para testar
            ssl (bool): Usar SSL/HTTPS
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nikto,
            '-host', alvo,
            '-ask', 'no',
            '-Format', 'xml'
        ]
        
        if porta:
            comando.extend(['-port', str(porta)])
        
        if ssl:
            comando.append('-ssl')
        
        return self._executar_varredura(comando, "varredura_basica")
    
    def varredura_completa(self, alvo: str, porta: Optional[int] = None, ssl: bool = False) -> Dict[str, Any]:
        """
        Executa varredura completa com todos os testes
        Args:
            alvo (str): URL ou IP do alvo
            porta (int): Porta específica
            ssl (bool): Usar SSL/HTTPS
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nikto,
            '-host', alvo,
            '-ask', 'no',
            '-Format', 'xml',
            '-Tuning', 'x'  # Todos os testes
        ]
        
        if porta:
            comando.extend(['-port', str(porta)])
        
        if ssl:
            comando.append('-ssl')
        
        return self._executar_varredura(comando, "varredura_completa")
    
    def varredura_cgi(self, alvo: str, porta: Optional[int] = None, ssl: bool = False) -> Dict[str, Any]:
        """
        Executa varredura focada em CGI
        Args:
            alvo (str): URL ou IP do alvo
            porta (int): Porta específica
            ssl (bool): Usar SSL/HTTPS
        Returns:
            Dict[str, Any]: Resultados da varredura CGI
        """
        comando = [
            self.binario_nikto,
            '-host', alvo,
            '-ask', 'no',
            '-Format', 'xml',
            '-Tuning', '8'  # CGI
        ]
        
        if porta:
            comando.extend(['-port', str(porta)])
        
        if ssl:
            comando.append('-ssl')
        
        return self._executar_varredura(comando, "varredura_cgi")
    
    def varredura_arquivos_interessantes(self, alvo: str, porta: Optional[int] = None, ssl: bool = False) -> Dict[str, Any]:
        """
        Executa varredura para arquivos interessantes
        Args:
            alvo (str): URL ou IP do alvo
            porta (int): Porta específica
            ssl (bool): Usar SSL/HTTPS
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nikto,
            '-host', alvo,
            '-ask', 'no',
            '-Format', 'xml',
            '-Tuning', '2'  # Arquivos interessantes
        ]
        
        if porta:
            comando.extend(['-port', str(porta)])
        
        if ssl:
            comando.append('-ssl')
        
        return self._executar_varredura(comando, "varredura_arquivos_interessantes")
    
    def varredura_configuracao_incorreta(self, alvo: str, porta: Optional[int] = None, ssl: bool = False) -> Dict[str, Any]:
        """
        Executa varredura para configurações incorretas
        Args:
            alvo (str): URL ou IP do alvo
            porta (int): Porta específica
            ssl (bool): Usar SSL/HTTPS
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nikto,
            '-host', alvo,
            '-ask', 'no',
            '-Format', 'xml',
            '-Tuning', '3'  # Configuração incorreta
        ]
        
        if porta:
            comando.extend(['-port', str(porta)])
        
        if ssl:
            comando.append('-ssl')
        
        return self._executar_varredura(comando, "varredura_configuracao_incorreta")
    
    def varredura_injecao(self, alvo: str, porta: Optional[int] = None, ssl: bool = False) -> Dict[str, Any]:
        """
        Executa varredura para vulnerabilidades de injeção
        Args:
            alvo (str): URL ou IP do alvo
            porta (int): Porta específica
            ssl (bool): Usar SSL/HTTPS
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nikto,
            '-host', alvo,
            '-ask', 'no',
            '-Format', 'xml',
            '-Tuning', '9'  # Injeção SQL
        ]
        
        if porta:
            comando.extend(['-port', str(porta)])
        
        if ssl:
            comando.append('-ssl')
        
        return self._executar_varredura(comando, "varredura_injecao")
    
    def varredura_personalizada(self, alvo: str, tuning: str, opcoes: Optional[List[str]] = None,
                               porta: Optional[int] = None, ssl: bool = False) -> Dict[str, Any]:
        """
        Executa varredura personalizada
        Args:
            alvo (str): URL ou IP do alvo
            tuning (str): Código de tuning do Nikto
            opcoes (List[str]): Opções adicionais
            porta (int): Porta específica
            ssl (bool): Usar SSL/HTTPS
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [
            self.binario_nikto,
            '-host', alvo,
            '-ask', 'no',
            '-Format', 'xml',
            '-Tuning', tuning
        ]
        
        if porta:
            comando.extend(['-port', str(porta)])
        
        if ssl:
            comando.append('-ssl')
        
        if opcoes:
            comando.extend(opcoes)
        
        return self._executar_varredura(comando, "varredura_personalizada")
    
    def varredura_multiplas_portas(self, alvo: str, portas: List[int], ssl: bool = False) -> Dict[str, Any]:
        """
        Executa varredura em múltiplas portas
        Args:
            alvo (str): URL ou IP do alvo
            portas (List[int]): Lista de portas
            ssl (bool): Usar SSL/HTTPS
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        portas_str = ','.join(map(str, portas))
        
        comando = [
            self.binario_nikto,
            '-host', alvo,
            '-port', portas_str,
            '-ask', 'no',
            '-Format', 'xml'
        ]
        
        if ssl:
            comando.append('-ssl')
        
        return self._executar_varredura(comando, "varredura_multiplas_portas")
    
    def _executar_varredura(self, comando: List[str], tipo_varredura: str) -> Dict[str, Any]:
        """
        Executa comando Nikto e processa resultados
        Args:
            comando (List[str]): Comando completo do Nikto
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
            # Criar arquivo temporário para saída XML
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
                arquivo_xml = temp_file.name
            
            # Adicionar saída XML ao comando
            comando_completo = comando + ['-output', arquivo_xml]
            
            self.logger.info(f"Executando {tipo_varredura}: {' '.join(comando_completo)}")
            
            # Executar comando Nikto
            processo = subprocess.run(
                comando_completo,
                capture_output=True,
                text=True,
                timeout=self.timeout_padrao
            )
            
            resultado['codigo_saida'] = processo.returncode
            resultado['saida_padrao'] = processo.stdout
            resultado['saida_erro'] = processo.stderr
            
            if processo.returncode == 0 or os.path.exists(arquivo_xml):
                # Processar saída XML
                resultado['dados'] = self._processar_xml_nikto(arquivo_xml)
                resultado['sucesso'] = True
                self.logger.info(f"{tipo_varredura} concluída com sucesso")
            else:
                resultado['erro'] = f"Nikto retornou código {processo.returncode}: {processo.stderr}"
                self.logger.error(resultado['erro'])
            
            # Limpar arquivo temporário
            try:
                os.unlink(arquivo_xml)
            except:
                pass
            
        except subprocess.TimeoutExpired:
            resultado['erro'] = f"Timeout na execução da varredura ({self.timeout_padrao}s)"
            self.logger.error(resultado['erro'])
        except Exception as e:
            resultado['erro'] = f"Erro na execução: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def _processar_xml_nikto(self, arquivo_xml: str) -> Dict[str, Any]:
        """
        Processa arquivo XML de saída do Nikto
        Args:
            arquivo_xml (str): Caminho para arquivo XML do Nikto
        Returns:
            Dict[str, Any]: Dados estruturados da varredura
        """
        dados = {
            'hosts': [],
            'resumo': {
                'total_vulnerabilidades': 0,
                'hosts_testados': 0,
                'tempo_execucao': '',
                'versao_nikto': ''
            }
        }
        
        try:
            if not os.path.exists(arquivo_xml) or os.path.getsize(arquivo_xml) == 0:
                self.logger.warning("Arquivo XML vazio ou inexistente")
                return dados
            
            tree = ET.parse(arquivo_xml)
            root = tree.getroot()
            
            # Informações gerais
            dados['resumo']['versao_nikto'] = root.get('version', '')
            
            # Processar hosts
            for scandetails in root.findall('scandetails'):
                host_info = self._processar_host_nikto(scandetails)
                if host_info:
                    dados['hosts'].append(host_info)
                    dados['resumo']['total_vulnerabilidades'] += len(host_info.get('vulnerabilidades', []))
            
            dados['resumo']['hosts_testados'] = len(dados['hosts'])
            
        except ET.ParseError as e:
            self.logger.error(f"Erro ao parsear XML: {str(e)}")
        except Exception as e:
            self.logger.error(f"Erro ao processar XML: {str(e)}")
        
        return dados
    
    def _processar_host_nikto(self, scandetails_elem) -> Dict[str, Any]:
        """
        Processa elemento de host do XML do Nikto
        Args:
            scandetails_elem: Elemento XML do host
        Returns:
            Dict[str, Any]: Informações do host
        """
        host_info = {
            'alvo': scandetails_elem.get('targetip', ''),
            'hostname': scandetails_elem.get('targethostname', ''),
            'porta': scandetails_elem.get('targetport', ''),
            'banner': scandetails_elem.get('targetbanner', ''),
            'inicio_scan': scandetails_elem.get('starttime', ''),
            'vulnerabilidades': [],
            'estatisticas': {
                'total_itens': 0,
                'por_categoria': {}
            }
        }
        
        # Processar vulnerabilidades
        for item in scandetails_elem.findall('item'):
            vulnerabilidade = {
                'id': item.get('id', ''),
                'osvdb': item.get('osvdb', ''),
                'metodo': item.get('method', ''),
                'uri': item.get('uri', ''),
                'descricao': item.text.strip() if item.text else '',
                'categoria': self._categorizar_vulnerabilidade(item.text or ''),
                'severidade': self._determinar_severidade_nikto(item.text or '')
            }
            
            host_info['vulnerabilidades'].append(vulnerabilidade)
            
            # Atualizar estatísticas
            categoria = vulnerabilidade['categoria']
            if categoria not in host_info['estatisticas']['por_categoria']:
                host_info['estatisticas']['por_categoria'][categoria] = 0
            host_info['estatisticas']['por_categoria'][categoria] += 1
        
        host_info['estatisticas']['total_itens'] = len(host_info['vulnerabilidades'])
        
        return host_info
    
    def _categorizar_vulnerabilidade(self, descricao: str) -> str:
        """
        Categoriza vulnerabilidade baseada na descrição
        Args:
            descricao (str): Descrição da vulnerabilidade
        Returns:
            str: Categoria da vulnerabilidade
        """
        descricao_lower = descricao.lower()
        
        if any(termo in descricao_lower for termo in ['sql', 'injection', 'sqli']):
            return 'SQL Injection'
        elif any(termo in descricao_lower for termo in ['xss', 'cross-site', 'script']):
            return 'Cross-Site Scripting'
        elif any(termo in descricao_lower for termo in ['directory', 'path', 'traversal']):
            return 'Directory Traversal'
        elif any(termo in descricao_lower for termo in ['file', 'disclosure', 'exposed']):
            return 'Information Disclosure'
        elif any(termo in descricao_lower for termo in ['admin', 'login', 'panel']):
            return 'Admin Interface'
        elif any(termo in descricao_lower for termo in ['backup', 'old', 'temp']):
            return 'Backup Files'
        elif any(termo in descricao_lower for termo in ['cgi', 'script']):
            return 'CGI'
        elif any(termo in descricao_lower for termo in ['config', 'configuration']):
            return 'Configuration'
        else:
            return 'Other'
    
    def _determinar_severidade_nikto(self, descricao: str) -> str:
        """
        Determina severidade baseada na descrição
        Args:
            descricao (str): Descrição da vulnerabilidade
        Returns:
            str: Severidade (Critical/High/Medium/Low/Info)
        """
        descricao_lower = descricao.lower()
        
        # Crítico
        if any(termo in descricao_lower for termo in ['remote code execution', 'rce', 'shell']):
            return 'Critical'
        
        # Alto
        elif any(termo in descricao_lower for termo in ['sql injection', 'authentication bypass', 'admin']):
            return 'High'
        
        # Médio
        elif any(termo in descricao_lower for termo in ['xss', 'directory traversal', 'file disclosure']):
            return 'Medium'
        
        # Baixo
        elif any(termo in descricao_lower for termo in ['information disclosure', 'version']):
            return 'Low'
        
        # Informativo
        else:
            return 'Info'
    
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
        relatorio.append(f"RELATÓRIO NIKTO - {resultados['tipo_varredura'].upper()}")
        relatorio.append("=" * 60)
        relatorio.append(f"Timestamp: {resultados['timestamp']}")
        relatorio.append(f"Comando: {resultados['comando']}")
        if resumo.get('versao_nikto'):
            relatorio.append(f"Versão Nikto: {resumo['versao_nikto']}")
        relatorio.append("")
        
        # Resumo
        relatorio.append("RESUMO:")
        relatorio.append(f"  Hosts Testados: {resumo.get('hosts_testados', 0)}")
        relatorio.append(f"  Total de Vulnerabilidades: {resumo.get('total_vulnerabilidades', 0)}")
        relatorio.append("")
        
        # Detalhes dos hosts
        for host in dados.get('hosts', []):
            relatorio.append(f"HOST: {host.get('alvo', 'N/A')}")
            if host.get('hostname'):
                relatorio.append(f"  Hostname: {host['hostname']}")
            relatorio.append(f"  Porta: {host.get('porta', 'N/A')}")
            if host.get('banner'):
                relatorio.append(f"  Banner: {host['banner']}")
            
            vulnerabilidades = host.get('vulnerabilidades', [])
            if vulnerabilidades:
                relatorio.append(f"  Vulnerabilidades Encontradas: {len(vulnerabilidades)}")
                
                # Agrupar por categoria
                categorias = host.get('estatisticas', {}).get('por_categoria', {})
                if categorias:
                    relatorio.append("  Por Categoria:")
                    for categoria, count in sorted(categorias.items()):
                        relatorio.append(f"    {categoria}: {count}")
                
                # Mostrar algumas vulnerabilidades críticas/altas
                vulns_importantes = [v for v in vulnerabilidades 
                                   if v.get('severidade') in ['Critical', 'High']]
                
                if vulns_importantes:
                    relatorio.append("  Vulnerabilidades Críticas/Altas:")
                    for vuln in vulns_importantes[:5]:  # Máximo 5
                        relatorio.append(f"    • {vuln.get('descricao', 'N/A')[:80]}...")
                        relatorio.append(f"      URI: {vuln.get('uri', 'N/A')}")
                        relatorio.append(f"      Severidade: {vuln.get('severidade', 'N/A')}")
                        relatorio.append("")
            
            relatorio.append("")
        
        return "\n".join(relatorio)
    
    def obter_opcoes_tuning(self) -> Dict[str, str]:
        """
        Retorna opções de tuning disponíveis
        Returns:
            Dict[str, str]: Dicionário com códigos e descrições
        """
        return {
            '0': 'File Upload',
            '1': 'Interesting File / Seen in logs',
            '2': 'Misconfiguration / Default File',
            '3': 'Information Disclosure',
            '4': 'Injection (XSS/Script/HTML)',
            '5': 'Remote File Retrieval - Inside Web Root',
            '6': 'Denial of Service',
            '7': 'Remote File Retrieval - Server Wide',
            '8': 'Command Execution / Remote Shell',
            '9': 'SQL Injection',
            'a': 'Authentication Bypass',
            'b': 'Software Identification',
            'c': 'Remote Source Inclusion',
            'x': 'Reverse Tuning Options (i.e., include all except specified)'
        }


if __name__ == "__main__":
    # Teste do módulo
    logger = obter_logger('VarreduraNiktoCLI')
    varredura = VarreduraNikto()
    
    if varredura.verificar_nikto():
        logger.info("Nikto está disponível!")
        
        # Mostrar opções de tuning
        logger.info("\nOpções de Tuning disponíveis:")
        opcoes = varredura.obter_opcoes_tuning()
        for codigo, descricao in opcoes.items():
            logger.info(f"  {codigo}: {descricao}")
        
        # Exemplo de varredura
        alvo = input("\nDigite a URL para varredura: ").strip()
        if alvo:
            logger.info(f"Executando varredura básica em {alvo}...")
            resultado = varredura.varredura_basica(alvo)
            
            if resultado['sucesso']:
                logger.info("\nRelatório da Varredura:")
                logger.info(varredura.gerar_relatorio_resumido(resultado))
            else:
                logger.error(f"Erro na varredura: {resultado['erro']}")
    else:
        logger.error("Nikto não está disponível. Instale o Nikto para continuar.")
        logger.error("Instalação Ubuntu/Debian: sudo apt-get install nikto")
        logger.error("Instalação manual: https://github.com/sullo/nikto")