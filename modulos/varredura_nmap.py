#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de varredura Nmap com suporte ao NSE (Nmap Scripting Engine)
Realiza varreduras de rede completas e análise de vulnerabilidades
"""

import os
import subprocess
import json
import xml.etree.ElementTree as ET
import yaml
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
import tempfile

from utils.logger import obter_logger

class VarreduraNmap:
    """Classe para executar varreduras Nmap com NSE"""
    
    def __init__(self):
        """Inicializa o módulo de varredura Nmap"""
        self.logger = obter_logger('VarreduraNmap')
        self.binario_nmap = 'nmap'
        self.timeout_padrao = 300
        self.scripts_nse_padrao = ['default']
        self.opcoes_padrao = ['-sV', '-sC']
        
        # Carregar configurações de timeout do arquivo YAML
        self._carregar_configuracoes_timeout()
        
        # Verificar se o Nmap está disponível
        self.verificar_nmap()
    
    def _carregar_configuracoes_timeout(self) -> None:
        """Carrega configurações de timeout do arquivo YAML"""
        config_path = Path(__file__).parent.parent / 'config' / 'nmap_timeouts.yaml'
        
        # Timeouts padrão (fallback)
        timeouts_padrao = {
            'varredura_basica': 300,
            'varredura_completa': 600,
            'varredura_vulnerabilidades': 900,
            'varredura_servicos_web': 600,
            'varredura_smb': 300,
            'descoberta_rede': 180,
            'varredura_personalizada': 600,
            'varredura_adaptativa': 450
        }
        
        # Configurações de performance padrão
        self.config_performance = {
            'max_hostgroup': 1,
            'max_parallelism_default': 10,
            'max_parallelism_vuln': 5,
            'max_parallelism_web': 5,
            'max_retries': 2,
            'timing_template': 3
        }
        
        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                
                # Carregar timeouts
                if 'timeouts' in config:
                    self.timeouts_especificos = {**timeouts_padrao, **config['timeouts']}
                else:
                    self.timeouts_especificos = timeouts_padrao
                
                # Carregar configurações de performance
                if 'performance' in config:
                    self.config_performance.update(config['performance'])
                
                # Carregar scripts otimizados
                self.scripts_otimizados = config.get('scripts_otimizados', {})
                
                self.logger.info(f"Configurações carregadas de {config_path}")
            else:
                self.timeouts_especificos = timeouts_padrao
                self.scripts_otimizados = {}
                self.logger.warning(f"Arquivo de configuração não encontrado: {config_path}. Usando valores padrão.")
                
        except Exception as e:
            self.timeouts_especificos = timeouts_padrao
            self.scripts_otimizados = {}
            self.logger.error(f"Erro ao carregar configurações: {str(e)}. Usando valores padrão.")
    
    def configurar_timeout(self, tipo_varredura: str, timeout: int) -> None:
        """
        Configura timeout personalizado para um tipo de varredura
        Args:
            tipo_varredura (str): Tipo da varredura
            timeout (int): Timeout em segundos
        """
        self.timeouts_especificos[tipo_varredura] = timeout
        self.logger.info(f"Timeout para {tipo_varredura} configurado para {timeout}s")
    
    def obter_timeout(self, tipo_varredura: str) -> int:
        """
        Obtém o timeout configurado para um tipo de varredura
        Args:
            tipo_varredura (str): Tipo da varredura
        Returns:
            int: Timeout em segundos
        """
        return self.timeouts_especificos.get(tipo_varredura, self.timeout_padrao)
    
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
                self.logger.error("Nmap não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.error(f"Binário Nmap não encontrado: {self.binario_nmap}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout ao verificar versão do Nmap")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar Nmap: {str(e)}")
            return False
    
    def listar_scripts_nse(self, categoria: Optional[str] = None) -> List[str]:
        """
        Lista scripts NSE disponíveis
        Args:
            categoria (str): Categoria de scripts (ex: 'vuln', 'discovery', 'auth')
        Returns:
            List[str]: Lista de scripts NSE
        """
        try:
            comando = [self.binario_nmap, '--script-help']
            if categoria:
                comando.append(categoria)
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            scripts = []
            if resultado.returncode == 0:
                linhas = resultado.stdout.split('\n')
                for linha in linhas:
                    if linha.strip() and not linha.startswith(' '):
                        script = linha.strip()
                        if '.' in script and script.endswith('.nse'):
                            scripts.append(script)
            
            self.logger.info(f"Encontrados {len(scripts)} scripts NSE")
            return scripts
            
        except Exception as e:
            self.logger.error(f"Erro ao listar scripts NSE: {str(e)}")
            return []
    
    def varredura_basica(self, alvo: str, portas: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura básica no alvo
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            portas (str): Especificação de portas (ex: '1-1000', '80,443,22')
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        if portas is None:
            portas = '1-1000'
        
        comando = [
            self.binario_nmap,
            '-p', portas,
            '-sT',  # TCP connect scan (não precisa de root)
            '--open',  # Apenas portas abertas
            alvo
        ]
        
        return self._executar_varredura(comando, "varredura_basica")
    
    def varredura_completa(self, alvo: str, portas: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura completa com detecção de versão e OS
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            portas (str): Especificação de portas
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        if portas is None:
            # Usar top ports para acelerar a varredura
            portas = '--top-ports=1000'
        else:
            portas = f'-p {portas}'
        
        comando = [
            self.binario_nmap,
            portas,
            '-sV',  # Detecção de versão
            '-sC',  # Scripts padrão (removido -O que precisa root)
            '--open',
            '--max-hostgroup', '1',  # Um host por vez
            '--max-parallelism', '20',  # Paralelismo moderado
            alvo
        ]
        
        # Ajustar comando para portas específicas
        if portas.startswith('-p'):
            comando[1] = portas
        else:
            comando[1] = portas
        
        return self._executar_varredura(comando, "varredura_completa")
    
    def varredura_vulnerabilidades(self, alvo: str, portas: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura focada em vulnerabilidades usando NSE
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            portas (str): Especificação de portas
        Returns:
            Dict[str, Any]: Resultados da varredura de vulnerabilidades
        """
        if portas is None:
            # Usar apenas portas mais comuns para acelerar a varredura
            portas = '22,53,80,443,135,139,445,993,995,1723,3306,3389,5432,5900'
        
        # Usar scripts otimizados se disponíveis
        scripts = self.scripts_otimizados.get('vulnerabilidades', ['vuln'])
        scripts_str = ','.join(scripts)
        
        comando = [
            self.binario_nmap,
            '-p', portas,
            '-sV',
            '--script', scripts_str,
            '--script-args', 'unsafe=1',
            '--max-hostgroup', str(self.config_performance['max_hostgroup']),
            '--max-parallelism', str(self.config_performance['max_parallelism_vuln']),
            '--max-retries', str(self.config_performance['max_retries']),
            '-T', str(self.config_performance['timing_template']),
            alvo
        ]
        
        return self._executar_varredura(comando, "varredura_vulnerabilidades")
    
    def varredura_personalizada(self, alvo: str, opcoes: List[str], scripts_nse: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Executa varredura personalizada com opções específicas
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            opcoes (List[str]): Lista de opções do Nmap
            scripts_nse (List[str]): Lista de scripts NSE específicos
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        comando = [self.binario_nmap] + opcoes
        
        if scripts_nse:
            comando.extend(['--script', ','.join(scripts_nse)])
        
        comando.append(alvo)
        
        return self._executar_varredura(comando, "varredura_personalizada")
    
    def varredura_descoberta_rede(self, rede: str) -> Dict[str, Any]:
        """
        Executa descoberta de hosts na rede
        Args:
            rede (str): Rede em notação CIDR (ex: '192.168.1.0/24')
        Returns:
            Dict[str, Any]: Hosts descobertos na rede
        """
        comando = [
            self.binario_nmap,
            '-sn',  # Ping scan
            '--script', 'discovery',
            rede
        ]
        
        return self._executar_varredura(comando, "descoberta_rede")
    
    def varredura_servicos_web(self, alvo: str) -> Dict[str, Any]:
        """
        Executa varredura focada em serviços web
        Args:
            alvo (str): Endereço IP ou hostname do alvo
        Returns:
            Dict[str, Any]: Resultados da varredura de serviços web
        """
        # Usar scripts otimizados se disponíveis
        scripts = self.scripts_otimizados.get('servicos_web', 
                                             ['http-enum', 'http-headers', 'http-methods', 'http-title'])
        scripts_str = ','.join(scripts)
        
        comando = [
            self.binario_nmap,
            '-p', '80,443,8080,8443,8000,8888,3000,5000',
            '-sV',
            '--script', scripts_str,
            '--max-hostgroup', str(self.config_performance['max_hostgroup']),
            '--max-parallelism', str(self.config_performance['max_parallelism_web']),
            '--max-retries', str(self.config_performance['max_retries']),
            '-T', str(self.config_performance['timing_template']),
            alvo
        ]
        
        return self._executar_varredura(comando, "varredura_servicos_web")
    
    def varredura_smb(self, alvo: str) -> Dict[str, Any]:
        """
        Executa varredura focada em serviços SMB
        Args:
            alvo (str): Endereço IP ou hostname do alvo
        Returns:
            Dict[str, Any]: Resultados da varredura SMB
        """
        # Usar scripts otimizados se disponíveis
        scripts = self.scripts_otimizados.get('smb', ['smb-*'])
        scripts_str = ','.join(scripts)
        
        comando = [
            self.binario_nmap,
            '-p', '139,445',
            '-sV',
            '--script', scripts_str,
            '--max-hostgroup', str(self.config_performance['max_hostgroup']),
            '--max-parallelism', str(self.config_performance['max_parallelism_default']),
            '--max-retries', str(self.config_performance['max_retries']),
            '-T', str(self.config_performance['timing_template']),
            alvo
        ]
        
        return self._executar_varredura(comando, "varredura_smb")
    
    def varredura_rapida_vulnerabilidades(self, alvo: str, portas_conhecidas: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Executa varredura rápida de vulnerabilidades apenas em portas conhecidas abertas
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            portas_conhecidas (List[int]): Lista de portas conhecidas abertas
        Returns:
            Dict[str, Any]: Resultados da varredura de vulnerabilidades
        """
        if portas_conhecidas:
            portas = ','.join(map(str, portas_conhecidas))
        else:
            # Usar apenas as portas mais críticas
            portas = '22,80,443,445,3389'
        
        comando = [
            self.binario_nmap,
            '-p', portas,
            '-sV',
            '--script', 'vuln',
            '--script-args', 'unsafe=1',
            '--max-hostgroup', '1',
            '--max-parallelism', '5',  # Paralelismo baixo para estabilidade
            '--max-retries', '1',       # Menos tentativas
            alvo
        ]
        
        return self._executar_varredura(comando, "varredura_vulnerabilidades")
    
    def varredura_adaptativa(self, alvo: str, portas_abertas: List[int], timeout_personalizado: Optional[int] = None) -> Dict[str, Any]:
        """
        Executa varredura adaptativa baseada nas portas já conhecidas
        Args:
            alvo (str): Endereço IP ou hostname do alvo
            portas_abertas (List[int]): Lista de portas abertas conhecidas
            timeout_personalizado (int): Timeout personalizado em segundos
        Returns:
            Dict[str, Any]: Resultados da varredura adaptativa
        """
        if not portas_abertas:
            self.logger.warning("Nenhuma porta aberta fornecida para varredura adaptativa")
            return {
                'sucesso': False,
                'erro': 'Nenhuma porta aberta fornecida',
                'tipo_varredura': 'varredura_adaptativa',
                'timestamp': datetime.now().isoformat()
            }
        
        # Configurar timeout se fornecido
        if timeout_personalizado:
            self.configurar_timeout('varredura_adaptativa', timeout_personalizado)
        
        portas_str = ','.join(map(str, portas_abertas))
        
        # Determinar scripts baseados nas portas
        scripts = []
        if any(p in portas_abertas for p in [80, 443, 8080, 8443]):
            scripts.append('http-enum')
        if any(p in portas_abertas for p in [139, 445]):
            scripts.append('smb-enum-shares')
        if 22 in portas_abertas:
            scripts.append('ssh-auth-methods')
        
        # Se não há scripts específicos, usar detecção básica
        if not scripts:
            scripts = ['version']
        
        comando = [
            self.binario_nmap,
            '-p', portas_str,
            '-sV',
            '--script', ','.join(scripts),
            '--max-hostgroup', '1',
            '--max-parallelism', '10',
            alvo
        ]
        
        return self._executar_varredura(comando, "varredura_adaptativa")
    
    def diagnosticar_xml_nmap(self, arquivo_xml: str) -> Dict[str, Any]:
        """
        Diagnostica problemas com arquivos XML do Nmap
        Args:
            arquivo_xml (str): Caminho para o arquivo XML
        Returns:
            Dict[str, Any]: Diagnóstico detalhado
        """
        diagnostico = {
            'arquivo_existe': False,
            'tamanho_bytes': 0,
            'conteudo_vazio': True,
            'xml_valido': False,
            'nmap_valido': False,
            'problemas': [],
            'sugestoes': []
        }
        
        try:
            # Verificar se o arquivo existe
            if os.path.exists(arquivo_xml):
                diagnostico['arquivo_existe'] = True
                
                # Verificar tamanho
                tamanho = os.path.getsize(arquivo_xml)
                diagnostico['tamanho_bytes'] = tamanho
                
                if tamanho == 0:
                    diagnostico['problemas'].append("Arquivo XML está vazio")
                    diagnostico['sugestoes'].append("Verificar se o Nmap teve permissões para escrever")
                    diagnostico['sugestoes'].append("Verificar se o disco não está cheio")
                else:
                    diagnostico['conteudo_vazio'] = False
                    
                    # Ler conteúdo
                    with open(arquivo_xml, 'r', encoding='utf-8') as f:
                        conteudo = f.read()
                    
                    # Verificar se é XML válido
                    try:
                        import xml.etree.ElementTree as ET
                        tree = ET.parse(arquivo_xml)
                        root = tree.getroot()
                        diagnostico['xml_valido'] = True
                        
                        # Verificar se é do Nmap
                        if root.tag == 'nmaprun':
                            diagnostico['nmap_valido'] = True
                        else:
                            diagnostico['problemas'].append(f"XML não é do Nmap (tag raiz: {root.tag})")
                            
                    except ET.ParseError as e:
                        diagnostico['problemas'].append(f"XML mal formado: {str(e)}")
                        diagnostico['sugestoes'].append("Verificar se o Nmap foi interrompido durante execução")
                        
                        # Mostrar início do conteúdo para debug
                        if len(conteudo) > 0:
                            inicio = conteudo[:200]
                            diagnostico['inicio_conteudo'] = inicio
                            
                            if not inicio.strip().startswith('<?xml'):
                                diagnostico['problemas'].append("Conteúdo não começa com declaração XML")
                                
            else:
                diagnostico['problemas'].append("Arquivo XML não foi criado")
                diagnostico['sugestoes'].extend([
                    "Verificar se o Nmap está instalado corretamente",
                    "Verificar permissões de escrita no diretório temporário",
                    "Verificar se o comando Nmap está correto"
                ])
        
        except Exception as e:
            diagnostico['problemas'].append(f"Erro ao diagnosticar: {str(e)}")
        
        return diagnostico
    
    def testar_nmap_xml(self, alvo: str = '127.0.0.1') -> Dict[str, Any]:
        """
        Testa a geração de XML do Nmap com comando simples
        Args:
            alvo (str): Alvo para teste
        Returns:
            Dict[str, Any]: Resultado do teste
        """
        self.logger.info(f"Testando geração de XML do Nmap para {alvo}")
        
        # Comando muito simples para teste
        comando = [
            self.binario_nmap,
            '-p', '80',
            '-sT',  # TCP connect (não precisa root)
            '--open',
            alvo
        ]
        
        resultado_teste = self._executar_varredura(comando, "teste_xml")
        
        if not resultado_teste.get('sucesso'):
            # Diagnosticar o problema
            arquivo_xml = resultado_teste.get('arquivo_xml')
            if arquivo_xml:
                diagnostico = self.diagnosticar_xml_nmap(arquivo_xml)
                resultado_teste['diagnostico_xml'] = diagnostico
        
        return resultado_teste
    
    def diagnosticar_timeout(self, resultado_varredura: Dict[str, Any]) -> Dict[str, Any]:
        """
        Diagnostica problemas de timeout e sugere otimizações
        Args:
            resultado_varredura (Dict): Resultado de uma varredura que teve timeout
        Returns:
            Dict[str, Any]: Diagnóstico e sugestões
        """
        diagnostico = {
            'teve_timeout': False,
            'tipo_varredura': resultado_varredura.get('tipo_varredura', 'desconhecido'),
            'timeout_usado': resultado_varredura.get('timeout_usado', 0),
            'sugestoes': [],
            'novos_timeouts_sugeridos': {},
            'otimizacoes_comando': []
        }
        
        # Verificar se teve timeout
        erro = resultado_varredura.get('erro', '')
        if 'Timeout' in erro or 'timeout' in erro.lower():
            diagnostico['teve_timeout'] = True
            
            tipo_varredura = diagnostico['tipo_varredura']
            timeout_atual = diagnostico['timeout_usado']
            
            # Sugerir aumento de timeout
            novo_timeout = min(timeout_atual * 1.5, 1800)  # Máximo de 30 minutos
            diagnostico['novos_timeouts_sugeridos'][tipo_varredura] = int(novo_timeout)
            
            # Sugestões específicas por tipo de varredura
            if tipo_varredura == 'varredura_vulnerabilidades':
                diagnostico['sugestoes'].extend([
                    'Considere usar varredura_rapida_vulnerabilidades() para portas específicas',
                    'Reduza o número de portas alvo usando --top-ports',
                    'Execute a varredura em horários de menor carga de rede',
                    'Use --max-parallelism menor (ex: 3-5) para reduzir carga'
                ])
                diagnostico['otimizacoes_comando'].extend([
                    '--max-parallelism 3',
                    '--max-retries 1',
                    '--host-timeout 600s'
                ])
            
            elif tipo_varredura == 'varredura_servicos_web':
                diagnostico['sugestoes'].extend([
                    'Use scripts HTTP específicos em vez de http-*',
                    'Teste conectividade HTTP manual antes da varredura',
                    'Considere varredura em portas web uma por vez',
                    'Verifique se o servidor web está respondendo'
                ])
                diagnostico['otimizacoes_comando'].extend([
                    '--script http-enum,http-title',
                    '--max-parallelism 3',
                    '--script-timeout 30s'
                ])
            
            elif tipo_varredura == 'varredura_completa':
                diagnostico['sugestoes'].extend([
                    'Use --top-ports=1000 em vez de todas as portas',
                    'Execute varredura básica primeiro para identificar portas abertas',
                    'Use timing template T2 para redes lentas',
                    'Considere dividir a varredura em etapas'
                ])
                diagnostico['otimizacoes_comando'].extend([
                    '--top-ports=1000',
                    '-T2',
                    '--max-parallelism 10'
                ])
            
            # Sugestões gerais
            diagnostico['sugestoes'].extend([
                f'Aumente o timeout para {novo_timeout}s',
                'Verifique a conectividade de rede com ping',
                'Execute a varredura em horários de menor tráfego',
                'Considere usar varredura_adaptativa() com portas conhecidas'
            ])
        
        return diagnostico
    
    def aplicar_otimizacoes_timeout(self, diagnostico: Dict[str, Any]) -> None:
        """
        Aplica otimizações de timeout baseadas no diagnóstico
        Args:
            diagnostico (Dict): Resultado do diagnóstico de timeout
        """
        if diagnostico.get('teve_timeout') and diagnostico.get('novos_timeouts_sugeridos'):
            for tipo_varredura, novo_timeout in diagnostico['novos_timeouts_sugeridos'].items():
                self.configurar_timeout(tipo_varredura, novo_timeout)
                self.logger.info(f"Timeout otimizado para {tipo_varredura}: {novo_timeout}s")
    
    def executar_varredura_com_retry(self, metodo_varredura, alvo: str, 
                                   max_tentativas: int = 2, **kwargs) -> Dict[str, Any]:
        """
        Executa varredura com retry automático em caso de timeout
        Args:
            metodo_varredura: Método de varredura a ser executado
            alvo (str): Alvo da varredura
            max_tentativas (int): Número máximo de tentativas
            **kwargs: Argumentos adicionais para o método de varredura
        Returns:
            Dict[str, Any]: Resultado da varredura
        """
        ultima_tentativa = None
        
        for tentativa in range(max_tentativas):
            self.logger.info(f"Tentativa {tentativa + 1}/{max_tentativas} para {metodo_varredura.__name__}")
            
            resultado = metodo_varredura(alvo, **kwargs)
            
            if resultado.get('sucesso'):
                if tentativa > 0:
                    self.logger.info(f"Varredura bem-sucedida na tentativa {tentativa + 1}")
                return resultado
            
            ultima_tentativa = resultado
            
            # Se houve timeout, aplicar otimizações para próxima tentativa
            if 'timeout' in resultado.get('erro', '').lower():
                diagnostico = self.diagnosticar_timeout(resultado)
                self.aplicar_otimizacoes_timeout(diagnostico)
                
                self.logger.warning(f"Timeout na tentativa {tentativa + 1}, aplicando otimizações...")
        
        # Se chegou aqui, todas as tentativas falharam
        self.logger.error(f"Todas as {max_tentativas} tentativas falharam")
        return ultima_tentativa or {
            'sucesso': False,
            'erro': f'Falha após {max_tentativas} tentativas',
            'timestamp': datetime.now().isoformat()
        }
    
    def _executar_varredura(self, comando: List[str], tipo_varredura: str) -> Dict[str, Any]:
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
        
        # Obter timeout específico para o tipo de varredura
        timeout_varredura = self.timeouts_especificos.get(tipo_varredura, self.timeout_padrao)
        arquivo_xml = None
        
        try:
            # Criar arquivo temporário para saída XML no diretório do projeto
            # para evitar problemas de permissão com snap do Nmap
            projeto_dir = Path(__file__).parent.parent
            temp_dir = projeto_dir / 'temp'
            temp_dir.mkdir(exist_ok=True)
            
            # Criar arquivo temporário no diretório do projeto
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            arquivo_xml = temp_dir / f'nmap_{tipo_varredura}_{timestamp}.xml'
            
            # Adicionar saída XML ao comando
            comando_completo = comando + ['-oX', str(arquivo_xml)]
            
            self.logger.info(f"Executando {tipo_varredura}: {' '.join(comando_completo)}")
            self.logger.info(f"Timeout configurado: {timeout_varredura}s")
            self.logger.debug(f"Arquivo XML de saída: {arquivo_xml}")
            
            # Executar comando Nmap
            processo = subprocess.run(
                comando_completo,
                capture_output=True,
                text=True,
                timeout=timeout_varredura
            )
            
            resultado['codigo_saida'] = processo.returncode
            resultado['saida_padrao'] = processo.stdout
            resultado['saida_erro'] = processo.stderr
            resultado['timeout_usado'] = timeout_varredura
            resultado['arquivo_xml'] = str(arquivo_xml)
            
            # Log da saída para debug
            if processo.stdout:
                self.logger.debug(f"STDOUT: {processo.stdout[:200]}...")
            if processo.stderr:
                self.logger.debug(f"STDERR: {processo.stderr[:200]}...")
            
            # Verificar se o comando foi executado com sucesso
            if processo.returncode == 0:
                # Aguardar um momento para o arquivo ser escrito completamente
                import time
                time.sleep(0.1)
                
                # Verificar se o arquivo XML foi criado
                if arquivo_xml.exists():
                    tamanho = arquivo_xml.stat().st_size
                    self.logger.debug(f"Arquivo XML criado: {tamanho} bytes")
                    
                    if tamanho > 0:
                        # Processar saída XML
                        resultado['dados'] = self._processar_xml_nmap(str(arquivo_xml))
                        resultado['sucesso'] = True
                        self.logger.info(f"{tipo_varredura} concluída com sucesso")
                    else:
                        self.logger.warning(f"Arquivo XML está vazio: {arquivo_xml}")
                        # Mesmo assim, considerar sucesso se o código de saída foi 0
                        resultado['sucesso'] = True
                        resultado['aviso'] = "Nmap executou com sucesso mas não gerou saída XML"
                else:
                    self.logger.error(f"Arquivo XML não foi criado: {arquivo_xml}")
                    resultado['erro'] = "Nmap não gerou arquivo XML de saída"
                    
            else:
                resultado['erro'] = f"Nmap retornou código {processo.returncode}"
                if processo.stderr:
                    resultado['erro'] += f": {processo.stderr}"
                self.logger.error(resultado['erro'])
            
        except subprocess.TimeoutExpired:
            resultado['erro'] = f"Timeout na execução da varredura ({timeout_varredura}s)"
            resultado['timeout_usado'] = timeout_varredura
            self.logger.error(resultado['erro'])
            
        except Exception as e:
            resultado['erro'] = f"Erro na execução: {str(e)}"
            self.logger.error(resultado['erro'])
        
        finally:
            # Limpar arquivo temporário apenas se não estamos em modo debug
            if arquivo_xml and arquivo_xml.exists():
                try:
                    # Preservar arquivo se houve erro para debug
                    if resultado.get('sucesso', False) or not self.logger.isEnabledFor(10):  # 10 = DEBUG
                        arquivo_xml.unlink()
                    else:
                        self.logger.debug(f"Arquivo XML preservado para debug: {arquivo_xml}")
                except Exception as e:
                    self.logger.warning(f"Erro ao limpar arquivo temporário: {e}")
        
        return resultado
    
    def _processar_xml_nmap(self, arquivo_xml: str) -> Dict[str, Any]:
        """
        Processa arquivo XML de saída do Nmap
        Args:
            arquivo_xml (str): Caminho para arquivo XML do Nmap
        Returns:
            Dict[str, Any]: Dados estruturados da varredura
        """
        dados = {
            'hosts': [],
            'resumo': {
                'hosts_total': 0,
                'hosts_ativos': 0,
                'portas_abertas': 0,
                'servicos_detectados': 0,
                'vulnerabilidades': 0
            }
        }
        
        try:
            # Verificar se o arquivo existe e não está vazio
            if not os.path.exists(arquivo_xml):
                self.logger.error(f"Arquivo XML não encontrado: {arquivo_xml}")
                return dados
            
            # Verificar tamanho do arquivo
            tamanho_arquivo = os.path.getsize(arquivo_xml)
            if tamanho_arquivo == 0:
                self.logger.error(f"Arquivo XML está vazio: {arquivo_xml}")
                return dados
            
            # Log para debug
            self.logger.debug(f"Processando XML: {arquivo_xml} ({tamanho_arquivo} bytes)")
            
            # Tentar ler o conteúdo do arquivo primeiro
            with open(arquivo_xml, 'r', encoding='utf-8') as f:
                conteudo = f.read().strip()
                
            if not conteudo:
                self.logger.error(f"Arquivo XML contém apenas espaços em branco: {arquivo_xml}")
                return dados
            
            # Verificar se parece com XML válido
            if not conteudo.startswith('<?xml') and not conteudo.startswith('<nmaprun'):
                self.logger.error(f"Arquivo não parece ser XML válido do Nmap: {arquivo_xml}")
                self.logger.debug(f"Primeiros 200 caracteres: {conteudo[:200]}")
                return dados
            
            # Tentar fazer o parse do XML
            tree = ET.parse(arquivo_xml)
            root = tree.getroot()
            
            # Verificar se é uma saída válida do Nmap
            if root.tag != 'nmaprun':
                self.logger.error(f"XML não é uma saída válida do Nmap. Tag raiz: {root.tag}")
                return dados
            
            # Processar hosts
            for host in root.findall('host'):
                host_info = self._processar_host_xml(host)
                if host_info:
                    dados['hosts'].append(host_info)
                    dados['resumo']['hosts_ativos'] += 1
                    dados['resumo']['portas_abertas'] += len(host_info.get('portas', []))
            
            dados['resumo']['hosts_total'] = len(dados['hosts'])
            
            # Contar serviços únicos
            servicos = set()
            vulnerabilidades = 0
            
            for host in dados['hosts']:
                for porta in host.get('portas', []):
                    if porta.get('servico'):
                        servicos.add(porta['servico'])
                
                # Contar vulnerabilidades nos scripts
                for script in host.get('scripts', []):
                    if 'vuln' in script.get('id', '').lower():
                        vulnerabilidades += 1
            
            dados['resumo']['servicos_detectados'] = len(servicos) if hasattr(servicos, '__len__') else (servicos if isinstance(servicos, int) else 1)
            dados['resumo']['vulnerabilidades'] = vulnerabilidades
            
        except ET.ParseError as e:
            self.logger.error(f"Erro de parsing XML: {str(e)}")
            self.logger.error(f"Arquivo: {arquivo_xml}")
            
            # Tentar mostrar o conteúdo problemático
            try:
                with open(arquivo_xml, 'r', encoding='utf-8') as f:
                    conteudo = f.read()
                self.logger.debug(f"Conteúdo do arquivo XML problemático ({len(conteudo)} chars):")
                self.logger.debug(conteudo[:500] if len(conteudo) > 500 else conteudo)
            except Exception:
                pass
                
        except Exception as e:
            self.logger.error(f"Erro ao processar XML: {str(e)}")
            self.logger.error(f"Arquivo: {arquivo_xml}")
        
        return dados
        
        return dados
    
    def _processar_host_xml(self, host_elem) -> Dict[str, Any]:
        """
        Processa elemento de host do XML
        Args:
            host_elem: Elemento XML do host
        Returns:
            Dict[str, Any]: Informações do host
        """
        host_info = {
            'endereco': '',
            'hostname': '',
            'status': '',
            'os': {},
            'portas': [],
            'scripts': []
        }
        
        # Endereço IP
        address = host_elem.find('address[@addrtype="ipv4"]')
        if address is not None:
            host_info['endereco'] = address.get('addr', '')
        
        # Hostname
        hostname = host_elem.find('hostnames/hostname')
        if hostname is not None:
            host_info['hostname'] = hostname.get('name', '')
        
        # Status do host
        status = host_elem.find('status')
        if status is not None:
            host_info['status'] = status.get('state', '')
        
        # Sistema operacional
        os_elem = host_elem.find('os')
        if os_elem is not None:
            osmatch = os_elem.find('osmatch')
            if osmatch is not None:
                host_info['os'] = {
                    'nome': osmatch.get('name', ''),
                    'precisao': osmatch.get('accuracy', ''),
                    'familia': ''
                }
                
                osclass = osmatch.find('osclass')
                if osclass is not None:
                    host_info['os']['familia'] = osclass.get('osfamily', '')
        
        # Portas
        ports = host_elem.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                porta_info = self._processar_porta_xml(port)
                if porta_info:
                    host_info['portas'].append(porta_info)
        
        # Scripts de host
        hostscript = host_elem.find('hostscript')
        if hostscript is not None:
            for script in hostscript.findall('script'):
                script_info = self._processar_script_xml(script)
                if script_info:
                    host_info['scripts'].append(script_info)
        
        return host_info
    
    def _processar_porta_xml(self, port_elem) -> Dict[str, Any]:
        """
        Processa elemento de porta do XML
        Args:
            port_elem: Elemento XML da porta
        Returns:
            Dict[str, Any]: Informações da porta
        """
        porta_info = {
            'numero': int(port_elem.get('portid', 0)),
            'protocolo': port_elem.get('protocol', ''),
            'estado': '',
            'servico': '',
            'versao': '',
            'produto': '',
            'scripts': []
        }
        
        # Estado da porta
        state = port_elem.find('state')
        if state is not None:
            porta_info['estado'] = state.get('state', '')
        
        # Informações do serviço
        service = port_elem.find('service')
        if service is not None:
            porta_info['servico'] = service.get('name', '')
            porta_info['produto'] = service.get('product', '')
            porta_info['versao'] = service.get('version', '')
        
        # Scripts da porta
        for script in port_elem.findall('script'):
            script_info = self._processar_script_xml(script)
            if script_info:
                porta_info['scripts'].append(script_info)
        
        return porta_info
    
    def _processar_script_xml(self, script_elem) -> Dict[str, Any]:
        """
        Processa elemento de script NSE do XML
        Args:
            script_elem: Elemento XML do script
        Returns:
            Dict[str, Any]: Informações do script
        """
        script_info = {
            'id': script_elem.get('id', ''),
            'saida': script_elem.get('output', ''),
            'elementos': []
        }
        
        # Processar elementos estruturados do script
        for elem in script_elem.findall('.//elem'):
            elemento = {
                'chave': elem.get('key', ''),
                'valor': elem.text or ''
            }
            script_info['elementos'].append(elemento)
        
        return script_info
    
    def gerar_resumo(self, resultados: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera resumo dos resultados de varredura Nmap
        Args:
            resultados (Dict): Resultado da varredura Nmap
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
            'servicos_detectados': resumo_dados.get('servicos_detectados', 0),
            'vulnerabilidades': resumo_dados.get('vulnerabilidades', 0)
        }
        
        # Adicionar detalhes dos hosts
        hosts_detalhes = []
        for host in dados.get('hosts', []):
            host_info = {
                'endereco': host.get('endereco'),
                'hostname': host.get('hostname'),
                'status': host.get('status'),
                'os': host.get('os', {}),
                'total_portas': len(host.get('portas', [])),
                'portas_abertas': [p['numero'] for p in host.get('portas', []) if p.get('estado') == 'open'],
                'servicos': [p['servico'] for p in host.get('portas', []) if p.get('servico')],
                'vulnerabilidades_encontradas': len([s for s in host.get('scripts', []) if 'vuln' in s.get('id', '').lower()])
            }
            hosts_detalhes.append(host_info)
        
        resumo['hosts_detalhes'] = hosts_detalhes
        
        return resumo
    
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
        relatorio.append(f"RELATÓRIO DE VARREDURA - {resultados['tipo_varredura'].upper()}")
        relatorio.append("=" * 60)
        relatorio.append(f"Timestamp: {resultados['timestamp']}")
        relatorio.append(f"Comando: {resultados['comando']}")
        relatorio.append("")
        
        # Resumo
        relatorio.append("RESUMO:")
        relatorio.append(f"  Hosts Total: {resumo.get('hosts_total', 0)}")
        relatorio.append(f"  Hosts Ativos: {resumo.get('hosts_ativos', 0)}")
        relatorio.append(f"  Portas Abertas: {resumo.get('portas_abertas', 0)}")
        relatorio.append(f"  Serviços Detectados: {resumo.get('servicos_detectados', 0)}")
        relatorio.append(f"  Vulnerabilidades: {resumo.get('vulnerabilidades', 0)}")
        relatorio.append("")
        
        # Detalhes dos hosts
        for host in dados.get('hosts', []):
            relatorio.append(f"HOST: {host.get('endereco', 'N/A')}")
            if host.get('hostname'):
                relatorio.append(f"  Hostname: {host['hostname']}")
            relatorio.append(f"  Status: {host.get('status', 'N/A')}")
            
            if host.get('os', {}).get('nome'):
                relatorio.append(f"  OS: {host['os']['nome']} ({host['os'].get('precisao', 'N/A')}% precisão)")
            
            # Portas abertas
            portas_abertas = [p for p in host.get('portas', []) if p.get('estado') == 'open']
            if portas_abertas:
                relatorio.append(f"  Portas Abertas ({len(portas_abertas)}):")
                for porta in portas_abertas:
                    servico = porta.get('servico', 'unknown')
                    produto = porta.get('produto', '')
                    versao = porta.get('versao', '')
                    info_servico = f"{servico}"
                    if produto:
                        info_servico += f" ({produto}"
                        if versao:
                            info_servico += f" {versao}"
                        info_servico += ")"
                    
                    relatorio.append(f"    {porta['numero']}/{porta['protocolo']} - {info_servico}")
            
            relatorio.append("")
        
        return "\n".join(relatorio)


if __name__ == "__main__":
    # Teste do módulo
    logger = obter_logger('VarreduraNmapCLI')
    varredura = VarreduraNmap()
    
    if varredura.verificar_nmap():
        logger.info("Nmap está disponível!")
        
        # Exemplo de varredura
        alvo = input("Digite o IP ou hostname para varredura: ").strip()
        if alvo:
            logger.info(f"Executando varredura básica em {alvo}...")
            resultado = varredura.varredura_basica(alvo, "1-1000")
            
            if resultado['sucesso']:
                logger.info("\nRelatório da Varredura:")
                logger.info(varredura.gerar_relatorio_resumido(resultado))
            else:
                logger.error(f"Erro na varredura: {resultado['erro']}")
    else:
        logger.error("Nmap não está disponível. Instale o Nmap para continuar.")