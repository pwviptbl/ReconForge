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
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
import tempfile

from core.configuracao import obter_config

class VarreduraNmap:
    """Classe para executar varreduras Nmap com NSE"""
    
    def __init__(self):
        """Inicializa o módulo de varredura Nmap"""
        self.logger = logging.getLogger(__name__)
        self.binario_nmap = obter_config('nmap.binario', 'nmap')
        self.timeout_padrao = obter_config('nmap.timeout_padrao', 300)
        self.scripts_nse_padrao = obter_config('nmap.scripts_nse_padrao', ['default'])
        self.opcoes_padrao = obter_config('nmap.opcoes_padrao', ['-sV', '-sC'])
        
        # Verificar se o Nmap está disponível
        self.verificar_nmap()
    
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
            portas = obter_config('nmap.porta_padrao', '1-1000')
        
        comando = [
            self.binario_nmap,
            '-p', portas,
            '-sS',  # SYN scan
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
            portas = obter_config('nmap.porta_padrao', '1-65535')
        
        comando = [
            self.binario_nmap,
            '-p', portas,
            '-sV',  # Detecção de versão
            '-O',   # Detecção de OS
            '-sC',  # Scripts padrão
            '--open',
            alvo
        ]
        
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
            portas = obter_config('nmap.porta_padrao', '1-65535')
        
        comando = [
            self.binario_nmap,
            '-p', portas,
            '-sV',
            '--script', 'vuln',
            '--script-args', 'unsafe=1',
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
        comando = [
            self.binario_nmap,
            '-p', '80,443,8080,8443,8000,8888,3000,5000',
            '-sV',
            '--script', 'http-*',
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
        comando = [
            self.binario_nmap,
            '-p', '139,445',
            '-sV',
            '--script', 'smb-*',
            alvo
        ]
        
        return self._executar_varredura(comando, "varredura_smb")
    
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
        
        try:
            # Criar arquivo temporário para saída XML
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
                arquivo_xml = temp_file.name
            
            # Adicionar saída XML ao comando
            comando_completo = comando + ['-oX', arquivo_xml]
            
            self.logger.info(f"Executando {tipo_varredura}: {' '.join(comando_completo)}")
            
            # Executar comando Nmap
            processo = subprocess.run(
                comando_completo,
                capture_output=True,
                text=True,
                timeout=self.timeout_padrao
            )
            
            resultado['codigo_saida'] = processo.returncode
            resultado['saida_padrao'] = processo.stdout
            resultado['saida_erro'] = processo.stderr
            
            if processo.returncode == 0:
                # Processar saída XML
                resultado['dados'] = self._processar_xml_nmap(arquivo_xml)
                resultado['sucesso'] = True
                self.logger.info(f"{tipo_varredura} concluída com sucesso")
            else:
                resultado['erro'] = f"Nmap retornou código {processo.returncode}: {processo.stderr}"
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
            tree = ET.parse(arquivo_xml)
            root = tree.getroot()
            
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
            
            dados['resumo']['servicos_detectados'] = len(servicos)
            dados['resumo']['vulnerabilidades'] = vulnerabilidades
            
        except Exception as e:
            self.logger.error(f"Erro ao processar XML: {str(e)}")
        
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
    varredura = VarreduraNmap()
    
    if varredura.verificar_nmap():
        print("Nmap está disponível!")
        
        # Exemplo de varredura
        alvo = input("Digite o IP ou hostname para varredura: ").strip()
        if alvo:
            print(f"Executando varredura básica em {alvo}...")
            resultado = varredura.varredura_basica(alvo, "1-1000")
            
            if resultado['sucesso']:
                print("\nRelatório da Varredura:")
                print(varredura.gerar_relatorio_resumido(resultado))
            else:
                print(f"Erro na varredura: {resultado['erro']}")
    else:
        print("Nmap não está disponível. Instale o Nmap para continuar.")