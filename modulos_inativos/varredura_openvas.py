#!/usr/bin/env python3
"""
Módulo de integração com OpenVAS/GVM para varreduras de vulnerabilidades
Autor: VarreduraIA
Data: 2025
"""

import os
import time
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

try:
    from gvm.connections import UnixSocketConnection, TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    from gvm.xml import pretty_print
except ImportError:
    logging.getLogger('VarreduraOpenVAS').error("Erro: Biblioteca python-gvm não encontrada. Execute: pip install python-gvm")
    exit(1)


class VarreduraOpenVAS:
    """
    Classe para realizar varreduras de vulnerabilidades usando OpenVAS/GVM
    """
    
    def __init__(self):
        """
        Inicializa o cliente OpenVAS/GVM
        """
        self.logger = logging.getLogger(__name__)
        self.connection = None
        self.gmp = None
        self.transform = EtreeTransform()
        
        # Configurações padrão
        self.host = os.getenv('OPENVAS_HOST', 'localhost')
        self.port = int(os.getenv('OPENVAS_PORT', 9390))
        self.username = os.getenv('OPENVAS_USERNAME', 'admin')
        self.password = os.getenv('OPENVAS_PASSWORD', 'admin')
        self.socket_path = os.getenv('OPENVAS_SOCKET', '/run/gvmd/gvmd.sock')
        
        # IDs de configurações padrão do OpenVAS
        self.config_ids = {
            'full_and_fast': 'daba56c8-73ec-11df-a475-002264764cea',
            'full_and_very_deep': '74db13d6-7489-11df-91b9-002264764cea',
            'system_discovery': '8715c877-47a0-438d-98a3-27c7a6ab2196',
            'host_discovery': '2d3f051c-55ba-11e3-bf43-406186ea4fc5'
        }
        
        self.scanner_id = '08b69003-5fc2-4037-a479-93b440211c73'  # OpenVAS Scanner padrão

    def conectar(self) -> bool:
        """
        Estabelece conexão com o OpenVAS/GVM
        
        Returns:
            bool: True se conectado com sucesso, False caso contrário
        """
        try:
            # Tenta conexão via socket Unix primeiro (mais rápida)
            if os.path.exists(self.socket_path):
                self.logger.info(f"Conectando via socket Unix: {self.socket_path}")
                self.connection = UnixSocketConnection(path=self.socket_path)
            else:
                # Fallback para conexão TLS
                self.logger.info(f"Conectando via TLS: {self.host}:{self.port}")
                self.connection = TLSConnection(hostname=self.host, port=self.port)
            
            self.gmp = Gmp(connection=self.connection, transform=self.transform)
            
            # Autentica
            self.gmp.authenticate(self.username, self.password)
            
            # Verifica se a conexão está funcionando
            version = self.gmp.get_version()
            self.logger.info(f"Conectado ao GVM versão: {version.get('version')}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao conectar com OpenVAS/GVM: {e}")
            return False

    def desconectar(self):
        """
        Encerra a conexão com o OpenVAS/GVM
        """
        try:
            if self.connection:
                self.connection.disconnect()
                self.logger.info("Desconectado do OpenVAS/GVM")
        except Exception as e:
            self.logger.error(f"Erro ao desconectar: {e}")

    def verificar_openvas(self) -> bool:
        """
        Verifica se o OpenVAS/GVM está disponível e funcionando
        
        Returns:
            bool: True se disponível, False caso contrário
        """
        try:
            if not self.conectar():
                return False
            
            # Testa uma operação simples
            self.gmp.get_version()
            self.desconectar()
            return True
            
        except Exception as e:
            self.logger.error(f"OpenVAS/GVM não disponível: {e}")
            return False

    def criar_alvo(self, nome: str, hosts: str, descricao: str = "") -> Optional[str]:
        """
        Cria um alvo para varredura
        
        Args:
            nome: Nome do alvo
            hosts: IPs ou hostnames (separados por vírgula)
            descricao: Descrição opcional
            
        Returns:
            str: ID do alvo criado ou None se erro
        """
        try:
            response = self.gmp.create_target(
                name=nome,
                hosts=[hosts],
                comment=descricao
            )
            
            target_id = response.get('id')
            self.logger.info(f"Alvo criado: {nome} (ID: {target_id})")
            return target_id
            
        except Exception as e:
            self.logger.error(f"Erro ao criar alvo: {e}")
            return None

    def criar_tarefa(self, nome: str, target_id: str, config_type: str = 'full_and_fast') -> Optional[str]:
        """
        Cria uma tarefa de varredura
        
        Args:
            nome: Nome da tarefa
            target_id: ID do alvo
            config_type: Tipo de configuração de varredura
            
        Returns:
            str: ID da tarefa criada ou None se erro
        """
        try:
            config_id = self.config_ids.get(config_type, self.config_ids['full_and_fast'])
            
            response = self.gmp.create_task(
                name=nome,
                config_id=config_id,
                target_id=target_id,
                scanner_id=self.scanner_id,
                comment=f"Tarefa criada automaticamente - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
            task_id = response.get('id')
            self.logger.info(f"Tarefa criada: {nome} (ID: {task_id})")
            return task_id
            
        except Exception as e:
            self.logger.error(f"Erro ao criar tarefa: {e}")
            return None

    def iniciar_varredura(self, task_id: str) -> bool:
        """
        Inicia uma varredura
        
        Args:
            task_id: ID da tarefa
            
        Returns:
            bool: True se iniciada com sucesso
        """
        try:
            self.gmp.start_task(task_id)
            self.logger.info(f"Varredura iniciada (Task ID: {task_id})")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao iniciar varredura: {e}")
            return False

    def verificar_status_varredura(self, task_id: str) -> Dict[str, Any]:
        """
        Verifica o status de uma varredura
        
        Args:
            task_id: ID da tarefa
            
        Returns:
            Dict com informações do status
        """
        try:
            response = self.gmp.get_task(task_id)
            task = response.find('task')
            
            if task is not None:
                status = task.find('status').text
                progress = task.find('progress').text if task.find('progress') is not None else "0"
                
                return {
                    'status': status,
                    'progress': int(progress),
                    'task_id': task_id,
                    'concluida': status in ['Done', 'Stopped']
                }
            
            return {'status': 'Unknown', 'progress': 0, 'task_id': task_id, 'concluida': False}
            
        except Exception as e:
            self.logger.error(f"Erro ao verificar status: {e}")
            return {'status': 'Error', 'progress': 0, 'task_id': task_id, 'concluida': True}

    def aguardar_conclusao(self, task_id: str, timeout: int = 3600) -> bool:
        """
        Aguarda a conclusão de uma varredura
        
        Args:
            task_id: ID da tarefa
            timeout: Timeout em segundos (padrão: 1 hora)
            
        Returns:
            bool: True se concluída com sucesso
        """
        inicio = time.time()
        
        while time.time() - inicio < timeout:
            status_info = self.verificar_status_varredura(task_id)
            
            self.logger.info(f"Status: {status_info['status']} - Progresso: {status_info['progress']}%")
            
            if status_info['concluida']:
                return status_info['status'] == 'Done'
            
            time.sleep(30)  # Verifica a cada 30 segundos
        
        self.logger.warning(f"Timeout atingido para tarefa {task_id}")
        return False

    def obter_relatorio(self, task_id: str, formato: str = 'xml') -> Optional[str]:
        """
        Obtém o relatório de uma varredura concluída
        
        Args:
            task_id: ID da tarefa
            formato: Formato do relatório (xml, pdf, html)
            
        Returns:
            str: Conteúdo do relatório ou None se erro
        """
        try:
            # Obtém a lista de relatórios para a tarefa
            reports = self.gmp.get_reports()
            
            report_id = None
            for report in reports.xpath('report'):
                task = report.find('task')
                if task is not None and task.get('id') == task_id:
                    report_id = report.get('id')
                    break
            
            if not report_id:
                self.logger.error(f"Relatório não encontrado para tarefa {task_id}")
                return None
            
            # Obtém o relatório no formato especificado
            if formato.lower() == 'xml':
                report = self.gmp.get_report(report_id)
                return pretty_print(report)
            else:
                # Para outros formatos, seria necessário usar get_report com format_id
                self.logger.warning(f"Formato {formato} não implementado, retornando XML")
                report = self.gmp.get_report(report_id)
                return pretty_print(report)
                
        except Exception as e:
            self.logger.error(f"Erro ao obter relatório: {e}")
            return None

    def processar_relatorio_xml(self, xml_content: str) -> Dict[str, Any]:
        """
        Processa o relatório XML e extrai informações relevantes
        
        Args:
            xml_content: Conteúdo XML do relatório
            
        Returns:
            Dict com dados processados
        """
        try:
            from xml.etree import ElementTree as ET
            
            root = ET.fromstring(xml_content)
            
            resultados = {
                'timestamp': datetime.now().isoformat(),
                'hosts': [],
                'vulnerabilidades': [],
                'resumo': {
                    'total_hosts': 0,
                    'total_vulnerabilidades': 0,
                    'criticas': 0,
                    'altas': 0,
                    'medias': 0,
                    'baixas': 0,
                    'informativas': 0
                }
            }
            
            # Processa resultados
            for result in root.xpath('.//result'):
                host_elem = result.find('host')
                if host_elem is not None:
                    host_ip = host_elem.text
                    
                    # Informações da vulnerabilidade
                    nvt = result.find('nvt')
                    if nvt is not None:
                        vuln = {
                            'host': host_ip,
                            'nome': nvt.find('name').text if nvt.find('name') is not None else 'N/A',
                            'oid': nvt.get('oid', 'N/A'),
                            'severidade': result.find('severity').text if result.find('severity') is not None else '0.0',
                            'descricao': result.find('description').text if result.find('description') is not None else '',
                            'porta': result.find('port').text if result.find('port') is not None else 'N/A'
                        }
                        
                        # Classifica severidade
                        severidade_num = float(vuln['severidade'])
                        if severidade_num >= 9.0:
                            vuln['nivel'] = 'Crítica'
                            resultados['resumo']['criticas'] += 1
                        elif severidade_num >= 7.0:
                            vuln['nivel'] = 'Alta'
                            resultados['resumo']['altas'] += 1
                        elif severidade_num >= 4.0:
                            vuln['nivel'] = 'Média'
                            resultados['resumo']['medias'] += 1
                        elif severidade_num > 0.0:
                            vuln['nivel'] = 'Baixa'
                            resultados['resumo']['baixas'] += 1
                        else:
                            vuln['nivel'] = 'Informativa'
                            resultados['resumo']['informativas'] += 1
                        
                        resultados['vulnerabilidades'].append(vuln)
                        
                        # Adiciona host se não existir
                        if host_ip not in [h['ip'] for h in resultados['hosts']]:
                            resultados['hosts'].append({
                                'ip': host_ip,
                                'vulnerabilidades_encontradas': 0
                            })
            
            # Atualiza contadores
            resultados['resumo']['total_hosts'] = len(resultados['hosts'])
            resultados['resumo']['total_vulnerabilidades'] = len(resultados['vulnerabilidades'])
            
            # Conta vulnerabilidades por host
            for host in resultados['hosts']:
                host['vulnerabilidades_encontradas'] = len([v for v in resultados['vulnerabilidades'] if v['host'] == host['ip']])
            
            return resultados
            
        except Exception as e:
            self.logger.error(f"Erro ao processar relatório XML: {e}")
            return {}

    def varredura_completa(self, alvo: str, nome_varredura: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa uma varredura completa (criar alvo, tarefa, executar e obter resultados)
        
        Args:
            alvo: IP ou hostname do alvo
            nome_varredura: Nome personalizado para a varredura
            
        Returns:
            Dict com resultados da varredura
        """
        if not nome_varredura:
            nome_varredura = f"Varredura_{alvo}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            if not self.conectar():
                return {'erro': 'Não foi possível conectar ao OpenVAS/GVM'}
            
            # Cria alvo
            target_id = self.criar_alvo(f"Alvo_{nome_varredura}", alvo, f"Alvo criado para {nome_varredura}")
            if not target_id:
                return {'erro': 'Não foi possível criar o alvo'}
            
            # Cria tarefa
            task_id = self.criar_tarefa(nome_varredura, target_id, 'full_and_fast')
            if not task_id:
                return {'erro': 'Não foi possível criar a tarefa'}
            
            # Inicia varredura
            if not self.iniciar_varredura(task_id):
                return {'erro': 'Não foi possível iniciar a varredura'}
            
            self.logger.info(f"Varredura iniciada. Aguardando conclusão...")
            
            # Aguarda conclusão
            if not self.aguardar_conclusao(task_id):
                return {'erro': 'Varredura não foi concluída no tempo esperado'}
            
            # Obtém relatório
            relatorio_xml = self.obter_relatorio(task_id)
            if not relatorio_xml:
                return {'erro': 'Não foi possível obter o relatório'}
            
            # Processa resultados
            resultados = self.processar_relatorio_xml(relatorio_xml)
            resultados['task_id'] = task_id
            resultados['target_id'] = target_id
            resultados['nome_varredura'] = nome_varredura
            
            self.desconectar()
            return resultados
            
        except Exception as e:
            self.logger.error(f"Erro na varredura completa: {e}")
            self.desconectar()
            return {'erro': f'Erro durante a varredura: {str(e)}'}

    def varredura_rapida(self, alvo: str, nome_varredura: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa uma varredura rápida (descoberta de sistema)
        
        Args:
            alvo: IP ou hostname do alvo
            nome_varredura: Nome personalizado para a varredura
            
        Returns:
            Dict com resultados da varredura
        """
        if not nome_varredura:
            nome_varredura = f"Varredura_Rapida_{alvo}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            if not self.conectar():
                return {'erro': 'Não foi possível conectar ao OpenVAS/GVM'}
            
            # Cria alvo
            target_id = self.criar_alvo(f"Alvo_{nome_varredura}", alvo, f"Alvo criado para {nome_varredura}")
            if not target_id:
                return {'erro': 'Não foi possível criar o alvo'}
            
            # Cria tarefa com configuração de descoberta
            task_id = self.criar_tarefa(nome_varredura, target_id, 'system_discovery')
            if not task_id:
                return {'erro': 'Não foi possível criar a tarefa'}
            
            # Inicia varredura
            if not self.iniciar_varredura(task_id):
                return {'erro': 'Não foi possível iniciar a varredura'}
            
            self.logger.info(f"Varredura rápida iniciada. Aguardando conclusão...")
            
            # Aguarda conclusão (timeout menor para varredura rápida)
            if not self.aguardar_conclusao(task_id, timeout=1800):  # 30 minutos
                return {'erro': 'Varredura não foi concluída no tempo esperado'}
            
            # Obtém relatório
            relatorio_xml = self.obter_relatorio(task_id)
            if not relatorio_xml:
                return {'erro': 'Não foi possível obter o relatório'}
            
            # Processa resultados
            resultados = self.processar_relatorio_xml(relatorio_xml)
            resultados['task_id'] = task_id
            resultados['target_id'] = target_id
            resultados['nome_varredura'] = nome_varredura
            resultados['tipo_varredura'] = 'rapida'
            
            self.desconectar()
            return resultados
            
        except Exception as e:
            self.logger.error(f"Erro na varredura rápida: {e}")
            self.desconectar()
            return {'erro': f'Erro durante a varredura: {str(e)}'}

    def listar_tarefas(self) -> List[Dict[str, Any]]:
        """
        Lista todas as tarefas existentes
        
        Returns:
            Lista de tarefas
        """
        try:
            if not self.conectar():
                return []
            
            response = self.gmp.get_tasks()
            tarefas = []
            
            for task in response.xpath('task'):
                tarefa = {
                    'id': task.get('id'),
                    'nome': task.find('name').text if task.find('name') is not None else 'N/A',
                    'status': task.find('status').text if task.find('status') is not None else 'N/A',
                    'progresso': task.find('progress').text if task.find('progress') is not None else '0',
                    'criacao': task.find('creation_time').text if task.find('creation_time') is not None else 'N/A'
                }
                tarefas.append(tarefa)
            
            self.desconectar()
            return tarefas
            
        except Exception as e:
            self.logger.error(f"Erro ao listar tarefas: {e}")
            return []

    def gerar_relatorio_resumido(self, resultados: Dict[str, Any]) -> str:
        """
        Gera um relatório resumido em texto
        
        Args:
            resultados: Resultados da varredura
            
        Returns:
            str: Relatório formatado
        """
        if 'erro' in resultados:
            return f"ERRO: {resultados['erro']}"
        
        relatorio = []
        relatorio.append("=" * 60)
        relatorio.append("RELATÓRIO DE VARREDURA OPENVAS/GVM")
        relatorio.append("=" * 60)
        relatorio.append(f"Varredura: {resultados.get('nome_varredura', 'N/A')}")
        relatorio.append(f"Data/Hora: {resultados.get('timestamp', 'N/A')}")
        relatorio.append("")
        
        resumo = resultados.get('resumo', {})
        relatorio.append("RESUMO EXECUTIVO:")
        relatorio.append(f"• Total de hosts analisados: {resumo.get('total_hosts', 0)}")
        relatorio.append(f"• Total de vulnerabilidades: {resumo.get('total_vulnerabilidades', 0)}")
        relatorio.append("")
        
        relatorio.append("DISTRIBUIÇÃO POR SEVERIDADE:")
        relatorio.append(f"• Críticas: {resumo.get('criticas', 0)}")
        relatorio.append(f"• Altas: {resumo.get('altas', 0)}")
        relatorio.append(f"• Médias: {resumo.get('medias', 0)}")
        relatorio.append(f"• Baixas: {resumo.get('baixas', 0)}")
        relatorio.append(f"• Informativas: {resumo.get('informativas', 0)}")
        relatorio.append("")
        
        # Hosts analisados
        hosts = resultados.get('hosts', [])
        if hosts:
            relatorio.append("HOSTS ANALISADOS:")
            for host in hosts:
                relatorio.append(f"• {host['ip']} - {host['vulnerabilidades_encontradas']} vulnerabilidades")
            relatorio.append("")
        
        # Top 10 vulnerabilidades mais críticas
        vulnerabilidades = resultados.get('vulnerabilidades', [])
        if vulnerabilidades:
            vulns_criticas = sorted(
                [v for v in vulnerabilidades if float(v['severidade']) >= 7.0],
                key=lambda x: float(x['severidade']),
                reverse=True
            )[:10]
            
            if vulns_criticas:
                relatorio.append("TOP 10 VULNERABILIDADES CRÍTICAS/ALTAS:")
                for i, vuln in enumerate(vulns_criticas, 1):
                    relatorio.append(f"{i}. {vuln['nome']} (Severidade: {vuln['severidade']})")
                    relatorio.append(f"   Host: {vuln['host']} | Porta: {vuln['porta']}")
                relatorio.append("")
        
        relatorio.append("=" * 60)
        
        return "\n".join(relatorio)