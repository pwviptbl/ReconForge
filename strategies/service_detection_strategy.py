#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Estratégia de Detecção de Serviços - Fase 2 da Refatoração

Usa Nmap para detecção detalhada de serviços em portas abertas,
convertendo o módulo existente para o padrão Strategy.
"""

from typing import Dict, Any, List
from datetime import datetime
import socket
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from interfaces.scanner_strategy import (
    IServiceDetectionStrategy, StrategyPriority, ExecutionPhase, StrategyResult, BaseStrategy
)
from core.scan_context import ScanContext, ServiceInfo


class ServiceDetectionStrategy(BaseStrategy, IServiceDetectionStrategy):
    """Estratégia de detecção de serviços usando Nmap"""
    
    def __init__(self, nmap_module=None, logger=None):
        super().__init__(logger)
        self._nmap_module = nmap_module
        self._nmap_available = self._check_nmap_availability()
    
    @property
    def name(self) -> str:
        return "service_detection"
    
    @property
    def description(self) -> str:
        return "Detecta serviços detalhados e versões usando Nmap em portas abertas"
    
    @property
    def priority(self) -> StrategyPriority:
        return StrategyPriority.HIGH
    
    @property
    def execution_phase(self) -> ExecutionPhase:
        return ExecutionPhase.ENUMERATION
    
    def can_execute(self, context: ScanContext) -> bool:
        """
        Pode executar se:
        - Há portas abertas descobertas
        - Nmap está disponível
        - Ainda não foi executada para os hosts com portas
        """
        # Verificar se há portas abertas
        if not context.open_ports:
            return False
        
        # Verificar se Nmap está disponível
        if not self._nmap_available:
            self._log("WARNING", "Nmap não disponível para detecção de serviços")
            return False
        
        # Verificar se já foi executada para todos os hosts
        hosts_with_ports = set(context.open_ports.keys())
        hosts_with_detailed_services = set(context.services.keys())
        
        return not hosts_with_ports.issubset(hosts_with_detailed_services)
    
    def execute(self, target: str, context: ScanContext) -> StrategyResult:
        """
        Executa detecção de serviços no alvo especificado
        
        Args:
            target: IP ou hostname a analisar
            context: Contexto do scan
            
        Returns:
            Resultado com serviços detalhados descobertos
        """
        self._start_execution_timer()
        self._log("INFO", f"Iniciando detecção de serviços para: {target}")
        
        # Obter portas abertas para este host
        open_ports = context.open_ports.get(target, [])
        if not open_ports:
            return self._create_result(
                success=False,
                warnings=[f"Nenhuma porta aberta conhecida para {target}"]
            )
        
        # Usar módulo Nmap existente se disponível
        if self._nmap_module:
            try:
                result = self._execute_nmap_module(target, open_ports, context)
                if result.success:
                    return result
                else:
                    self._log("WARNING", "Módulo Nmap falhou, tentando implementação nativa")
            except Exception as e:
                self._log("WARNING", f"Erro no módulo Nmap: {e}, usando implementação nativa")
        
        # Implementação nativa
        return self._execute_native_detection(target, open_ports, context)
    
    def detect_services(self, target: str, ports: List[int], context: ScanContext) -> StrategyResult:
        """Implementação do método abstrato da interface IServiceDetectionStrategy"""
        # Adicionar portas específicas ao contexto se fornecidas
        if ports:
            context.user_preferences['target_ports'] = ports
            # Atualizar contexto com as portas se necessário
            if target not in context.open_ports:
                context.add_open_ports(target, ports, self.name)
        
        return self.execute(target, context)
    
    def get_dependencies(self) -> List[str]:
        return ["port_scan"]
    
    def estimate_execution_time(self, target: str, context: ScanContext) -> float:
        """
        Estima tempo baseado no número de portas abertas
        
        Args:
            target: Alvo a analisar
            context: Contexto atual
            
        Returns:
            Tempo estimado em segundos
        """
        open_ports = context.open_ports.get(target, [])
        
        if not open_ports:
            return 5.0  # Verificação rápida
        
        # ~2-3 segundos por porta para detecção de serviço
        base_time = len(open_ports) * 2.5
        
        # Adicionar tempo para scripts NSE se muitas portas
        if len(open_ports) > 10:
            base_time += 30.0  # Scripts adicionais
        
        return min(base_time, 180.0)  # Máximo 3 minutos
    
    def validate_target(self, target: str) -> bool:
        """Valida se o alvo é um IP ou hostname válido"""
        return self._is_valid_host(target)
    
    def get_required_tools(self) -> List[str]:
        """Requer Nmap para detecção adequada"""
        return ["nmap"]
    
    def get_output_artifacts(self) -> List[str]:
        """Produz informações detalhadas de serviços"""
        return ["services", "versions", "service_banners"]
    
    def supports_parallel_execution(self) -> bool:
        """Pode ser executado em paralelo para diferentes hosts"""
        return True
    
    # Métodos privados
    
    def _execute_nmap_module(self, target: str, ports: List[int], context: ScanContext) -> StrategyResult:
        """Executa detecção usando módulo Nmap existente"""
        try:
            # Preparar parâmetros para o módulo Nmap
            tipo_scan = "deteccao_servicos"
            
            if hasattr(self._nmap_module, 'varredura_servicos'):
                resultado = self._nmap_module.varredura_servicos(target, ports)
            elif hasattr(self._nmap_module, 'varredura_completa'):
                resultado = self._nmap_module.varredura_completa(target)
            else:
                # Tentar método genérico
                resultado = self._nmap_module.executar(target, tipo=tipo_scan)
            
            return self._convert_nmap_result(resultado, target, context)
            
        except Exception as e:
            return self._create_result(
                success=False,
                errors=[f"Erro no módulo Nmap: {e}"]
            )
    
    def _execute_native_detection(self, target: str, ports: List[int], context: ScanContext) -> StrategyResult:
        """Implementação nativa usando Nmap diretamente"""
        if not self._nmap_available:
            return self._create_result(
                success=False,
                errors=["Nmap não está disponível no sistema"]
            )
        
        try:
            # Construir comando Nmap
            ports_str = ",".join(map(str, ports))
            
            cmd = [
                "nmap",
                "-sV",  # Detecção de versão
                "-sC",  # Scripts padrão
                "--version-intensity", "5",
                "-p", ports_str,
                "-oX", "-",  # Output XML para stdout
                target
            ]
            
            self._log("INFO", f"Executando: {' '.join(cmd)}")
            
            # Executar Nmap
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutos timeout
            )
            
            if process.returncode != 0:
                return self._create_result(
                    success=False,
                    errors=[f"Erro no Nmap: {process.stderr}"]
                )
            
            # Processar resultado XML
            return self._parse_nmap_xml(process.stdout, target, context)
            
        except subprocess.TimeoutExpired:
            return self._create_result(
                success=False,
                errors=["Timeout na execução do Nmap"]
            )
        except Exception as e:
            return self._create_result(
                success=False,
                errors=[f"Erro na execução nativa do Nmap: {e}"]
            )
    
    def _parse_nmap_xml(self, xml_output: str, target: str, context: ScanContext) -> StrategyResult:
        """Processa output XML do Nmap"""
        try:
            root = ET.fromstring(xml_output)
            
            services_found = []
            detailed_services = {}
            vulnerabilities = []
            
            # Processar hosts
            for host in root.findall('.//host'):
                # Verificar se host está up
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue
                
                # Processar portas
                for port in host.findall('.//port'):
                    port_id = int(port.get('portid'))
                    protocol = port.get('protocol', 'tcp')
                    
                    # Verificar estado da porta
                    state = port.find('state')
                    if state is None or state.get('state') != 'open':
                        continue
                    
                    # Obter informações do serviço
                    service = port.find('service')
                    service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                    service_version = service.get('version', '') if service is not None else ''
                    service_product = service.get('product', '') if service is not None else ''
                    
                    # Obter banner se disponível
                    banner = ""
                    if service is not None:
                        extrainfo = service.get('extrainfo', '')
                        if extrainfo:
                            banner = extrainfo
                    
                    # Criar info do serviço
                    service_info = ServiceInfo(
                        host=target,
                        port=port_id,
                        service_name=service_name,
                        version=f"{service_product} {service_version}".strip(),
                        banner=banner,
                        state='open',
                        detected_by=self.name,
                        confidence=0.9,
                        metadata={
                            'protocol': protocol,
                            'product': service_product,
                            'nmap_service': service_name
                        }
                    )
                    
                    services_found.append(service_info)
                    
                    # Processar scripts NSE para vulnerabilidades
                    for script in port.findall('.//script'):
                        script_id = script.get('id', '')
                        script_output = script.get('output', '')
                        
                        # Detectar possíveis vulnerabilidades
                        if any(vuln_keyword in script_id.lower() for vuln_keyword in ['vuln', 'cve', 'exploit']):
                            if 'VULNERABLE' in script_output or 'CVE-' in script_output:
                                vulnerabilities.append({
                                    'id': f"nmap_script_{script_id}_{port_id}",
                                    'name': f"Vulnerability detected by {script_id}",
                                    'description': script_output[:200] + "..." if len(script_output) > 200 else script_output,
                                    'severity': 'medium',
                                    'affected_service': service_info,
                                    'source': 'nmap_nse'
                                })
            
            # Organizar serviços por host
            if target not in detailed_services:
                detailed_services[target] = []
            
            for service in services_found:
                detailed_services[target].append({
                    'port': service.port,
                    'service': service.service_name,
                    'version': service.version,
                    'banner': service.banner,
                    'state': service.state
                })
            
            # Determinar sucesso
            success = len(services_found) > 0
            confidence = 0.9 if success else 0.5
            
            # Sugerir próximas estratégias
            next_strategies = []
            if any(service.service_name in ['http', 'https'] for service in services_found):
                next_strategies.extend(["web_analysis", "technology_detection", "directory_scan"])
            if any(service.service_name in ['ssh', 'ftp', 'telnet'] for service in services_found):
                next_strategies.append("vulnerability_analysis")
            
            return self._create_result(
                success=success,
                data={
                    "services_detected": len(services_found),
                    "detailed_services": detailed_services,
                    "nmap_scan": True,
                    "scan_type": "service_detection"
                },
                discovered_services=detailed_services,
                vulnerabilities=vulnerabilities,
                next_strategies=next_strategies,
                confidence_score=confidence
            )
            
        except ET.ParseError as e:
            return self._create_result(
                success=False,
                errors=[f"Erro ao processar XML do Nmap: {e}"]
            )
        except Exception as e:
            return self._create_result(
                success=False,
                errors=[f"Erro ao processar resultado do Nmap: {e}"]
            )
    
    def _convert_nmap_result(self, resultado: Dict[str, Any], target: str, context: ScanContext) -> StrategyResult:
        """Converte resultado do módulo Nmap para formato Strategy"""
        if not isinstance(resultado, dict):
            return self._create_result(
                success=False,
                errors=[f"Resultado Nmap inválido: {type(resultado)}"]
            )
        
        success = resultado.get('sucesso', False)
        dados = resultado.get('dados', {})
        
        services_found = []
        detailed_services = {}
        
        # Processar dados do módulo Nmap
        if 'hosts' in dados:
            hosts = dados['hosts']
            if isinstance(hosts, list):
                for host_data in hosts:
                    if isinstance(host_data, dict):
                        host_ip = host_data.get('ip', target)
                        portas = host_data.get('portas', [])
                        
                        if host_ip not in detailed_services:
                            detailed_services[host_ip] = []
                        
                        for porta_info in portas:
                            if isinstance(porta_info, dict):
                                port_num = porta_info.get('numero')
                                service_name = porta_info.get('servico', 'unknown')
                                version = porta_info.get('versao', '')
                                
                                detailed_services[host_ip].append({
                                    'port': port_num,
                                    'service': service_name,
                                    'version': version,
                                    'state': porta_info.get('estado', 'open')
                                })
                                
                                # Criar ServiceInfo
                                service_info = ServiceInfo(
                                    host=host_ip,
                                    port=port_num,
                                    service_name=service_name,
                                    version=version,
                                    state=porta_info.get('estado', 'open'),
                                    detected_by=self.name
                                )
                                services_found.append(service_info)
        
        # Sugerir próximas estratégias
        next_strategies = []
        if any('http' in str(service).lower() for service in services_found):
            next_strategies.extend(["web_analysis", "technology_detection"])
        
        return self._create_result(
            success=success,
            data={
                "nmap_data": dados,
                "services_detected": len(services_found),
                "detailed_services": detailed_services
            },
            discovered_services=detailed_services,
            next_strategies=next_strategies,
            confidence_score=1.0 if success else 0.0
        )
    
    def _check_nmap_availability(self) -> bool:
        """Verifica se Nmap está disponível no sistema"""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _is_valid_host(self, target: str) -> bool:
        """Verifica se é um host válido (IP ou hostname)"""
        if not target or not isinstance(target, str):
            return False
        
        target = target.strip()
        
        # Verificar se é IP válido
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            pass
        
        # Verificar se é hostname válido
        if '.' in target and len(target) > 1:
            return True
        
        return False
