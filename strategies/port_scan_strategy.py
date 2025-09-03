#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Estratégia de Scan de Portas - Fase 2 da Refatoração

Converte o módulo de scan de portas existente (RustScan) para o padrão Strategy,
integrando com o módulo scanner_portas_python para funcionalidade completa.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from interfaces.scanner_strategy import (
    IPortScanStrategy, StrategyPriority, ExecutionPhase, StrategyResult, BaseStrategy
)
from core.scan_context import ScanContext, ServiceInfo


class PortScanStrategy(BaseStrategy, IPortScanStrategy):
    """Estratégia de scan de portas usando RustScan como base com fallback Python"""
    
    def __init__(self, rustscan_module=None, python_scanner_module=None, logger=None):
        super().__init__(logger)
        self._rustscan_module = rustscan_module
        self._python_scanner = python_scanner_module
        self._common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090
        ]
        self._all_ports_range = list(range(1, 65536))
    
    @property
    def name(self) -> str:
        return "port_scan"
    
    @property
    def description(self) -> str:
        return "Escaneia portas TCP abertas usando RustScan com fallback para scanner Python puro"
    
    @property
    def priority(self) -> StrategyPriority:
        return StrategyPriority.HIGH
    
    @property
    def execution_phase(self) -> ExecutionPhase:
        return ExecutionPhase.DISCOVERY
    
    def can_execute(self, context: ScanContext) -> bool:
        """
        Pode executar se:
        - Há hosts descobertos (via DNS ou especificados)
        - Ainda não foi executada para todos os hosts
        """
        # Verificar se há hosts para escanear
        if not context.discovered_hosts:
            return False
        
        # Verificar se já foi executada para todos os hosts
        hosts_without_scan = [
            host for host in context.discovered_hosts 
            if host not in context.open_ports
        ]
        
        return len(hosts_without_scan) > 0
    
    def execute(self, target: str, context: ScanContext) -> StrategyResult:
        """
        Executa scan de portas no alvo especificado
        
        Args:
            target: IP ou hostname a escanear
            context: Contexto do scan
            
        Returns:
            Resultado com portas abertas descobertas
        """
        self._start_execution_timer()
        self._log("INFO", f"Iniciando scan de portas para: {target}")
        
        # Determinar tipo de scan baseado no contexto
        scan_type = self._determine_scan_type(context)
        ports_to_scan = self._get_ports_for_scan_type(scan_type)
        
        # Tentar RustScan primeiro
        if self._rustscan_module:
            try:
                result = self._execute_rustscan(target, context, scan_type)
                if result.success:
                    return result
                else:
                    self._log("WARNING", "RustScan falhou, tentando scanner Python")
            except Exception as e:
                self._log("WARNING", f"Erro no RustScan: {e}, usando scanner Python")
        
        # Fallback para scanner Python
        return self._execute_python_scan(target, context, ports_to_scan)
    
    def scan_ports(self, target: str, ports: Optional[List[int]], context: ScanContext) -> StrategyResult:
        """Implementação específica da interface IPortScanStrategy"""
        if ports:
            # Scan customizado com portas específicas
            return self._execute_custom_scan(target, ports, context)
        else:
            # Scan padrão
            return self.execute(target, context)
    
    def scan_ports(self, target: str, ports: Optional[List[int]], context: ScanContext) -> StrategyResult:
        """Implementação do método abstrato da interface IPortScanStrategy"""
        # Adicionar portas específicas ao contexto se fornecidas
        if ports:
            context.user_preferences['target_ports'] = ports
        
        return self.execute(target, context)
    
    def get_dependencies(self) -> List[str]:
        """Depende de resolução DNS para ter hosts válidos"""
        return ["dns_resolution"]
    
    def estimate_execution_time(self, target: str, context: ScanContext) -> float:
        """
        Estima tempo baseado no tipo de scan e número de portas
        
        Args:
            target: Alvo a escanear
            context: Contexto atual
            
        Returns:
            Tempo estimado em segundos
        """
        scan_type = self._determine_scan_type(context)
        
        if scan_type == "quick":
            return 10.0  # Scan rápido: ~10 segundos
        elif scan_type == "common":
            return 30.0  # Scan comum: ~30 segundos
        elif scan_type == "full":
            return 300.0  # Scan completo: ~5 minutos
        else:
            return 60.0  # Padrão: 1 minuto
    
    def validate_target(self, target: str) -> bool:
        """Valida se o alvo é um IP ou hostname válido"""
        return self._is_valid_host(target)
    
    def get_required_tools(self) -> List[str]:
        """Preferível ter RustScan, mas funciona com Python puro"""
        return ["rustscan"]  # Opcional
    
    def get_output_artifacts(self) -> List[str]:
        """Produz informações de portas e serviços básicos"""
        return ["ports", "basic_services"]
    
    def supports_parallel_execution(self) -> bool:
        """Pode ser executado em paralelo para diferentes hosts"""
        return True
    
    # Métodos privados
    
    def _determine_scan_type(self, context: ScanContext) -> str:
        """Determina tipo de scan baseado no contexto"""
        # Se é scan inicial, fazer quick scan
        if len(context.executed_strategies) <= 2:
            return "quick"
        
        # Se encontrou muitos hosts, fazer common scan
        if len(context.discovered_hosts) > 5:
            return "common"
        
        # Se há indicações de serviços web, fazer scan focado
        if any("web" in str(tech).lower() for tech in context.technologies.values()):
            return "web_focused"
        
        # Padrão: scan comum
        return "common"
    
    def _get_ports_for_scan_type(self, scan_type: str) -> List[int]:
        """Retorna lista de portas baseada no tipo de scan"""
        if scan_type == "quick":
            return [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5432, 8080]
        elif scan_type == "common":
            return self._common_ports
        elif scan_type == "web_focused":
            return [80, 443, 8080, 8443, 8888, 9090, 3000, 5000, 8000, 8888, 9000]
        elif scan_type == "full":
            return self._all_ports_range
        else:
            return self._common_ports
    
    def _execute_rustscan(self, target: str, context: ScanContext, scan_type: str) -> StrategyResult:
        """Executa scan usando RustScan"""
        try:
            # Configurar parâmetros para RustScan
            if scan_type == "quick":
                resultado = self._rustscan_module.varredura_rapida(target)
            elif scan_type == "full":
                resultado = self._rustscan_module.varredura_completa(target)
            else:
                resultado = self._rustscan_module.varredura_completa(target)
            
            return self._convert_rustscan_result(resultado, target, context)
            
        except Exception as e:
            return self._create_result(
                success=False,
                errors=[f"Erro no RustScan: {e}"]
            )
    
    def _execute_python_scan(self, target: str, context: ScanContext, ports: List[int]) -> StrategyResult:
        """Executa scan usando módulo Python puro"""
        if not self._python_scanner:
            return self._execute_native_scan(target, ports, context)
        
        try:
            # Usar scanner Python existente
            if hasattr(self._python_scanner, 'scan_rapido'):
                resultado = self._python_scanner.scan_rapido(target)
            elif hasattr(self._python_scanner, 'scan_completo'):
                resultado = self._python_scanner.scan_completo(target)
            else:
                # Fallback para scan nativo
                return self._execute_native_scan(target, ports, context)
            
            return self._convert_python_scanner_result(resultado, target, context)
            
        except Exception as e:
            self._log("WARNING", f"Erro no scanner Python: {e}, usando implementação nativa")
            return self._execute_native_scan(target, ports, context)
    
    def _execute_native_scan(self, target: str, ports: List[int], context: ScanContext) -> StrategyResult:
        """Implementação nativa de scan de portas"""
        self._log("INFO", f"Executando scan nativo para {target} em {len(ports)} portas")
        
        open_ports = []
        basic_services = {}
        errors = []
        warnings = []
        
        # Scan multi-threaded para melhor performance
        max_threads = min(50, len(ports))
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    # Porta aberta, tentar identificar serviço
                    service_name = self._identify_service(port)
                    return {
                        'port': port,
                        'state': 'open',
                        'service': service_name
                    }
            except Exception as e:
                return {'port': port, 'error': str(e)}
            
            return None
        
        # Executar scan em threads
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                try:
                    result = future.result()
                    if result and 'port' in result and result.get('state') == 'open':
                        port = result['port']
                        open_ports.append(port)
                        
                        # Criar info do serviço
                        service_info = ServiceInfo(
                            host=target,
                            port=port,
                            service_name=result.get('service', 'unknown'),
                            state='open',
                            detected_by=self.name
                        )
                        
                        if target not in basic_services:
                            basic_services[target] = []
                        basic_services[target].append({
                            'port': port,
                            'service': result.get('service', 'unknown'),
                            'state': 'open'
                        })
                        
                except Exception as e:
                    errors.append(f"Erro no scan da porta: {e}")
        
        # Determinar sucesso
        success = len(open_ports) > 0
        confidence = 1.0 if success else 0.5  # Mesmo sem portas, scan foi executado
        
        # Sugerir próximas estratégias
        next_strategies = []
        if open_ports:
            next_strategies.append("service_detection")
            if any(port in [80, 443, 8080, 8443] for port in open_ports):
                next_strategies.extend(["web_analysis", "technology_detection"])
        
        return self._create_result(
            success=success,
            data={
                "open_ports": open_ports,
                "total_ports_scanned": len(ports),
                "scan_type": "native_python",
                "basic_services": basic_services
            },
            discovered_services=basic_services,
            next_strategies=next_strategies,
            confidence_score=confidence,
            warnings=warnings if not open_ports else [],
            errors=errors
        )
    
    def _execute_custom_scan(self, target: str, ports: List[int], context: ScanContext) -> StrategyResult:
        """Executa scan customizado com portas específicas"""
        return self._execute_native_scan(target, ports, context)
    
    def _convert_rustscan_result(self, resultado: Dict[str, Any], target: str, context: ScanContext) -> StrategyResult:
        """Converte resultado do RustScan para formato Strategy"""
        if not isinstance(resultado, dict):
            return self._create_result(
                success=False,
                errors=[f"Resultado RustScan inválido: {type(resultado)}"]
            )
        
        success = resultado.get('sucesso', False)
        dados = resultado.get('dados', {})
        
        open_ports = []
        basic_services = {}
        
        # Processar dados do RustScan
        if 'hosts' in dados:
            hosts = dados['hosts']
            if isinstance(hosts, list):
                for host_data in hosts:
                    if isinstance(host_data, dict) and 'portas' in host_data:
                        portas = host_data['portas']
                        if isinstance(portas, list):
                            for porta_info in portas:
                                if isinstance(porta_info, dict):
                                    port_num = porta_info.get('numero')
                                    if port_num and porta_info.get('estado') == 'open':
                                        open_ports.append(port_num)
                                        
                                        # Criar serviço básico
                                        if target not in basic_services:
                                            basic_services[target] = []
                                        basic_services[target].append({
                                            'port': port_num,
                                            'service': porta_info.get('servico', 'unknown'),
                                            'state': 'open'
                                        })
        
        next_strategies = []
        if open_ports:
            next_strategies.append("service_detection")
            if any(port in [80, 443, 8080, 8443] for port in open_ports):
                next_strategies.extend(["web_analysis", "technology_detection"])
        
        return self._create_result(
            success=success,
            data={
                "rustscan_data": dados,
                "open_ports": open_ports,
                "scan_tool": "rustscan"
            },
            discovered_services=basic_services,
            next_strategies=next_strategies,
            confidence_score=1.0 if success else 0.0
        )
    
    def _convert_python_scanner_result(self, resultado: Dict[str, Any], target: str, context: ScanContext) -> StrategyResult:
        """Converte resultado do scanner Python para formato Strategy"""
        if not isinstance(resultado, dict):
            return self._create_result(
                success=False,
                errors=[f"Resultado scanner Python inválido: {type(resultado)}"]
            )
        
        success = resultado.get('sucesso', False)
        
        open_ports = []
        basic_services = {}
        
        # Processar resultado do scanner Python
        if 'portas_abertas' in resultado:
            portas_data = resultado['portas_abertas']
            if isinstance(portas_data, dict):
                for host, portas in portas_data.items():
                    if isinstance(portas, list):
                        open_ports.extend(portas)
                        
                        # Criar serviços básicos
                        basic_services[host] = []
                        for port in portas:
                            basic_services[host].append({
                                'port': port,
                                'service': self._identify_service(port),
                                'state': 'open'
                            })
        
        next_strategies = []
        if open_ports:
            next_strategies.append("service_detection")
            if any(port in [80, 443, 8080, 8443] for port in open_ports):
                next_strategies.extend(["web_analysis", "technology_detection"])
        
        return self._create_result(
            success=success,
            data={
                "python_scanner_data": resultado,
                "open_ports": open_ports,
                "scan_tool": "python_scanner"
            },
            discovered_services=basic_services,
            next_strategies=next_strategies,
            confidence_score=1.0 if success else 0.0
        )
    
    def _identify_service(self, port: int) -> str:
        """Identifica serviço comum baseado na porta"""
        common_services = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            993: 'imaps',
            995: 'pop3s',
            1723: 'pptp',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            5900: 'vnc',
            8080: 'http-alt',
            8443: 'https-alt'
        }
        
        return common_services.get(port, 'unknown')
    
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
