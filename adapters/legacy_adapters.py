#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adaptadores para módulos legados - Fase 1 da Refatoração

Permite que módulos antigos funcionem com as novas interfaces
sem modificar o código legado imediatamente.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import time

from interfaces import (
    IScannerModule, IPortScanner, IDNSResolver, 
    ScannerCapability, ScannerPriority
)


class DNSResolverAdapter(IDNSResolver):
    """Adaptador para o módulo ResolucaoDNS legado"""
    
    def __init__(self, legacy_resolver):
        self._legacy_resolver = legacy_resolver
        self._name = "dns_resolver_legacy"
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def capabilities(self) -> List[ScannerCapability]:
        return [ScannerCapability.DNS_RESOLUTION]
    
    @property
    def priority(self) -> ScannerPriority:
        return ScannerPriority.CRITICAL  # DNS é sempre crítico
    
    def can_execute(self, context: Dict[str, Any]) -> bool:
        """DNS pode sempre ser executado se há um alvo"""
        target = context.get('target', '')
        return bool(target and isinstance(target, str))
    
    def execute(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Executa resolução DNS usando módulo legado"""
        start_time = time.time()
        
        try:
            # Chamar método legado
            result = self._legacy_resolver.resolver_dns(target)
            
            # Normalizar resultado para formato da interface
            normalized_result = {
                'module_name': self.name,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'execution_time': time.time() - start_time,
                'success': result.get('sucesso', False),
                'capabilities_used': [ScannerCapability.DNS_RESOLUTION.value],
                'data': result
            }
            
            if not normalized_result['success']:
                normalized_result['error'] = result.get('erro', 'DNS resolution failed')
            
            return normalized_result
            
        except Exception as e:
            return {
                'module_name': self.name,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'execution_time': time.time() - start_time,
                'success': False,
                'error': f'DNS adapter error: {str(e)}',
                'capabilities_used': [ScannerCapability.DNS_RESOLUTION.value],
                'data': {}
            }
    
    def get_dependencies(self) -> List[ScannerCapability]:
        """DNS não tem dependências"""
        return []
    
    def estimate_time(self, target: str, context: Dict[str, Any]) -> int:
        """DNS geralmente é rápido"""
        return 5  # 5 segundos estimados
    
    def resolve_dns(self, domain: str) -> Dict[str, Any]:
        """Implementação da interface IDNSResolver"""
        context = {'target': domain}
        return self.execute(domain, context)


class PortScannerAdapter(IPortScanner):
    """Adaptador para scanners de porta legados (RustScan, Nmap)"""
    
    def __init__(self, legacy_scanner, scanner_type: str = "generic"):
        self._legacy_scanner = legacy_scanner
        self._scanner_type = scanner_type
        self._name = f"port_scanner_{scanner_type}_legacy"
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def capabilities(self) -> List[ScannerCapability]:
        capabilities = [ScannerCapability.PORT_SCANNING]
        
        # Nmap também detecta serviços
        if self._scanner_type.lower() == 'nmap':
            capabilities.append(ScannerCapability.SERVICE_DETECTION)
            capabilities.append(ScannerCapability.VULNERABILITY_SCANNING)
        
        return capabilities
    
    @property
    def priority(self) -> ScannerPriority:
        # RustScan é rápido, maior prioridade
        if self._scanner_type.lower() == 'rustscan':
            return ScannerPriority.HIGH
        # Nmap é mais completo mas mais lento
        elif self._scanner_type.lower() == 'nmap':
            return ScannerPriority.MEDIUM
        else:
            return ScannerPriority.MEDIUM
    
    def can_execute(self, context: Dict[str, Any]) -> bool:
        """Scanner de porta pode executar se há IPs descobertos"""
        target = context.get('target', '')
        ips_discovered = context.get('ips_discovered', [])
        
        # Pode executar se tem um IP diretamente ou IPs descobertos
        return bool(target or ips_discovered)
    
    def execute(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Executa scan de portas usando módulo legado"""
        start_time = time.time()
        
        try:
            # Determinar método baseado no tipo de scanner
            if self._scanner_type.lower() == 'rustscan':
                result = self._legacy_scanner.varredura_completa(target)
            elif self._scanner_type.lower() == 'nmap':
                # Para Nmap, usar varredura básica por padrão
                result = self._legacy_scanner.varredura_basica([target])
            else:
                # Scanner genérico
                if hasattr(self._legacy_scanner, 'varredura_completa'):
                    result = self._legacy_scanner.varredura_completa(target)
                elif hasattr(self._legacy_scanner, 'scan'):
                    result = self._legacy_scanner.scan(target)
                else:
                    raise AttributeError(f"Scanner {self._scanner_type} não tem método conhecido")
            
            # Normalizar resultado
            normalized_result = {
                'module_name': self.name,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'execution_time': time.time() - start_time,
                'success': result.get('sucesso', False),
                'capabilities_used': [cap.value for cap in self.capabilities],
                'data': result
            }
            
            if not normalized_result['success']:
                normalized_result['error'] = result.get('erro', 'Port scan failed')
            
            return normalized_result
            
        except Exception as e:
            return {
                'module_name': self.name,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'execution_time': time.time() - start_time,
                'success': False,
                'error': f'Port scanner adapter error: {str(e)}',
                'capabilities_used': [cap.value for cap in self.capabilities],
                'data': {}
            }
    
    def get_dependencies(self) -> List[ScannerCapability]:
        """Port scanning geralmente depende de DNS"""
        return [ScannerCapability.DNS_RESOLUTION]
    
    def estimate_time(self, target: str, context: Dict[str, Any]) -> int:
        """Estima tempo baseado no tipo de scanner"""
        if self._scanner_type.lower() == 'rustscan':
            return 30  # RustScan é rápido
        elif self._scanner_type.lower() == 'nmap':
            return 300  # Nmap pode ser mais lento
        else:
            return 120  # Scanner genérico
    
    def scan_ports(self, target: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """Implementação da interface IPortScanner"""
        context = {'target': target, 'ports': ports}
        return self.execute(target, context)


class WebScannerAdapter(IScannerModule):
    """Adaptador genérico para scanners web legados"""
    
    def __init__(self, legacy_scanner, scanner_name: str):
        self._legacy_scanner = legacy_scanner
        self._scanner_name = scanner_name
        self._name = f"web_scanner_{scanner_name}_legacy"
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def capabilities(self) -> List[ScannerCapability]:
        return [ScannerCapability.WEB_SCANNING]
    
    @property
    def priority(self) -> ScannerPriority:
        return ScannerPriority.MEDIUM
    
    def can_execute(self, context: Dict[str, Any]) -> bool:
        """Web scanner pode executar se há serviços web detectados"""
        target = context.get('target', '')
        services = context.get('services_detected', {})
        
        # Verificar se há serviços web ou se target parece ser URL
        has_web_services = any(
            'http' in str(service).lower() or 'web' in str(service).lower()
            for service in services.values() if service
        )
        
        is_url = target.startswith('http://') or target.startswith('https://')
        
        return bool(target and (has_web_services or is_url))
    
    def execute(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Executa scanner web usando módulo legado"""
        start_time = time.time()
        
        try:
            # Tentar executar método padrão
            if hasattr(self._legacy_scanner, 'executar'):
                result = self._legacy_scanner.executar(target)
            elif hasattr(self._legacy_scanner, 'scan'):
                result = self._legacy_scanner.scan(target)
            elif hasattr(self._legacy_scanner, 'execute'):
                result = self._legacy_scanner.execute(target)
            else:
                raise AttributeError(f"Scanner {self._scanner_name} não tem método conhecido")
            
            # Normalizar resultado
            normalized_result = {
                'module_name': self.name,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'execution_time': time.time() - start_time,
                'success': result.get('sucesso', result.get('success', False)),
                'capabilities_used': [ScannerCapability.WEB_SCANNING.value],
                'data': result
            }
            
            if not normalized_result['success']:
                normalized_result['error'] = result.get('erro', result.get('error', 'Web scan failed'))
            
            return normalized_result
            
        except Exception as e:
            return {
                'module_name': self.name,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'execution_time': time.time() - start_time,
                'success': False,
                'error': f'Web scanner adapter error: {str(e)}',
                'capabilities_used': [ScannerCapability.WEB_SCANNING.value],
                'data': {}
            }
    
    def get_dependencies(self) -> List[ScannerCapability]:
        """Web scanning depende de port scanning para encontrar serviços web"""
        return [ScannerCapability.PORT_SCANNING]
    
    def estimate_time(self, target: str, context: Dict[str, Any]) -> int:
        """Web scanning geralmente demora mais"""
        return 180  # 3 minutos estimados


class LegacyModuleAdapter(IScannerModule):
    """Adaptador genérico para qualquer módulo legado"""
    
    def __init__(self, legacy_module, module_name: str, capabilities: List[ScannerCapability],
                 priority: ScannerPriority = ScannerPriority.MEDIUM):
        self._legacy_module = legacy_module
        self._module_name = module_name
        self._capabilities = capabilities
        self._priority = priority
        self._name = f"{module_name}_legacy"
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def capabilities(self) -> List[ScannerCapability]:
        return self._capabilities
    
    @property
    def priority(self) -> ScannerPriority:
        return self._priority
    
    def can_execute(self, context: Dict[str, Any]) -> bool:
        """Verificação genérica - sempre pode executar se há target"""
        return bool(context.get('target'))
    
    def execute(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execução genérica tentando métodos comuns"""
        start_time = time.time()
        
        try:
            # Tentar métodos comuns
            methods_to_try = ['executar', 'execute', 'scan', 'run', 'analisar']
            result = None
            
            for method_name in methods_to_try:
                if hasattr(self._legacy_module, method_name):
                    method = getattr(self._legacy_module, method_name)
                    if callable(method):
                        # Tentar com target simples primeiro
                        try:
                            result = method(target)
                            break
                        except TypeError:
                            # Talvez precise de parâmetros adicionais
                            try:
                                result = method(target, context)
                                break
                            except TypeError:
                                continue
            
            if result is None:
                raise AttributeError(f"Nenhum método executável encontrado em {self._module_name}")
            
            # Normalizar resultado
            normalized_result = {
                'module_name': self.name,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'execution_time': time.time() - start_time,
                'success': result.get('sucesso', result.get('success', False)),
                'capabilities_used': [cap.value for cap in self.capabilities],
                'data': result
            }
            
            if not normalized_result['success']:
                normalized_result['error'] = result.get('erro', result.get('error', 'Module execution failed'))
            
            return normalized_result
            
        except Exception as e:
            return {
                'module_name': self.name,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'execution_time': time.time() - start_time,
                'success': False,
                'error': f'Legacy module adapter error: {str(e)}',
                'capabilities_used': [cap.value for cap in self.capabilities],
                'data': {}
            }
    
    def get_dependencies(self) -> List[ScannerCapability]:
        """Dependências padrão baseadas nas capacidades"""
        dependencies = []
        
        # Se faz web scanning, depende de port scanning
        if ScannerCapability.WEB_SCANNING in self._capabilities:
            dependencies.append(ScannerCapability.PORT_SCANNING)
        
        # Se faz port scanning, depende de DNS
        if ScannerCapability.PORT_SCANNING in self._capabilities:
            dependencies.append(ScannerCapability.DNS_RESOLUTION)
        
        return dependencies
    
    def estimate_time(self, target: str, context: Dict[str, Any]) -> int:
        """Estimativa baseada nas capacidades"""
        if ScannerCapability.VULNERABILITY_SCANNING in self._capabilities:
            return 600  # 10 minutos para vulnerability scanning
        elif ScannerCapability.WEB_SCANNING in self._capabilities:
            return 300  # 5 minutos para web scanning
        elif ScannerCapability.PORT_SCANNING in self._capabilities:
            return 120  # 2 minutos para port scanning
        else:
            return 60   # 1 minuto para outros
