#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Estratégia de Resolução DNS - Fase 2 da Refatoração

Converte o módulo de resolução DNS existente para o padrão Strategy,
mantendo toda a funcionalidade original enquanto adiciona:
- Interface Strategy padronizada
- Contexto de execução
- Estimativas de tempo
- Validações aprimoradas
"""

from typing import Dict, Any, List
from datetime import datetime
import socket
import dns.resolver
import dns.reversename

from interfaces.scanner_strategy import (
    IDNSStrategy, StrategyPriority, ExecutionPhase, StrategyResult, BaseStrategy
)
from core.scan_context import ScanContext, ScanTarget


class DNSResolutionStrategy(BaseStrategy, IDNSStrategy):
    """Estratégia de resolução DNS usando o módulo existente como base"""
    
    def __init__(self, resolver_dns_module=None, logger=None):
        super().__init__(logger)
        self._resolver_module = resolver_dns_module
        self._dns_resolver = dns.resolver.Resolver()
        self._dns_resolver.timeout = 5
        self._dns_resolver.lifetime = 10
    
    @property
    def name(self) -> str:
        return "dns_resolution"
    
    @property
    def description(self) -> str:
        return "Resolve informações DNS básicas incluindo registros A, AAAA, MX, NS e TXT"
    
    @property
    def priority(self) -> StrategyPriority:
        return StrategyPriority.CRITICAL  # DNS é fundamental, deve executar primeiro
    
    @property
    def execution_phase(self) -> ExecutionPhase:
        return ExecutionPhase.RECONNAISSANCE
    
    def can_execute(self, context: ScanContext) -> bool:
        """
        Pode executar se:
        - O alvo inicial é um domínio (não IP)
        - Ainda não foi executada
        """
        # Verificar se é um domínio válido
        if not self._is_domain(context.initial_target):
            return False
        
        # Verificar se já foi executada
        if self.name in context.executed_strategies:
            return False
        
        return True
    
    def execute(self, target: str, context: ScanContext) -> StrategyResult:
        """
        Executa resolução DNS para o domínio especificado
        
        Args:
            target: Domínio a resolver
            context: Contexto do scan
            
        Returns:
            Resultado com informações DNS descobertas
        """
        self._start_execution_timer()
        self._log("INFO", f"Iniciando resolução DNS para: {target}")
        
        # Usar módulo existente se disponível
        if self._resolver_module:
            try:
                legacy_result = self._resolver_module.resolver_dns(target)
                return self._convert_legacy_result(legacy_result, target, context)
            except Exception as e:
                self._log("WARNING", f"Falha no módulo legado, usando implementação nativa: {e}")
        
        # Implementação nativa
        return self._resolve_dns_native(target, context)
    
    def resolve_domain(self, domain: str, context: ScanContext) -> StrategyResult:
        """Implementação específica da interface IDNSStrategy"""
        return self.execute(domain, context)
    
    def resolve_domain(self, domain: str, context: ScanContext) -> StrategyResult:
        """Implementação do método abstrato da interface IDNSStrategy"""
        return self.execute(domain, context)
    
    def get_dependencies(self) -> List[str]:
        """DNS não depende de outras estratégias"""
        return []
    
    def estimate_execution_time(self, target: str, context: ScanContext) -> float:
        """
        Estima tempo de execução baseado no número de consultas DNS
        
        Args:
            target: Domínio a resolver
            context: Contexto atual
            
        Returns:
            Tempo estimado em segundos
        """
        # DNS básico: ~2-5 segundos dependendo da resolução
        base_time = 3.0
        
        # Adicionar tempo para subdominios já descobertos
        subdomain_count = len(context.subdomains)
        additional_time = subdomain_count * 0.5  # 0.5s por subdominio adicional
        
        return min(base_time + additional_time, 30.0)  # Máximo 30 segundos
    
    def validate_target(self, target: str) -> bool:
        """Valida se o alvo é um domínio válido"""
        return self._is_domain(target)
    
    def get_required_tools(self) -> List[str]:
        """DNS resolution requer dnspython"""
        return ["dnspython"]
    
    def get_output_artifacts(self) -> List[str]:
        """Produz informações de hosts e subdomínios"""
        return ["hosts", "subdomains", "dns_records"]
    
    def supports_parallel_execution(self) -> bool:
        """DNS pode ser executado em paralelo"""
        return True
    
    # Métodos privados
    
    def _resolve_dns_native(self, target: str, context: ScanContext) -> StrategyResult:
        """Implementação nativa de resolução DNS"""
        discovered_hosts = []
        discovered_subdomains = []
        dns_records = {}
        errors = []
        warnings = []
        
        try:
            # Resolver registros A (IPv4)
            try:
                a_records = self._dns_resolver.resolve(target, 'A')
                ips = [str(record) for record in a_records]
                dns_records['A'] = ips
                discovered_hosts.extend(ips)
                self._log("INFO", f"Encontrados registros A: {ips}")
            except Exception as e:
                warnings.append(f"Erro ao resolver registros A: {e}")
            
            # Resolver registros AAAA (IPv6)
            try:
                aaaa_records = self._dns_resolver.resolve(target, 'AAAA')
                ipv6s = [str(record) for record in aaaa_records]
                dns_records['AAAA'] = ipv6s
                discovered_hosts.extend(ipv6s)
                self._log("INFO", f"Encontrados registros AAAA: {ipv6s}")
            except Exception as e:
                warnings.append(f"Erro ao resolver registros AAAA: {e}")
            
            # Resolver registros MX
            try:
                mx_records = self._dns_resolver.resolve(target, 'MX')
                mx_list = [f"{record.preference} {record.exchange}" for record in mx_records]
                dns_records['MX'] = mx_list
                self._log("INFO", f"Encontrados registros MX: {mx_list}")
                
                # Adicionar servidores MX como alvos potenciais
                for record in mx_records:
                    mx_host = str(record.exchange).rstrip('.')
                    if mx_host != target:
                        discovered_subdomains.append(mx_host)
            except Exception as e:
                warnings.append(f"Erro ao resolver registros MX: {e}")
            
            # Resolver registros NS
            try:
                ns_records = self._dns_resolver.resolve(target, 'NS')
                ns_list = [str(record) for record in ns_records]
                dns_records['NS'] = ns_list
                self._log("INFO", f"Encontrados registros NS: {ns_list}")
                
                # Adicionar nameservers como alvos potenciais
                for ns in ns_list:
                    ns_host = ns.rstrip('.')
                    if ns_host != target:
                        discovered_subdomains.append(ns_host)
            except Exception as e:
                warnings.append(f"Erro ao resolver registros NS: {e}")
            
            # Resolver registros TXT
            try:
                txt_records = self._dns_resolver.resolve(target, 'TXT')
                txt_list = [str(record) for record in txt_records]
                dns_records['TXT'] = txt_list
                self._log("INFO", f"Encontrados registros TXT: {len(txt_list)} registros")
            except Exception as e:
                warnings.append(f"Erro ao resolver registros TXT: {e}")
            
            # Tentar reverse DNS nos IPs descobertos
            for ip in discovered_hosts:
                if self._is_ipv4(ip):
                    try:
                        reverse_name = dns.reversename.from_address(ip)
                        ptr_records = self._dns_resolver.resolve(reverse_name, 'PTR')
                        for record in ptr_records:
                            ptr_host = str(record).rstrip('.')
                            if ptr_host != target and ptr_host not in discovered_subdomains:
                                discovered_subdomains.append(ptr_host)
                                self._log("INFO", f"Reverse DNS {ip} -> {ptr_host}")
                    except Exception as e:
                        # Reverse DNS pode falhar frequentemente, não é erro crítico
                        pass
            
            # Tentar descobrir subdomínios comuns
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop', 'test', 'dev']
            for subdomain in common_subdomains:
                full_subdomain = f"{subdomain}.{target}"
                try:
                    self._dns_resolver.resolve(full_subdomain, 'A')
                    discovered_subdomains.append(full_subdomain)
                    self._log("INFO", f"Subdomínio descoberto: {full_subdomain}")
                except:
                    pass  # Subdomínio não existe
            
        except Exception as e:
            errors.append(f"Erro crítico na resolução DNS: {e}")
            self._log("ERROR", f"Erro crítico na resolução DNS: {e}")
        
        # Determinar sucesso
        success = len(discovered_hosts) > 0 or len(discovered_subdomains) > 0
        confidence = 1.0 if success else 0.0
        
        # Sugerir próximas estratégias
        next_strategies = []
        if discovered_hosts:
            next_strategies.extend(["port_scan", "service_detection"])
        if discovered_subdomains:
            next_strategies.append("subdomain_enumeration")
        
        return self._create_result(
            success=success,
            data={
                "dns_records": dns_records,
                "discovered_hosts": discovered_hosts,
                "discovered_subdomains": discovered_subdomains,
                "total_hosts": len(discovered_hosts),
                "total_subdomains": len(discovered_subdomains)
            },
            errors=errors,
            warnings=warnings,
            discovered_targets=discovered_hosts + discovered_subdomains,
            next_strategies=next_strategies,
            confidence_score=confidence
        )
    
    def _convert_legacy_result(self, legacy_result: Dict[str, Any], target: str, context: ScanContext) -> StrategyResult:
        """Converte resultado do módulo legado para formato Strategy"""
        if not isinstance(legacy_result, dict):
            return self._create_result(
                success=False,
                errors=[f"Resultado legado inválido: {type(legacy_result)}"]
            )
        
        success = legacy_result.get('sucesso', False)
        
        # Extrair dados do resultado legado
        dados = legacy_result.get('dados', {})
        discovered_hosts = []
        discovered_subdomains = []
        
        # Processar diferentes formatos do módulo legado
        if 'ips' in dados:
            ips = dados['ips']
            if isinstance(ips, list):
                discovered_hosts.extend(ips)
            elif isinstance(ips, str):
                discovered_hosts.append(ips)
        
        if 'hosts' in dados:
            hosts = dados['hosts']
            if isinstance(hosts, list):
                for host in hosts:
                    if isinstance(host, dict) and 'ip' in host:
                        discovered_hosts.append(host['ip'])
                    elif isinstance(host, str):
                        discovered_hosts.append(host)
        
        # Determinar próximas estratégias
        next_strategies = []
        if discovered_hosts:
            next_strategies.extend(["port_scan", "service_detection"])
        
        return self._create_result(
            success=success,
            data={
                "legacy_data": dados,
                "discovered_hosts": discovered_hosts,
                "discovered_subdomains": discovered_subdomains
            },
            discovered_targets=discovered_hosts + discovered_subdomains,
            next_strategies=next_strategies,
            confidence_score=1.0 if success else 0.0
        )
    
    def _is_domain(self, target: str) -> bool:
        """Verifica se o target é um domínio (não IP)"""
        if not target or not isinstance(target, str):
            return False
        
        # Remover prefixos http/https se existirem
        target = target.replace('http://', '').replace('https://', '')
        
        # Verificar se é IP
        if self._is_ipv4(target) or self._is_ipv6(target):
            return False
        
        # Verificar formato básico de domínio
        if '.' not in target:
            return False
        
        # Domínio válido deve ter pelo menos 2 partes
        parts = target.split('.')
        return len(parts) >= 2 and all(len(part) > 0 for part in parts)
    
    def _is_ipv4(self, target: str) -> bool:
        """Verifica se é IPv4 válido"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _is_ipv6(self, target: str) -> bool:
        """Verifica se é IPv6 válido"""
        try:
            socket.inet_pton(socket.AF_INET6, target)
            return True
        except socket.error:
            return False
