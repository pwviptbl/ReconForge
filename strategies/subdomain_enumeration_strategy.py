#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Estratégia de Enumeração de Subdomínios - Fase 2 da Refatoração

Integra múltiplos módulos de descoberta de subdomínios:
- Scanner de subdomínios nativo
- DNS bruteforce
- Consulta de APIs externas
- Análise de certificados SSL
"""

from typing import Dict, Any, List, Optional, Set
from datetime import datetime
import re
import json

from interfaces.scanner_strategy import (
    ISubdomainEnumerationStrategy, StrategyPriority, ExecutionPhase, StrategyResult, BaseStrategy
)
from core.scan_context import ScanContext, ServiceInfo


class SubdomainEnumerationStrategy(BaseStrategy, ISubdomainEnumerationStrategy):
    """Estratégia de enumeração de subdomínios usando múltiplos métodos"""
    
    def __init__(self, subdomain_scanner_module=None, dns_module=None, 
                 certificate_analyzer_module=None, api_scanner_module=None, logger=None):
        super().__init__(logger)
        self._subdomain_scanner = subdomain_scanner_module
        self._dns_module = dns_module
        self._certificate_analyzer = certificate_analyzer_module
        self._api_scanner = api_scanner_module
        
        # Métodos de enumeração disponíveis
        self._enumeration_methods = {
            'dns_bruteforce': True,
            'certificate_transparency': True,
            'api_sources': True,
            'passive_dns': True,
            'zone_transfer': True
        }
        
        # Wordlists para bruteforce
        self._common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'www1', 'www2', 'mx', 'mx1', 'mx2', 'email', 'pop3', 'imap', 'admin',
            'blog', 'forum', 'shop', 'store', 'api', 'dev', 'test', 'staging',
            'vpn', 'remote', 'secure', 'login', 'portal', 'dashboard', 'cpanel',
            'webdisk', 'autodiscover', 'lyncdiscover', 'sip', 'exchange', 'owa'
        ]
        
        # Cache de resultados
        self._subdomain_cache = {}
    
    @property
    def name(self) -> str:
        return "subdomain_enumeration"
    
    @property
    def description(self) -> str:
        return "Enumeração abrangente de subdomínios usando múltiplos métodos e fontes"
    
    @property
    def priority(self) -> StrategyPriority:
        return StrategyPriority.MEDIUM
    
    @property
    def execution_phase(self) -> ExecutionPhase:
        return ExecutionPhase.RECONNAISSANCE
    
    def can_execute(self, context: ScanContext) -> bool:
        """
        Pode executar se:
        - Há um domínio válido identificado
        - Ainda não foi executada para o domínio
        """
        # Verificar se há alvos que parecem ser domínios
        valid_domains = []
        
        for host in context.discovered_hosts:
            if self._is_valid_domain(host):
                valid_domains.append(host)
        
        # Verificar alvos no contexto geral
        if hasattr(context, 'target') and self._is_valid_domain(context.target):
            valid_domains.append(context.target)
        
        return len(valid_domains) > 0
    
    def execute(self, target: str, context: ScanContext) -> StrategyResult:
        """
        Executa enumeração de subdomínios no domínio especificado
        
        Args:
            target: Domínio principal a enumerar
            context: Contexto do scan
            
        Returns:
            Resultado com subdomínios descobertos
        """
        self._start_execution_timer()
        self._log("INFO", f"Iniciando enumeração de subdomínios para: {target}")
        
        # Validar e normalizar o domínio
        domain = self._normalize_domain(target)
        
        if not domain:
            return self._create_result(
                success=False,
                warnings=[f"Domínio inválido para enumeração: {target}"]
            )
        
        # Verificar cache
        if domain in self._subdomain_cache:
            cache_entry = self._subdomain_cache[domain]
            # Cache válido por 2 horas
            if (datetime.now() - cache_entry['timestamp']).seconds < 7200:
                self._log("INFO", f"Usando resultados em cache para {domain}")
                return cache_entry['result']
        
        # Executar métodos de enumeração
        all_subdomains = set()
        enumeration_results = {
            'dns_bruteforce': {'success': False, 'count': 0},
            'certificate_transparency': {'success': False, 'count': 0},
            'api_sources': {'success': False, 'count': 0},
            'passive_dns': {'success': False, 'count': 0},
            'zone_transfer': {'success': False, 'count': 0}
        }
        errors = []
        warnings = []
        
        # 1. DNS Bruteforce
        if self._enumeration_methods['dns_bruteforce']:
            try:
                bruteforce_result = self._dns_bruteforce_enumeration(domain, context)
                all_subdomains.update(bruteforce_result['subdomains'])
                enumeration_results['dns_bruteforce'] = {
                    'success': bruteforce_result['success'],
                    'count': len(bruteforce_result['subdomains'])
                }
                if bruteforce_result['errors']:
                    errors.extend(bruteforce_result['errors'])
                if bruteforce_result['warnings']:
                    warnings.extend(bruteforce_result['warnings'])
            except Exception as e:
                error_msg = f"Erro no DNS bruteforce: {e}"
                errors.append(error_msg)
                self._log("ERROR", error_msg)
        
        # 2. Certificate Transparency Logs
        if self._enumeration_methods['certificate_transparency']:
            try:
                cert_result = self._certificate_transparency_enumeration(domain, context)
                all_subdomains.update(cert_result['subdomains'])
                enumeration_results['certificate_transparency'] = {
                    'success': cert_result['success'],
                    'count': len(cert_result['subdomains'])
                }
                if cert_result['errors']:
                    errors.extend(cert_result['errors'])
                if cert_result['warnings']:
                    warnings.extend(cert_result['warnings'])
            except Exception as e:
                error_msg = f"Erro nos logs de transparência: {e}"
                errors.append(error_msg)
                self._log("ERROR", error_msg)
        
        # 3. API Sources
        if self._enumeration_methods['api_sources']:
            try:
                api_result = self._api_sources_enumeration(domain, context)
                all_subdomains.update(api_result['subdomains'])
                enumeration_results['api_sources'] = {
                    'success': api_result['success'],
                    'count': len(api_result['subdomains'])
                }
                if api_result['errors']:
                    errors.extend(api_result['errors'])
                if api_result['warnings']:
                    warnings.extend(api_result['warnings'])
            except Exception as e:
                error_msg = f"Erro nas fontes de API: {e}"
                errors.append(error_msg)
                self._log("ERROR", error_msg)
        
        # 4. Passive DNS
        if self._enumeration_methods['passive_dns']:
            try:
                passive_result = self._passive_dns_enumeration(domain, context)
                all_subdomains.update(passive_result['subdomains'])
                enumeration_results['passive_dns'] = {
                    'success': passive_result['success'],
                    'count': len(passive_result['subdomains'])
                }
                if passive_result['errors']:
                    errors.extend(passive_result['errors'])
                if passive_result['warnings']:
                    warnings.extend(passive_result['warnings'])
            except Exception as e:
                error_msg = f"Erro no DNS passivo: {e}"
                errors.append(error_msg)
                self._log("ERROR", error_msg)
        
        # 5. Zone Transfer
        if self._enumeration_methods['zone_transfer']:
            try:
                zone_result = self._zone_transfer_enumeration(domain, context)
                all_subdomains.update(zone_result['subdomains'])
                enumeration_results['zone_transfer'] = {
                    'success': zone_result['success'],
                    'count': len(zone_result['subdomains'])
                }
                if zone_result['errors']:
                    errors.extend(zone_result['errors'])
                if zone_result['warnings']:
                    warnings.extend(zone_result['warnings'])
            except Exception as e:
                error_msg = f"Erro na transferência de zona: {e}"
                errors.append(error_msg)
                self._log("ERROR", error_msg)
        
        # Processar resultados
        result = self._process_enumeration_results(domain, all_subdomains, 
                                                 enumeration_results, errors, warnings, context)
        
        # Armazenar no cache
        self._subdomain_cache[domain] = {
            'result': result,
            'timestamp': datetime.now()
        }
        
        return result
    
    def enumerate_subdomains(self, domain: str, methods: List[str], 
                           context: ScanContext) -> StrategyResult:
        """Implementação específica da interface ISubdomainEnumerationStrategy"""
        # Filtrar métodos solicitados
        original_methods = self._enumeration_methods.copy()
        
        # Desabilitar todos os métodos primeiro
        for method in self._enumeration_methods:
            self._enumeration_methods[method] = False
        
        # Habilitar apenas os métodos solicitados
        for method in methods:
            if method in self._enumeration_methods:
                self._enumeration_methods[method] = True
        
        result = self.execute(domain, context)
        
        # Restaurar métodos originais
        self._enumeration_methods = original_methods
        
        return result
    
    def get_dependencies(self) -> List[str]:
        """Preferencialmente executa após resolução DNS inicial"""
        return ["dns_resolution"]
    
    def estimate_execution_time(self, target: str, context: ScanContext) -> float:
        """
        Estima tempo baseado nos métodos habilitados
        
        Args:
            target: Domínio a enumerar
            context: Contexto atual
            
        Returns:
            Tempo estimado em segundos
        """
        domain = self._normalize_domain(target)
        
        if not domain:
            return 10.0
        
        # Estimativas por método
        method_times = {
            'dns_bruteforce': 120,  # 2 minutos
            'certificate_transparency': 30,  # 30 segundos
            'api_sources': 60,  # 1 minuto
            'passive_dns': 45,  # 45 segundos
            'zone_transfer': 15  # 15 segundos
        }
        
        total_time = sum(
            method_times[method] for method, enabled in self._enumeration_methods.items()
            if enabled
        )
        
        return min(total_time, 600.0)  # Máximo 10 minutos
    
    def validate_target(self, target: str) -> bool:
        """Valida se o alvo é um domínio válido"""
        return self._is_valid_domain(self._normalize_domain(target))
    
    def get_required_tools(self) -> List[str]:
        """Ferramentas úteis para enumeração"""
        return ["subfinder", "assetfinder", "amass", "dnsrecon"]
    
    def get_output_artifacts(self) -> List[str]:
        """Produz lista de subdomínios e relatório de enumeração"""
        return ["subdomain_list", "enumeration_report", "dns_records"]
    
    def supports_parallel_execution(self) -> bool:
        """Enumeração pode ser paralela para diferentes métodos"""
        return True
    
    # Métodos privados
    
    def _normalize_domain(self, target: str) -> str:
        """Normaliza e extrai domínio do target"""
        if not target or not isinstance(target, str):
            return ""
        
        # Remover protocolo se presente
        if target.startswith(('http://', 'https://')):
            import urllib.parse
            parsed = urllib.parse.urlparse(target)
            target = parsed.netloc
        
        # Remover porta se presente
        if ':' in target:
            target = target.split(':')[0]
        
        # Verificar se é um domínio válido
        if self._is_valid_domain(target):
            return target.lower()
        
        return ""
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Verifica se é um domínio válido"""
        if not domain or not isinstance(domain, str):
            return False
        
        # Padrão básico para domínios
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}|[a-zA-Z]{2,}\.[a-zA-Z]{2,})$'
        
        # Verificar se tem pelo menos um ponto e formato válido
        if '.' not in domain:
            return False
        
        return re.match(domain_pattern, domain) is not None
    
    def _dns_bruteforce_enumeration(self, domain: str, context: ScanContext) -> Dict[str, Any]:
        """Enumeração via DNS bruteforce"""
        subdomains = set()
        success = False
        errors = []
        warnings = []
        
        try:
            # Usar scanner de subdomínios se disponível
            if self._subdomain_scanner:
                scanner_result = self._execute_subdomain_scanner(domain, context)
                if scanner_result['success']:
                    subdomains.update(scanner_result['subdomains'])
                    success = True
                else:
                    warnings.extend(scanner_result.get('warnings', []))
            
            # Bruteforce manual com wordlist comum
            if self._dns_module:
                bruteforce_result = self._manual_dns_bruteforce(domain, context)
                if bruteforce_result['success']:
                    subdomains.update(bruteforce_result['subdomains'])
                    success = True
                else:
                    warnings.extend(bruteforce_result.get('warnings', []))
            
        except Exception as e:
            errors.append(f"Erro no DNS bruteforce: {e}")
        
        return {
            'subdomains': list(subdomains),
            'success': success,
            'errors': errors,
            'warnings': warnings
        }
    
    def _certificate_transparency_enumeration(self, domain: str, context: ScanContext) -> Dict[str, Any]:
        """Enumeração via logs de transparência de certificados"""
        subdomains = set()
        success = False
        errors = []
        warnings = []
        
        try:
            if self._certificate_analyzer:
                cert_result = self._search_certificate_logs(domain, context)
                if cert_result['success']:
                    subdomains.update(cert_result['subdomains'])
                    success = True
                else:
                    warnings.extend(cert_result.get('warnings', []))
            else:
                warnings.append("Analisador de certificados não disponível")
        
        except Exception as e:
            errors.append(f"Erro nos logs de certificado: {e}")
        
        return {
            'subdomains': list(subdomains),
            'success': success,
            'errors': errors,
            'warnings': warnings
        }
    
    def _api_sources_enumeration(self, domain: str, context: ScanContext) -> Dict[str, Any]:
        """Enumeração via APIs externas"""
        subdomains = set()
        success = False
        errors = []
        warnings = []
        
        try:
            if self._api_scanner:
                api_result = self._query_external_apis(domain, context)
                if api_result['success']:
                    subdomains.update(api_result['subdomains'])
                    success = True
                else:
                    warnings.extend(api_result.get('warnings', []))
            else:
                warnings.append("Scanner de APIs não disponível")
        
        except Exception as e:
            errors.append(f"Erro nas APIs externas: {e}")
        
        return {
            'subdomains': list(subdomains),
            'success': success,
            'errors': errors,
            'warnings': warnings
        }
    
    def _passive_dns_enumeration(self, domain: str, context: ScanContext) -> Dict[str, Any]:
        """Enumeração via DNS passivo"""
        subdomains = set()
        success = False
        errors = []
        warnings = []
        
        try:
            if self._dns_module:
                passive_result = self._query_passive_dns(domain, context)
                if passive_result['success']:
                    subdomains.update(passive_result['subdomains'])
                    success = True
                else:
                    warnings.extend(passive_result.get('warnings', []))
            else:
                warnings.append("Módulo DNS não disponível para consulta passiva")
        
        except Exception as e:
            errors.append(f"Erro no DNS passivo: {e}")
        
        return {
            'subdomains': list(subdomains),
            'success': success,
            'errors': errors,
            'warnings': warnings
        }
    
    def _zone_transfer_enumeration(self, domain: str, context: ScanContext) -> Dict[str, Any]:
        """Enumeração via transferência de zona"""
        subdomains = set()
        success = False
        errors = []
        warnings = []
        
        try:
            if self._dns_module:
                zone_result = self._attempt_zone_transfer(domain, context)
                if zone_result['success']:
                    subdomains.update(zone_result['subdomains'])
                    success = True
                else:
                    warnings.extend(zone_result.get('warnings', []))
            else:
                warnings.append("Módulo DNS não disponível para transferência de zona")
        
        except Exception as e:
            errors.append(f"Erro na transferência de zona: {e}")
        
        return {
            'subdomains': list(subdomains),
            'success': success,
            'errors': errors,
            'warnings': warnings
        }
    
    def _execute_subdomain_scanner(self, domain: str, context: ScanContext) -> Dict[str, Any]:
        """Executa scanner de subdomínios especializado"""
        try:
            if hasattr(self._subdomain_scanner, 'scan_subdomains'):
                result = self._subdomain_scanner.scan_subdomains(domain)
            elif hasattr(self._subdomain_scanner, 'executar'):
                result = self._subdomain_scanner.executar(domain)
            else:
                return {'success': False, 'warnings': ['Scanner sem método conhecido']}
            
            if isinstance(result, dict) and result.get('sucesso'):
                subdomains = result.get('dados', {}).get('subdominios', [])
                return {
                    'success': True,
                    'subdomains': subdomains
                }
            else:
                return {
                    'success': False,
                    'warnings': [f"Scanner retornou: {result}"]
                }
                
        except Exception as e:
            return {
                'success': False,
                'warnings': [f"Erro no scanner: {e}"]
            }
    
    def _manual_dns_bruteforce(self, domain: str, context: ScanContext) -> Dict[str, Any]:
        """Bruteforce manual usando wordlist comum"""
        subdomains = []
        
        try:
            if hasattr(self._dns_module, 'resolve_hostname'):
                for subdomain in self._common_subdomains:
                    full_domain = f"{subdomain}.{domain}"
                    try:
                        result = self._dns_module.resolve_hostname(full_domain)
                        if result and result.get('success'):
                            subdomains.append(full_domain)
                    except:
                        continue  # Ignorar falhas individuais
            
            return {
                'success': len(subdomains) > 0,
                'subdomains': subdomains,
                'warnings': [] if subdomains else ["Nenhum subdomínio encontrado via bruteforce manual"]
            }
            
        except Exception as e:
            return {
                'success': False,
                'subdomains': [],
                'warnings': [f"Erro no bruteforce manual: {e}"]
            }
    
    def _search_certificate_logs(self, domain: str, context: ScanContext) -> Dict[str, Any]:
        """Busca subdomínios nos logs de certificados"""
        try:
            if hasattr(self._certificate_analyzer, 'search_ct_logs'):
                result = self._certificate_analyzer.search_ct_logs(domain)
            elif hasattr(self._certificate_analyzer, 'buscar_certificados'):
                result = self._certificate_analyzer.buscar_certificados(domain)
            else:
                return {'success': False, 'warnings': ['Analisador sem método conhecido']}
            
            if isinstance(result, dict) and result.get('subdomains'):
                return {
                    'success': True,
                    'subdomains': result['subdomains']
                }
            else:
                return {
                    'success': False,
                    'warnings': [f"Analisador retornou: {result}"]
                }
                
        except Exception as e:
            return {
                'success': False,
                'warnings': [f"Erro no analisador de certificados: {e}"]
            }
    
    def _query_external_apis(self, domain: str, context: ScanContext) -> Dict[str, Any]:
        """Consulta APIs externas para subdomínios"""
        try:
            if hasattr(self._api_scanner, 'query_apis'):
                result = self._api_scanner.query_apis(domain)
            elif hasattr(self._api_scanner, 'consultar_apis'):
                result = self._api_scanner.consultar_apis(domain)
            else:
                return {'success': False, 'warnings': ['Scanner de API sem método conhecido']}
            
            if isinstance(result, dict) and result.get('subdomains'):
                return {
                    'success': True,
                    'subdomains': result['subdomains']
                }
            else:
                return {
                    'success': False,
                    'warnings': [f"Scanner de API retornou: {result}"]
                }
                
        except Exception as e:
            return {
                'success': False,
                'warnings': [f"Erro no scanner de API: {e}"]
            }
    
    def _query_passive_dns(self, domain: str, context: ScanContext) -> Dict[str, Any]:
        """Consulta DNS passivo para subdomínios"""
        try:
            if hasattr(self._dns_module, 'passive_dns_query'):
                result = self._dns_module.passive_dns_query(domain)
            elif hasattr(self._dns_module, 'consulta_passiva'):
                result = self._dns_module.consulta_passiva(domain)
            else:
                return {'success': False, 'warnings': ['Módulo DNS sem método de consulta passiva']}
            
            if isinstance(result, dict) and result.get('subdomains'):
                return {
                    'success': True,
                    'subdomains': result['subdomains']
                }
            else:
                return {
                    'success': False,
                    'warnings': [f"DNS passivo retornou: {result}"]
                }
                
        except Exception as e:
            return {
                'success': False,
                'warnings': [f"Erro no DNS passivo: {e}"]
            }
    
    def _attempt_zone_transfer(self, domain: str, context: ScanContext) -> Dict[str, Any]:
        """Tenta transferência de zona DNS"""
        try:
            if hasattr(self._dns_module, 'zone_transfer'):
                result = self._dns_module.zone_transfer(domain)
            elif hasattr(self._dns_module, 'transferencia_zona'):
                result = self._dns_module.transferencia_zona(domain)
            else:
                return {'success': False, 'warnings': ['Módulo DNS sem método de transferência de zona']}
            
            if isinstance(result, dict) and result.get('success'):
                return {
                    'success': True,
                    'subdomains': result.get('subdomains', [])
                }
            else:
                return {
                    'success': False,
                    'warnings': [f"Transferência de zona falhou: {result}"]
                }
                
        except Exception as e:
            return {
                'success': False,
                'warnings': [f"Erro na transferência de zona: {e}"]
            }
    
    def _process_enumeration_results(self, domain: str, all_subdomains: Set[str], 
                                   enumeration_results: Dict, errors: List[str], 
                                   warnings: List[str], context: ScanContext) -> StrategyResult:
        """Processa resultados finais da enumeração"""
        
        # Filtrar e validar subdomínios
        valid_subdomains = []
        for subdomain in all_subdomains:
            if subdomain and self._is_valid_subdomain(subdomain, domain):
                valid_subdomains.append(subdomain)
        
        # Adicionar subdomínios descobertos ao contexto
        context.discovered_hosts.extend(valid_subdomains)
        
        # Calcular estatísticas
        total_methods_used = sum(1 for result in enumeration_results.values() if result['success'])
        total_subdomains = len(valid_subdomains)
        
        # Determinar sucesso
        success = total_subdomains > 0
        confidence = min(0.8 + (total_methods_used * 0.1), 1.0) if success else 0.3
        
        # Sugerir próximas estratégias
        next_strategies = []
        if valid_subdomains:
            next_strategies.extend(["port_scan", "service_detection", "web_analysis"])
        
        return self._create_result(
            success=success,
            data={
                "domain": domain,
                "subdomains_found": total_subdomains,
                "subdomains": valid_subdomains,
                "enumeration_methods": enumeration_results,
                "methods_successful": total_methods_used,
                "enumeration_complete": True
            },
            next_strategies=next_strategies,
            confidence_score=confidence,
            warnings=warnings,
            errors=errors
        )
    
    def _is_valid_subdomain(self, subdomain: str, parent_domain: str) -> bool:
        """Verifica se é um subdomínio válido do domínio pai"""
        if not subdomain or not parent_domain:
            return False
        
        # Verificar se termina com o domínio pai
        if not subdomain.endswith(f".{parent_domain}"):
            return False
        
        # Verificar formato geral
        return self._is_valid_domain(subdomain)
