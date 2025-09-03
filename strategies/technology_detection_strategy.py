#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Estratégia de Detecção de Tecnologias - Fase 2 da Refatoração

Integra múltiplos módulos de detecção de tecnologias:
- Detector de tecnologias nativo
- Wappalyzer integrado
- Análise de headers HTTP
- Fingerprinting de serviços
"""

from typing import Dict, Any, List, Optional, Set
from datetime import datetime
import re
import json

from interfaces.scanner_strategy import (
    ITechnologyDetectionStrategy, StrategyPriority, ExecutionPhase, StrategyResult, BaseStrategy
)
from core.scan_context import ScanContext, ServiceInfo


class TechnologyDetectionStrategy(BaseStrategy, ITechnologyDetectionStrategy):
    """Estratégia de detecção de tecnologias usando múltiplos métodos"""
    
    def __init__(self, tech_detector_module=None, wappalyzer_module=None, 
                 service_detector=None, logger=None):
        super().__init__(logger)
        self._tech_detector = tech_detector_module
        self._wappalyzer = wappalyzer_module
        self._service_detector = service_detector
        
        # Cache de resultados por URL
        self._detection_cache = {}
        
        # Padrões conhecidos para detecção passiva
        self._server_patterns = {
            'apache': r'apache[/\s](\d+\.\d+)',
            'nginx': r'nginx[/\s](\d+\.\d+)',
            'iis': r'microsoft-iis[/\s](\d+\.\d+)',
            'lighttpd': r'lighttpd[/\s](\d+\.\d+)',
            'tomcat': r'tomcat[/\s](\d+\.\d+)',
            'jetty': r'jetty[/\s](\d+\.\d+)'
        }
        
        self._technology_categories = [
            'web_servers', 'cms', 'frameworks', 'databases', 'programming_languages',
            'javascript_libraries', 'analytics', 'advertising', 'caching', 'cdn'
        ]
    
    @property
    def name(self) -> str:
        return "technology_detection"
    
    @property
    def description(self) -> str:
        return "Detecção abrangente de tecnologias usando múltiplos métodos de fingerprinting"
    
    @property
    def priority(self) -> StrategyPriority:
        return StrategyPriority.MEDIUM
    
    @property
    def execution_phase(self) -> ExecutionPhase:
        return ExecutionPhase.ENUMERATION
    
    def can_execute(self, context: ScanContext) -> bool:
        """
        Pode executar se:
        - Há serviços HTTP/HTTPS detectados
        - Há hosts ativos
        """
        # Verificar se há serviços web para analisar
        web_services_found = False
        
        for host, services in context.services.items():
            for service in services:
                if service.service_name and 'http' in service.service_name.lower():
                    web_services_found = True
                    break
            if web_services_found:
                break
        
        # Se não há serviços web específicos, verificar portas comuns
        if not web_services_found:
            web_ports = [80, 443, 8080, 8443, 8000, 8888]
            for host, ports in context.open_ports.items():
                if any(port in web_ports for port in ports):
                    web_services_found = True
                    break
        
        return web_services_found or len(context.discovered_hosts) > 0
    
    def execute(self, target: str, context: ScanContext) -> StrategyResult:
        """
        Executa detecção de tecnologias no alvo especificado
        
        Args:
            target: URL ou host a analisar
            context: Contexto do scan
            
        Returns:
            Resultado com tecnologias detectadas
        """
        self._start_execution_timer()
        self._log("INFO", f"Iniciando detecção de tecnologias para: {target}")
        
        # Determinar alvos para análise
        targets_to_analyze = self._determine_analysis_targets(target, context)
        
        if not targets_to_analyze:
            return self._create_result(
                success=False,
                warnings=[f"Nenhum alvo válido encontrado para detecção de tecnologias: {target}"]
            )
        
        # Executar detecção para cada alvo
        all_technologies = {}
        combined_confidence = 0.0
        errors = []
        warnings = []
        
        for analysis_target in targets_to_analyze:
            try:
                target_result = self._detect_technologies_for_target(analysis_target, context)
                
                if target_result['technologies']:
                    all_technologies[analysis_target] = target_result['technologies']
                    combined_confidence = max(combined_confidence, target_result['confidence'])
                
                if target_result['errors']:
                    errors.extend(target_result['errors'])
                if target_result['warnings']:
                    warnings.extend(target_result['warnings'])
                    
            except Exception as e:
                error_msg = f"Erro ao detectar tecnologias para {analysis_target}: {e}"
                errors.append(error_msg)
                self._log("ERROR", error_msg)
        
        # Processar resultados combinados
        return self._process_combined_results(all_technologies, combined_confidence, 
                                            errors, warnings, context)
    
    def detect_web_technologies(self, url: str, context: ScanContext) -> StrategyResult:
        """Implementação específica da interface ITechnologyDetectionStrategy"""
        return self.execute(url, context)
    
    def detect_technologies(self, url: str, context: ScanContext) -> StrategyResult:
        """Implementação do método abstrato da interface ITechnologyDetectionStrategy"""
        return self.execute(url, context)
    
    def get_dependencies(self) -> List[str]:
        """Preferencialmente executa após detecção de serviços"""
        return ["service_detection"]  # Opcional mas recomendado
    
    def estimate_execution_time(self, target: str, context: ScanContext) -> float:
        """
        Estima tempo baseado no número de alvos a analisar
        
        Args:
            target: Alvo a analisar
            context: Contexto atual
            
        Returns:
            Tempo estimado em segundos
        """
        targets = self._determine_analysis_targets(target, context)
        
        if not targets:
            return 5.0
        
        # ~15-30 segundos por alvo dependendo dos módulos disponíveis
        base_time_per_target = 20.0
        total_time = len(targets) * base_time_per_target
        
        return min(total_time, 300.0)  # Máximo 5 minutos
    
    def validate_target(self, target: str) -> bool:
        """Valida se o alvo pode ser analisado para tecnologias"""
        if not target or not isinstance(target, str):
            return False
        
        # URLs são válidas
        if target.startswith(('http://', 'https://')):
            return True
        
        # Hosts válidos também podem ser analisados
        return self._is_valid_host(target)
    
    def get_required_tools(self) -> List[str]:
        """Ferramentas opcionais mas úteis"""
        return ["requests", "Wappalyzer", "python-Wappalyzer"]
    
    def get_output_artifacts(self) -> List[str]:
        """Produz inventário de tecnologias"""
        return ["technology_inventory", "version_information", "server_fingerprint"]
    
    def supports_parallel_execution(self) -> bool:
        """Detecção de tecnologias pode ser paralela"""
        return True
    
    # Métodos privados
    
    def _determine_analysis_targets(self, target: str, context: ScanContext) -> List[str]:
        """Determina alvos específicos para análise de tecnologias"""
        targets = []
        
        # Se target é uma URL, usar diretamente
        if target.startswith(('http://', 'https://')):
            targets.append(target)
            return targets
        
        # Construir URLs baseado em serviços conhecidos
        host = target
        
        # Verificar serviços HTTP conhecidos
        if host in context.services:
            for service in context.services[host]:
                if 'http' in service.service_name.lower():
                    if service.port == 443 or 'https' in service.service_name.lower():
                        targets.append(f"https://{host}:{service.port}")
                    else:
                        targets.append(f"http://{host}:{service.port}")
        
        # Verificar portas web abertas
        if not targets and host in context.open_ports:
            web_ports = [80, 443, 8080, 8443, 8000, 8888, 9000]
            for port in context.open_ports[host]:
                if port in web_ports:
                    if port == 443:
                        targets.append(f"https://{host}")
                    elif port == 80:
                        targets.append(f"http://{host}")
                    else:
                        protocol = "https" if port in [443, 8443] else "http"
                        targets.append(f"{protocol}://{host}:{port}")
        
        # Fallback: tentar URLs padrão se o host parece válido
        if not targets and self._is_valid_host(host):
            targets.extend([f"http://{host}", f"https://{host}"])
        
        return list(set(targets))
    
    def _detect_technologies_for_target(self, target: str, context: ScanContext) -> Dict[str, Any]:
        """Detecta tecnologias para um alvo específico usando todos os métodos"""
        
        # Verificar cache primeiro
        if target in self._detection_cache:
            cache_entry = self._detection_cache[target]
            # Cache válido por 1 hora
            if (datetime.now() - cache_entry['timestamp']).seconds < 3600:
                return cache_entry['result']
        
        technologies = {}
        confidence = 0.0
        errors = []
        warnings = []
        
        # 1. Detector nativo de tecnologias
        if self._tech_detector:
            try:
                native_result = self._detect_with_native_detector(target)
                if native_result['success']:
                    technologies.update(native_result['technologies'])
                    confidence = max(confidence, native_result['confidence'])
                else:
                    warnings.extend(native_result.get('warnings', []))
            except Exception as e:
                warnings.append(f"Detector nativo falhou para {target}: {e}")
        
        # 2. Wappalyzer (se disponível)
        if self._wappalyzer:
            try:
                wappalyzer_result = self._detect_with_wappalyzer(target)
                if wappalyzer_result['success']:
                    technologies.update(wappalyzer_result['technologies'])
                    confidence = max(confidence, wappalyzer_result['confidence'])
                else:
                    warnings.extend(wappalyzer_result.get('warnings', []))
            except Exception as e:
                warnings.append(f"Wappalyzer falhou para {target}: {e}")
        
        # 3. Detecção passiva via headers
        try:
            passive_result = self._detect_passive_technologies(target, context)
            if passive_result['technologies']:
                technologies.update(passive_result['technologies'])
                confidence = max(confidence, passive_result['confidence'])
        except Exception as e:
            warnings.append(f"Detecção passiva falhou para {target}: {e}")
        
        # 4. Fingerprinting de serviços
        try:
            service_result = self._detect_via_service_fingerprinting(target, context)
            if service_result['technologies']:
                technologies.update(service_result['technologies'])
                confidence = max(confidence, service_result['confidence'])
        except Exception as e:
            warnings.append(f"Fingerprinting de serviços falhou para {target}: {e}")
        
        result = {
            'technologies': technologies,
            'confidence': confidence,
            'errors': errors,
            'warnings': warnings
        }
        
        # Armazenar no cache
        self._detection_cache[target] = {
            'result': result,
            'timestamp': datetime.now()
        }
        
        return result
    
    def _detect_with_native_detector(self, target: str) -> Dict[str, Any]:
        """Usa o detector nativo de tecnologias"""
        try:
            if hasattr(self._tech_detector, 'detect_technologies'):
                result = self._tech_detector.detect_technologies(target)
            elif hasattr(self._tech_detector, 'executar'):
                result = self._tech_detector.executar(target)
            else:
                return {'success': False, 'warnings': ['Detector nativo sem método conhecido']}
            
            if isinstance(result, dict) and result.get('sucesso'):
                technologies = result.get('dados', {}).get('tecnologias', {})
                
                # Normalizar formato
                normalized_tech = self._normalize_technologies(technologies)
                
                return {
                    'success': True,
                    'technologies': normalized_tech,
                    'confidence': 0.8
                }
            else:
                return {
                    'success': False,
                    'warnings': [f"Detector nativo não retornou sucesso: {result}"]
                }
                
        except Exception as e:
            return {
                'success': False,
                'warnings': [f"Erro no detector nativo: {e}"]
            }
    
    def _detect_with_wappalyzer(self, target: str) -> Dict[str, Any]:
        """Usa Wappalyzer para detecção"""
        try:
            if hasattr(self._wappalyzer, 'analyze'):
                result = self._wappalyzer.analyze(target)
            elif hasattr(self._wappalyzer, 'detect'):
                result = self._wappalyzer.detect(target)
            else:
                return {'success': False, 'warnings': ['Wappalyzer sem método conhecido']}
            
            if result:
                # Wappalyzer geralmente retorna lista de tecnologias
                if isinstance(result, (list, dict)):
                    normalized_tech = self._normalize_wappalyzer_result(result)
                    return {
                        'success': True,
                        'technologies': normalized_tech,
                        'confidence': 0.9
                    }
            
            return {'success': False, 'warnings': ['Wappalyzer não retornou resultados']}
            
        except Exception as e:
            return {
                'success': False,
                'warnings': [f"Erro no Wappalyzer: {e}"]
            }
    
    def _detect_passive_technologies(self, target: str, context: ScanContext) -> Dict[str, Any]:
        """Detecção passiva via análise de headers e informações de contexto"""
        technologies = {}
        
        # Extrair host e porta do target
        if target.startswith(('http://', 'https://')):
            import urllib.parse
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        else:
            host = target
            port = 80  # Assumir HTTP por padrão
        
        # Verificar informações de serviços no contexto
        if host in context.services:
            for service in context.services[host]:
                if service.port == port and service.version:
                    # Detectar servidor web via versão do serviço
                    server_tech = self._extract_server_from_version(service.version)
                    if server_tech:
                        technologies.update(server_tech)
        
        # Detectar tecnologias via padrões conhecidos
        confidence = 0.6 if technologies else 0.0
        
        return {
            'technologies': technologies,
            'confidence': confidence
        }
    
    def _detect_via_service_fingerprinting(self, target: str, context: ScanContext) -> Dict[str, Any]:
        """Detecção via fingerprinting de serviços conhecidos"""
        technologies = {}
        
        if not self._service_detector:
            return {'technologies': technologies, 'confidence': 0.0}
        
        try:
            # Usar detector de serviços para obter informações detalhadas
            if hasattr(self._service_detector, 'get_service_details'):
                details = self._service_detector.get_service_details(target)
                if details and isinstance(details, dict):
                    # Extrair tecnologias dos detalhes do serviço
                    service_tech = self._extract_technologies_from_service_details(details)
                    technologies.update(service_tech)
        except Exception as e:
            self._log("WARNING", f"Erro no fingerprinting de serviços: {e}")
        
        confidence = 0.7 if technologies else 0.0
        return {'technologies': technologies, 'confidence': confidence}
    
    def _normalize_technologies(self, technologies: Dict[str, Any]) -> Dict[str, Any]:
        """Normaliza formato de tecnologias para padrão comum"""
        normalized = {}
        
        for category, items in technologies.items():
            if isinstance(items, dict):
                normalized[category] = items
            elif isinstance(items, list):
                # Converter lista para dict com confidence padrão
                normalized[category] = {item: {'confidence': 0.7} for item in items}
            else:
                normalized[category] = {str(items): {'confidence': 0.7}}
        
        return normalized
    
    def _normalize_wappalyzer_result(self, result: Any) -> Dict[str, Any]:
        """Normaliza resultado do Wappalyzer"""
        normalized = {}
        
        if isinstance(result, list):
            # Lista de tecnologias
            for tech in result:
                if isinstance(tech, dict):
                    name = tech.get('name', str(tech))
                    version = tech.get('version', '')
                    category = tech.get('category', 'unknown')
                    
                    if category not in normalized:
                        normalized[category] = {}
                    
                    normalized[category][name] = {
                        'version': version,
                        'confidence': tech.get('confidence', 0.8)
                    }
                else:
                    # String simples
                    if 'unknown' not in normalized:
                        normalized['unknown'] = {}
                    normalized['unknown'][str(tech)] = {'confidence': 0.7}
        
        elif isinstance(result, dict):
            # Dict de tecnologias por categoria
            for category, techs in result.items():
                normalized[category] = {}
                if isinstance(techs, list):
                    for tech in techs:
                        normalized[category][tech] = {'confidence': 0.8}
                elif isinstance(techs, dict):
                    normalized[category] = techs
        
        return normalized
    
    def _extract_server_from_version(self, version_info: str) -> Dict[str, Any]:
        """Extrai informações do servidor web da string de versão"""
        technologies = {}
        
        if not version_info:
            return technologies
        
        version_lower = version_info.lower()
        
        for server, pattern in self._server_patterns.items():
            match = re.search(pattern, version_lower)
            if match:
                if 'web_servers' not in technologies:
                    technologies['web_servers'] = {}
                
                version = match.group(1) if match.groups() else ''
                technologies['web_servers'][server] = {
                    'version': version,
                    'confidence': 0.9,
                    'source': 'service_detection'
                }
        
        return technologies
    
    def _extract_technologies_from_service_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Extrai tecnologias dos detalhes de serviço"""
        technologies = {}
        
        # Implementar lógica específica baseada na estrutura dos detalhes
        # Isso dependeria do formato exato retornado pelo service_detector
        
        return technologies
    
    def _process_combined_results(self, all_technologies: Dict[str, Dict], confidence: float,
                                errors: List[str], warnings: List[str], 
                                context: ScanContext) -> StrategyResult:
        """Processa e combina todos os resultados de detecção"""
        
        if not all_technologies:
            return self._create_result(
                success=False,
                warnings=warnings + ["Nenhuma tecnologia detectada"],
                errors=errors
            )
        
        # Agregar estatísticas
        total_technologies = 0
        categories_found = set()
        technology_summary = {}
        
        for target, technologies in all_technologies.items():
            for category, techs in technologies.items():
                categories_found.add(category)
                total_technologies += len(techs)
                
                if category not in technology_summary:
                    technology_summary[category] = {}
                
                # Merge technologies from this target
                for tech_name, tech_info in techs.items():
                    if tech_name not in technology_summary[category]:
                        technology_summary[category][tech_name] = {
                            'targets': [],
                            'max_confidence': 0.0,
                            'version': tech_info.get('version', ''),
                            'source': tech_info.get('source', 'detection')
                        }
                    
                    technology_summary[category][tech_name]['targets'].append(target)
                    technology_summary[category][tech_name]['max_confidence'] = max(
                        technology_summary[category][tech_name]['max_confidence'],
                        tech_info.get('confidence', 0.0)
                    )
        
        # Sugerir próximas estratégias baseado nas tecnologias encontradas
        next_strategies = []
        if 'cms' in categories_found:
            next_strategies.append("vulnerability_analysis")
        if 'web_servers' in categories_found:
            next_strategies.append("web_analysis")
        if 'databases' in categories_found:
            next_strategies.append("database_scan")
        
        return self._create_result(
            success=True,
            data={
                "technologies_by_target": all_technologies,
                "technology_summary": technology_summary,
                "total_technologies": total_technologies,
                "categories_found": list(categories_found),
                "detection_complete": True
            },
            next_strategies=next_strategies,
            confidence_score=confidence,
            warnings=warnings,
            errors=errors
        )
    
    def _is_valid_host(self, host: str) -> bool:
        """Valida se é um host válido"""
        if not host or not isinstance(host, str):
            return False
        
        # Verificar formato básico
        if re.match(r'^[a-zA-Z0-9.-]+$', host):
            return True
        
        return False
