#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Estratégia de Análise Web - Fase 2 da Refatoração

Integra múltiplos módulos de análise web existentes em uma estratégia unificada:
- Scanner web avançado
- Navegador web com IA
- Detector de tecnologias
- Scanner de diretórios
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import re
import urllib.parse

from interfaces.scanner_strategy import (
    IWebAnalysisStrategy, StrategyPriority, ExecutionPhase, StrategyResult, BaseStrategy
)
from core.scan_context import ScanContext, ServiceInfo


class WebAnalysisStrategy(BaseStrategy, IWebAnalysisStrategy):
    """Estratégia unificada de análise web usando múltiplos módulos"""
    
    def __init__(self, web_scanner_module=None, navegador_module=None, 
                 tech_detector_module=None, logger=None):
        super().__init__(logger)
        self._web_scanner = web_scanner_module
        self._navegador_module = navegador_module
        self._tech_detector = tech_detector_module
        
        # Padrões para detecção de URLs web
        self._web_ports = [80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 3000, 5000]
        self._web_services = ['http', 'https', 'http-alt', 'https-alt', 'http-proxy']
    
    @property
    def name(self) -> str:
        return "web_analysis"
    
    @property
    def description(self) -> str:
        return "Análise abrangente de aplicações web incluindo tecnologias, diretórios e vulnerabilidades"
    
    @property
    def priority(self) -> StrategyPriority:
        return StrategyPriority.MEDIUM
    
    @property
    def execution_phase(self) -> ExecutionPhase:
        return ExecutionPhase.ENUMERATION
    
    def can_execute(self, context: ScanContext) -> bool:
        """
        Pode executar se:
        - Há serviços web detectados (HTTP/HTTPS)
        - Ainda não foi executada para todos os serviços web
        """
        # Verificar se há serviços web conhecidos
        web_services_found = False
        
        for host, services in context.services.items():
            for service in services:
                if (service.port in self._web_ports or 
                    service.service_name.lower() in self._web_services):
                    web_services_found = True
                    break
            if web_services_found:
                break
        
        # Também verificar se há portas web abertas
        if not web_services_found:
            for host, ports in context.open_ports.items():
                if any(port in self._web_ports for port in ports):
                    web_services_found = True
                    break
        
        if not web_services_found:
            return False
        
        # Verificar se já foi executada (permitir re-execução para diferentes URLs)
        return True
    
    def execute(self, target: str, context: ScanContext) -> StrategyResult:
        """
        Executa análise web completa no alvo especificado
        
        Args:
            target: URL ou host a analisar
            context: Contexto do scan
            
        Returns:
            Resultado com descobertas web
        """
        self._start_execution_timer()
        self._log("INFO", f"Iniciando análise web para: {target}")
        
        # Determinar URLs para analisar
        urls_to_analyze = self._determine_web_urls(target, context)
        
        if not urls_to_analyze:
            return self._create_result(
                success=False,
                warnings=[f"Nenhuma URL web válida encontrada para {target}"]
            )
        
        # Executar análise para cada URL
        combined_results = {
            'technologies': {},
            'directories': {},
            'vulnerabilities': [],
            'forms': {},
            'cookies': {},
            'headers': {},
            'urls_analyzed': urls_to_analyze
        }
        
        errors = []
        warnings = []
        
        for url in urls_to_analyze:
            try:
                url_result = self._analyze_single_url(url, context)
                self._merge_url_results(combined_results, url_result, url)
            except Exception as e:
                error_msg = f"Erro ao analisar {url}: {e}"
                errors.append(error_msg)
                self._log("ERROR", error_msg)
        
        # Processar resultados combinados
        return self._create_combined_result(combined_results, errors, warnings, context)
    
    def analyze_web_application(self, url: str, credentials: Optional[Dict[str, str]], 
                               context: ScanContext) -> StrategyResult:
        """Implementação específica da interface IWebAnalysisStrategy"""
        # Adicionar credenciais ao contexto se fornecidas
        if credentials:
            context.user_preferences['web_credentials'] = credentials
        
        return self.execute(url, context)
    
    def get_dependencies(self) -> List[str]:
        """Depende de detecção de serviços para identificar serviços web"""
        return ["service_detection"]
    
    def estimate_execution_time(self, target: str, context: ScanContext) -> float:
        """
        Estima tempo baseado no número de URLs web a analisar
        
        Args:
            target: Alvo a analisar
            context: Contexto atual
            
        Returns:
            Tempo estimado em segundos
        """
        urls = self._determine_web_urls(target, context)
        
        if not urls:
            return 10.0  # Verificação básica
        
        # ~30-60 segundos por URL dependendo da profundidade
        base_time_per_url = 45.0
        total_time = len(urls) * base_time_per_url
        
        # Adicionar tempo para navegação com IA se disponível
        if self._navegador_module:
            total_time += len(urls) * 20.0
        
        return min(total_time, 600.0)  # Máximo 10 minutos
    
    def validate_target(self, target: str) -> bool:
        """Valida se o alvo pode ser uma URL web válida"""
        if not target or not isinstance(target, str):
            return False
        
        # Se já é uma URL, validar
        if target.startswith(('http://', 'https://')):
            return self._is_valid_url(target)
        
        # Se é um host, pode ser convertido para URL
        return self._is_valid_host(target)
    
    def get_required_tools(self) -> List[str]:
        """Ferramentas opcionais mas recomendadas"""
        return ["requests", "beautifulsoup4", "selenium"]  # Opcionais
    
    def get_output_artifacts(self) -> List[str]:
        """Produz análise web abrangente"""
        return ["web_technologies", "web_directories", "web_vulnerabilities", "web_forms"]
    
    def supports_parallel_execution(self) -> bool:
        """Análise web pode ser complexa, melhor executar sequencialmente"""
        return False
    
    # Métodos privados
    
    def _determine_web_urls(self, target: str, context: ScanContext) -> List[str]:
        """Determina URLs web para analisar baseado no target e contexto"""
        urls = []
        
        # Se target já é uma URL, usar diretamente
        if target.startswith(('http://', 'https://')):
            urls.append(target)
            return urls
        
        # Construir URLs baseado em serviços web conhecidos
        host = target
        
        # Verificar serviços conhecidos
        if host in context.services:
            for service in context.services[host]:
                if service.port in self._web_ports or service.service_name.lower() in self._web_services:
                    if service.port == 443 or 'https' in service.service_name.lower():
                        urls.append(f"https://{host}:{service.port}")
                    else:
                        urls.append(f"http://{host}:{service.port}")
        
        # Verificar portas abertas se não há serviços conhecidos
        if not urls and host in context.open_ports:
            for port in context.open_ports[host]:
                if port in self._web_ports:
                    if port == 443:
                        urls.append(f"https://{host}:{port}")
                    elif port == 80:
                        urls.append(f"http://{host}")
                    else:
                        urls.append(f"http://{host}:{port}")
        
        # Fallback: tentar URLs padrão
        if not urls:
            urls.extend([f"http://{host}", f"https://{host}"])
        
        return list(set(urls))  # Remover duplicatas
    
    def _analyze_single_url(self, url: str, context: ScanContext) -> Dict[str, Any]:
        """Analisa uma única URL usando todos os módulos disponíveis"""
        results = {
            'technologies': {},
            'directories': [],
            'vulnerabilities': [],
            'forms': [],
            'navigation_data': {},
            'scan_data': {}
        }
        
        # 1. Detecção de tecnologias
        if self._tech_detector:
            try:
                tech_result = self._tech_detector.detect_technologies(url)
                if isinstance(tech_result, dict) and tech_result.get('sucesso'):
                    results['technologies'] = tech_result.get('dados', {}).get('tecnologias', {})
                    self._log("INFO", f"Tecnologias detectadas para {url}: {len(results['technologies'])}")
            except Exception as e:
                self._log("WARNING", f"Erro na detecção de tecnologias para {url}: {e}")
        
        # 2. Scanner web avançado
        if self._web_scanner:
            try:
                scan_result = self._web_scanner.scan_completo(url)
                if isinstance(scan_result, dict) and 'vulnerabilidades' in scan_result:
                    results['vulnerabilities'] = scan_result['vulnerabilidades']
                    results['scan_data'] = scan_result
                    self._log("INFO", f"Scanner web executado para {url}: {len(results['vulnerabilities'])} vulnerabilidades")
            except Exception as e:
                self._log("WARNING", f"Erro no scanner web para {url}: {e}")
        
        # 3. Navegação com IA (se disponível)
        if self._navegador_module:
            try:
                credentials = context.user_preferences.get('web_credentials')
                if hasattr(self._navegador_module, 'executar_para_orquestrador'):
                    nav_result = self._navegador_module.executar_para_orquestrador(
                        alvo=url,
                        credenciais=credentials,
                        modo='web'
                    )
                else:
                    nav_result = self._navegador_module.executar(url, credentials)
                
                if isinstance(nav_result, dict) and nav_result.get('sucesso'):
                    nav_data = nav_result.get('dados', {})
                    results['navigation_data'] = nav_data
                    results['forms'] = nav_data.get('formularios', [])
                    self._log("INFO", f"Navegação IA executada para {url}")
            except Exception as e:
                self._log("WARNING", f"Erro na navegação IA para {url}: {e}")
        
        return results
    
    def _merge_url_results(self, combined: Dict[str, Any], url_result: Dict[str, Any], url: str) -> None:
        """Combina resultados de uma URL com os resultados gerais"""
        # Merge technologies
        if url_result.get('technologies'):
            combined['technologies'][url] = url_result['technologies']
        
        # Merge vulnerabilities
        if url_result.get('vulnerabilities'):
            for vuln in url_result['vulnerabilities']:
                if isinstance(vuln, dict):
                    vuln['url'] = url  # Adicionar URL ao contexto
                combined['vulnerabilities'].append(vuln)
        
        # Merge forms
        if url_result.get('forms'):
            combined['forms'][url] = url_result['forms']
        
        # Merge navigation data
        if url_result.get('navigation_data'):
            nav_data = url_result['navigation_data']
            if 'headers_seguranca' in nav_data:
                combined['headers'][url] = nav_data['headers_seguranca']
            if 'cookies' in nav_data:
                combined['cookies'][url] = nav_data['cookies']
    
    def _create_combined_result(self, combined_results: Dict[str, Any], errors: List[str], 
                               warnings: List[str], context: ScanContext) -> StrategyResult:
        """Cria resultado final combinando todas as descobertas"""
        
        # Contar descobertas
        total_technologies = sum(len(techs) for techs in combined_results['technologies'].values())
        total_vulnerabilities = len(combined_results['vulnerabilities'])
        total_forms = sum(len(forms) for forms in combined_results['forms'].values())
        
        # Determinar sucesso
        success = (total_technologies > 0 or total_vulnerabilities > 0 or total_forms > 0)
        confidence = 0.8 if success else 0.3
        
        # Organizar serviços descobertos
        discovered_services = {}
        for url in combined_results['urls_analyzed']:
            host = urllib.parse.urlparse(url).netloc.split(':')[0]
            port = urllib.parse.urlparse(url).port
            
            if port is None:
                port = 443 if url.startswith('https') else 80
            
            if host not in discovered_services:
                discovered_services[host] = []
            
            service_data = {
                'port': port,
                'service': 'https' if url.startswith('https') else 'http',
                'url': url,
                'technologies': combined_results['technologies'].get(url, {}),
                'forms_count': len(combined_results['forms'].get(url, [])),
                'state': 'open'
            }
            
            discovered_services[host].append(service_data)
        
        # Converter vulnerabilidades para formato padrão
        formatted_vulnerabilities = []
        for vuln in combined_results['vulnerabilities']:
            if isinstance(vuln, dict):
                formatted_vuln = {
                    'id': vuln.get('id', f"web_vuln_{len(formatted_vulnerabilities)}"),
                    'name': vuln.get('tipo', vuln.get('name', 'Web Vulnerability')),
                    'description': vuln.get('descricao', vuln.get('description', '')),
                    'severity': vuln.get('severidade', vuln.get('severity', 'medium')),
                    'url': vuln.get('url', ''),
                    'confidence': vuln.get('confianca', 0.7)
                }
                formatted_vulnerabilities.append(formatted_vuln)
        
        # Sugerir próximas estratégias
        next_strategies = []
        if total_vulnerabilities > 0:
            next_strategies.append("vulnerability_analysis")
        if any('cms' in str(tech).lower() for tech in combined_results['technologies'].values()):
            next_strategies.append("directory_scan")
        
        return self._create_result(
            success=success,
            data={
                "urls_analyzed": combined_results['urls_analyzed'],
                "technologies_found": total_technologies,
                "vulnerabilities_found": total_vulnerabilities,
                "forms_found": total_forms,
                "detailed_technologies": combined_results['technologies'],
                "security_headers": combined_results['headers'],
                "cookies_analysis": combined_results['cookies'],
                "web_analysis_complete": True
            },
            discovered_services=discovered_services,
            vulnerabilities=formatted_vulnerabilities,
            next_strategies=next_strategies,
            confidence_score=confidence,
            errors=errors,
            warnings=warnings
        )
    
    def _is_valid_url(self, url: str) -> bool:
        """Valida se é uma URL válida"""
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.scheme in ['http', 'https'] and parsed.netloc
        except:
            return False
    
    def _is_valid_host(self, host: str) -> bool:
        """Valida se é um host válido"""
        if not host or not isinstance(host, str):
            return False
        
        # Verificar formato básico
        if re.match(r'^[a-zA-Z0-9.-]+$', host):
            return True
        
        return False
