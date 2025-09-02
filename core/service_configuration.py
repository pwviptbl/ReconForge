#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sistema de configuração de serviços - Fase 1 da Refatoração

Permite configurar serviços através de arquivos YAML,
definindo implementações, ciclo de vida e dependências.
"""

import yaml
import os
from typing import Dict, Any, Type, Optional, Callable
from pathlib import Path

from .dependency_container import DependencyContainer, ServiceLifetime
from interfaces import *


class ServiceConfiguration:
    """Carregador e configurador de serviços"""
    
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'services.yaml')
        
        self.config_path = Path(config_path)
        self.config_data: Dict[str, Any] = {}
        self._load_config()
    
    def _load_config(self):
        """Carrega configuração do arquivo YAML"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self.config_data = yaml.safe_load(f) or {}
            else:
                # Criar configuração padrão se não existir
                self._create_default_config()
        except Exception as e:
            print(f"Erro ao carregar configuração de serviços: {e}")
            self._create_default_config()
    
    def _create_default_config(self):
        """Cria configuração padrão"""
        self.config_data = {
            'profiles': {
                'development': {
                    'services': {
                        'logger_factory': {
                            'implementation': 'utils.logger.DefaultLoggerFactory',
                            'lifetime': 'singleton',
                            'config': {
                                'level': 'DEBUG',
                                'console_output': True,
                                'file_output': True
                            }
                        },
                        'persistence_layer': {
                            'implementation': 'infra.file_persistence.FilePersistenceLayer',
                            'lifetime': 'singleton',
                            'config': {
                                'base_path': 'dados',
                                'format': 'json'
                            }
                        },
                        'report_generator': {
                            'implementation': 'relatorios.html_generator.HtmlReportGenerator',
                            'lifetime': 'singleton'
                        }
                    }
                },
                'production': {
                    'services': {
                        'logger_factory': {
                            'implementation': 'utils.logger.DefaultLoggerFactory',
                            'lifetime': 'singleton',
                            'config': {
                                'level': 'INFO',
                                'console_output': False,
                                'file_output': True
                            }
                        },
                        'persistence_layer': {
                            'implementation': 'infra.file_persistence.FilePersistenceLayer',
                            'lifetime': 'singleton',
                            'config': {
                                'base_path': 'dados',
                                'format': 'json',
                                'backup_enabled': True
                            }
                        },
                        'report_generator': {
                            'implementation': 'relatorios.html_generator.HtmlReportGenerator',
                            'lifetime': 'singleton'
                        }
                    }
                },
                'testing': {
                    'services': {
                        'logger_factory': {
                            'implementation': 'utils.logger.MockLoggerFactory',
                            'lifetime': 'singleton'
                        },
                        'persistence_layer': {
                            'implementation': 'tests.mocks.MockPersistenceLayer',
                            'lifetime': 'singleton'
                        },
                        'report_generator': {
                            'implementation': 'tests.mocks.MockReportGenerator',
                            'lifetime': 'singleton'
                        }
                    }
                }
            },
            'module_mappings': {
                'dns_resolver': {
                    'implementation': 'adapters.legacy_adapters.DNSResolverAdapter',
                    'legacy_module': 'modulos.resolucao_dns.ResolucaoDNS',
                    'capabilities': ['DNS_RESOLUTION'],
                    'priority': 'CRITICAL'
                },
                'port_scanner_rustscan': {
                    'implementation': 'adapters.legacy_adapters.PortScannerAdapter',
                    'legacy_module': 'modulos.varredura_rustscan.VarreduraRustScan',
                    'init_params': {'scanner_type': 'rustscan'},
                    'capabilities': ['PORT_SCANNING'],
                    'priority': 'HIGH'
                },
                'port_scanner_nmap': {
                    'implementation': 'adapters.legacy_adapters.PortScannerAdapter',
                    'legacy_module': 'modulos.varredura_nmap.VarreduraNmap',
                    'init_params': {'scanner_type': 'nmap'},
                    'capabilities': ['PORT_SCANNING', 'SERVICE_DETECTION', 'VULNERABILITY_SCANNING'],
                    'priority': 'MEDIUM'
                }
            }
        }
        
        # Salvar configuração padrão
        self._save_config()
    
    def _save_config(self):
        """Salva configuração no arquivo"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.safe_dump(self.config_data, f, default_flow_style=False, allow_unicode=True)
        except Exception as e:
            print(f"Erro ao salvar configuração: {e}")
    
    def configure_container(self, container: DependencyContainer, profile: str = 'development') -> bool:
        """
        Configura container com serviços do perfil especificado
        
        Args:
            container: Container a configurar
            profile: Perfil de configuração ('development', 'production', 'testing')
            
        Returns:
            True se configurado com sucesso
        """
        try:
            if profile not in self.config_data.get('profiles', {}):
                print(f"Perfil '{profile}' não encontrado, usando 'development'")
                profile = 'development'
            
            profile_config = self.config_data['profiles'][profile]
            services_config = profile_config.get('services', {})
            
            # Configurar serviços principais
            for service_name, service_config in services_config.items():
                self._register_service(container, service_name, service_config)
            
            # Configurar módulos scanner
            self._register_scanner_modules(container)
            
            return True
            
        except Exception as e:
            print(f"Erro ao configurar container: {e}")
            return False
    
    def _register_service(self, container: DependencyContainer, service_name: str, config: Dict[str, Any]):
        """Registra um serviço no container"""
        try:
            implementation_path = config.get('implementation')
            if not implementation_path:
                print(f"Implementação não especificada para {service_name}")
                return
            
            # Importar classe da implementação
            implementation_class = self._import_class(implementation_path)
            if not implementation_class:
                return
            
            # Determinar interface baseada no nome do serviço
            interface_class = self._get_interface_for_service(service_name)
            if not interface_class:
                interface_class = implementation_class
            
            # Determinar ciclo de vida
            lifetime_str = config.get('lifetime', 'singleton').lower()
            lifetime = ServiceLifetime.SINGLETON if lifetime_str == 'singleton' else ServiceLifetime.TRANSIENT
            
            # Criar factory se há configuração específica
            service_config = config.get('config', {})
            
            if service_config:
                # Factory que passa configuração para o construtor
                def factory(container_ref=container):
                    return implementation_class(service_config)
                
                if lifetime == ServiceLifetime.SINGLETON:
                    container.register_factory(interface_class, factory, ServiceLifetime.SINGLETON)
                else:
                    container.register_factory(interface_class, factory, ServiceLifetime.TRANSIENT)
            else:
                # Registro simples sem configuração
                if lifetime == ServiceLifetime.SINGLETON:
                    container.register_singleton(interface_class, implementation_class)
                else:
                    container.register_transient(interface_class, implementation_class)
            
            print(f"Serviço '{service_name}' registrado como {lifetime.value}")
            
        except Exception as e:
            print(f"Erro ao registrar serviço '{service_name}': {e}")
    
    def _register_scanner_modules(self, container: DependencyContainer):
        """Registra módulos scanner baseado na configuração"""
        try:
            module_mappings = self.config_data.get('module_mappings', {})
            
            for module_name, module_config in module_mappings.items():
                self._register_scanner_module(container, module_name, module_config)
                
        except Exception as e:
            print(f"Erro ao registrar módulos scanner: {e}")
    
    def _register_scanner_module(self, container: DependencyContainer, module_name: str, config: Dict[str, Any]):
        """Registra um módulo scanner específico"""
        try:
            implementation_path = config.get('implementation')
            legacy_module_path = config.get('legacy_module')
            
            if not implementation_path or not legacy_module_path:
                print(f"Configuração incompleta para módulo '{module_name}'")
                return
            
            # Importar classes
            adapter_class = self._import_class(implementation_path)
            legacy_class = self._import_class(legacy_module_path)
            
            if not adapter_class or not legacy_class:
                return
            
            # Parâmetros de inicialização
            init_params = config.get('init_params', {})
            
            # Factory que cria adapter com módulo legado
            def factory():
                legacy_instance = legacy_class()
                return adapter_class(legacy_instance, **init_params)
            
            # Registrar como transient para permitir múltiplas instâncias
            container.register_factory(adapter_class, factory, ServiceLifetime.TRANSIENT)
            
            print(f"Módulo scanner '{module_name}' registrado")
            
        except Exception as e:
            print(f"Erro ao registrar módulo scanner '{module_name}': {e}")
    
    def _import_class(self, class_path: str) -> Optional[Type]:
        """Importa classe a partir do caminho especificado"""
        try:
            module_path, class_name = class_path.rsplit('.', 1)
            module = __import__(module_path, fromlist=[class_name])
            return getattr(module, class_name)
        except Exception as e:
            print(f"Erro ao importar classe '{class_path}': {e}")
            return None
    
    def _get_interface_for_service(self, service_name: str) -> Optional[Type]:
        """Retorna interface apropriada baseada no nome do serviço"""
        interface_mapping = {
            'logger_factory': ILoggerFactory,
            'persistence_layer': IPersistenceLayer,
            'report_generator': IReportGenerator,
            'orchestrator': IOrchestrator,
            'decision_engine': IDecisionEngine,
            'cache_layer': ICacheLayer
        }
        
        return interface_mapping.get(service_name)
    
    def get_profile_names(self) -> list:
        """Retorna lista de perfis disponíveis"""
        return list(self.config_data.get('profiles', {}).keys())
    
    def add_service(self, profile: str, service_name: str, service_config: Dict[str, Any]):
        """Adiciona novo serviço à configuração"""
        if profile not in self.config_data.get('profiles', {}):
            self.config_data.setdefault('profiles', {})[profile] = {'services': {}}
        
        self.config_data['profiles'][profile].setdefault('services', {})[service_name] = service_config
        self._save_config()
    
    def remove_service(self, profile: str, service_name: str):
        """Remove serviço da configuração"""
        try:
            del self.config_data['profiles'][profile]['services'][service_name]
            self._save_config()
        except KeyError:
            pass
    
    def update_service_config(self, profile: str, service_name: str, new_config: Dict[str, Any]):
        """Atualiza configuração de um serviço"""
        if profile in self.config_data.get('profiles', {}):
            services = self.config_data['profiles'][profile].setdefault('services', {})
            if service_name in services:
                services[service_name].update(new_config)
                self._save_config()


def create_configured_container(profile: str = 'development', 
                              config_path: Optional[str] = None) -> DependencyContainer:
    """
    Cria e configura um container pronto para uso
    
    Args:
        profile: Perfil de configuração
        config_path: Caminho personalizado para configuração
        
    Returns:
        Container configurado
    """
    container = DependencyContainer()
    configurator = ServiceConfiguration(config_path)
    
    if configurator.configure_container(container, profile):
        print(f"Container configurado com perfil '{profile}'")
        
        # Validar dependências
        errors = container.validate_dependencies()
        if errors:
            print("Avisos de dependências:")
            for service, service_errors in errors.items():
                print(f"  {service.__name__}: {', '.join(service_errors)}")
    else:
        print(f"Falha ao configurar container com perfil '{profile}'")
    
    return container
