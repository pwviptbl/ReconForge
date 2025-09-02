#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Container de Injeção de Dependência - Fase 1 da Refatoração

Este módulo implementa um container DI completo que:
- Registra serviços e suas factories
- Gerencia ciclo de vida (singleton vs transient)
- Resolve dependências automaticamente
- Valida dependências circulares
- Suporta configuração externa
"""

import threading
import sys
from typing import Any, Dict, Optional, Callable, Type, Union, Set, List
from enum import Enum
from dataclasses import dataclass
import inspect
import weakref
from functools import wraps


class ServiceLifetime(Enum):
    """Tipos de ciclo de vida para serviços"""
    SINGLETON = "singleton"  # Uma única instância para toda a aplicação
    TRANSIENT = "transient"  # Nova instância a cada resolução
    SCOPED = "scoped"        # Uma instância por escopo (futuro)


@dataclass
class ServiceDescriptor:
    """Descritor de um serviço registrado"""
    service_type: Type
    implementation_type: Optional[Type] = None
    factory: Optional[Callable] = None
    instance: Optional[Any] = None
    lifetime: ServiceLifetime = ServiceLifetime.SINGLETON
    dependencies: List[Type] = None
    is_configured: bool = False


class CircularDependencyError(Exception):
    """Erro lançado quando há dependência circular"""
    def __init__(self, dependency_chain: List[str]):
        self.dependency_chain = dependency_chain
        super().__init__(f"Dependência circular detectada: {' -> '.join(dependency_chain)}")


class ServiceNotRegisteredError(Exception):
    """Erro lançado quando serviço não está registrado"""
    def __init__(self, service_type: Type):
        super().__init__(f"Serviço não registrado: {service_type.__name__}")


class DependencyContainer:
    """Container de Injeção de Dependência thread-safe"""
    
    def __init__(self, logger=None):
        self._services: Dict[Type, ServiceDescriptor] = {}
        self._singletons: Dict[Type, Any] = {}
        self._lock = threading.RLock()
        self._resolution_stack: List[Type] = []
        self._logger = logger
        
        # Auto-registrar o próprio container
        self.register_instance(DependencyContainer, self)
    
    def _log(self, level: str, message: str):
        """Log interno com fallback para print"""
        if self._logger and hasattr(self._logger, level.lower()):
            getattr(self._logger, level.lower())(message)
        elif level.upper() in ['ERROR', 'WARNING']:
            print(f"[{level}] DependencyContainer: {message}")
    
    def register_singleton(self, service_type: Type, implementation_type: Optional[Type] = None, 
                          factory: Optional[Callable] = None) -> 'DependencyContainer':
        """
        Registra um serviço como singleton
        
        Args:
            service_type: Interface ou tipo do serviço
            implementation_type: Implementação concreta (opcional se factory fornecida)
            factory: Factory function para criar instância (opcional)
        
        Returns:
            Self para fluent interface
        """
        with self._lock:
            descriptor = ServiceDescriptor(
                service_type=service_type,
                implementation_type=implementation_type,
                factory=factory,
                lifetime=ServiceLifetime.SINGLETON,
                dependencies=self._extract_dependencies(implementation_type or service_type)
            )
            
            self._services[service_type] = descriptor
            self._log('INFO', f"Registrado singleton: {service_type.__name__}")
            
            return self
    
    def register_transient(self, service_type: Type, implementation_type: Optional[Type] = None,
                          factory: Optional[Callable] = None) -> 'DependencyContainer':
        """
        Registra um serviço como transient (nova instância a cada resolução)
        
        Args:
            service_type: Interface ou tipo do serviço
            implementation_type: Implementação concreta (opcional se factory fornecida)
            factory: Factory function para criar instância (opcional)
        
        Returns:
            Self para fluent interface
        """
        with self._lock:
            descriptor = ServiceDescriptor(
                service_type=service_type,
                implementation_type=implementation_type,
                factory=factory,
                lifetime=ServiceLifetime.TRANSIENT,
                dependencies=self._extract_dependencies(implementation_type or service_type)
            )
            
            self._services[service_type] = descriptor
            self._log('INFO', f"Registrado transient: {service_type.__name__}")
            
            return self
    
    def register_instance(self, service_type: Type, instance: Any) -> 'DependencyContainer':
        """
        Registra uma instância específica como singleton
        
        Args:
            service_type: Tipo do serviço
            instance: Instância já criada
        
        Returns:
            Self para fluent interface
        """
        with self._lock:
            descriptor = ServiceDescriptor(
                service_type=service_type,
                instance=instance,
                lifetime=ServiceLifetime.SINGLETON,
                is_configured=True
            )
            
            self._services[service_type] = descriptor
            self._singletons[service_type] = instance
            self._log('INFO', f"Registrada instância: {service_type.__name__}")
            
            return self
    
    def register_factory(self, service_type: Type, factory: Callable, 
                        lifetime: ServiceLifetime = ServiceLifetime.SINGLETON) -> 'DependencyContainer':
        """
        Registra uma factory function para criar o serviço
        
        Args:
            service_type: Tipo do serviço
            factory: Function que cria a instância
            lifetime: Ciclo de vida do serviço
        
        Returns:
            Self para fluent interface
        """
        with self._lock:
            descriptor = ServiceDescriptor(
                service_type=service_type,
                factory=factory,
                lifetime=lifetime,
                dependencies=self._extract_dependencies(factory)
            )
            
            self._services[service_type] = descriptor
            self._log('INFO', f"Registrada factory: {service_type.__name__} ({lifetime.value})")
            
            return self
    
    def resolve(self, service_type: Type) -> Any:
        """
        Resolve um serviço e suas dependências
        
        Args:
            service_type: Tipo do serviço a resolver
        
        Returns:
            Instância do serviço
        
        Raises:
            ServiceNotRegisteredError: Se o serviço não estiver registrado
            CircularDependencyError: Se houver dependência circular
        """
        with self._lock:
            # Verificar se serviço está registrado
            if service_type not in self._services:
                raise ServiceNotRegisteredError(service_type)
            
            # Verificar dependência circular
            if service_type in self._resolution_stack:
                cycle_start = self._resolution_stack.index(service_type)
                cycle = self._resolution_stack[cycle_start:] + [service_type]
                chain = [t.__name__ for t in cycle]
                raise CircularDependencyError(chain)
            
            descriptor = self._services[service_type]
            
            # Se é singleton e já foi criado, retornar instância existente
            if (descriptor.lifetime == ServiceLifetime.SINGLETON and 
                service_type in self._singletons):
                return self._singletons[service_type]
            
            # Adicionar à pilha de resolução
            self._resolution_stack.append(service_type)
            
            try:
                instance = self._create_instance(descriptor)
                
                # Se é singleton, armazenar para reuso
                if descriptor.lifetime == ServiceLifetime.SINGLETON:
                    self._singletons[service_type] = instance
                
                self._log('DEBUG', f"Resolvido: {service_type.__name__}")
                return instance
                
            finally:
                # Remover da pilha de resolução
                if self._resolution_stack and self._resolution_stack[-1] == service_type:
                    self._resolution_stack.pop()
    
    def try_resolve(self, service_type: Type) -> Optional[Any]:
        """
        Tenta resolver um serviço, retornando None se não conseguir
        
        Args:
            service_type: Tipo do serviço a resolver
        
        Returns:
            Instância do serviço ou None se não conseguir resolver
        """
        try:
            return self.resolve(service_type)
        except (ServiceNotRegisteredError, CircularDependencyError) as e:
            self._log('WARNING', f"Falha ao resolver {service_type.__name__}: {e}")
            return None
    
    def is_registered(self, service_type: Type) -> bool:
        """
        Verifica se um serviço está registrado
        
        Args:
            service_type: Tipo do serviço
        
        Returns:
            True se registrado, False caso contrário
        """
        with self._lock:
            return service_type in self._services
    
    def get_registered_services(self) -> List[Type]:
        """
        Retorna lista de todos os serviços registrados
        
        Returns:
            Lista de tipos de serviços registrados
        """
        with self._lock:
            return list(self._services.keys())
    
    def validate_dependencies(self) -> Dict[Type, List[str]]:
        """
        Valida todas as dependências registradas
        
        Returns:
            Dicionário com erros de validação por serviço
        """
        errors = {}
        
        with self._lock:
            for service_type, descriptor in self._services.items():
                service_errors = []
                
                # Verificar se dependências estão registradas
                if descriptor.dependencies:
                    for dep in descriptor.dependencies:
                        if not self.is_registered(dep):
                            service_errors.append(f"Dependência não registrada: {dep.__name__}")
                
                # Verificar se há factory ou implementation_type para criação
                if (descriptor.instance is None and 
                    descriptor.factory is None and 
                    descriptor.implementation_type is None):
                    service_errors.append("Nenhuma forma de criar instância definida")
                
                if service_errors:
                    errors[service_type] = service_errors
        
        return errors
    
    def create_scope(self) -> 'DependencyScope':
        """
        Cria um novo escopo para serviços scoped (futuro)
        
        Returns:
            Novo escopo de dependências
        """
        return DependencyScope(self)
    
    def _create_instance(self, descriptor: ServiceDescriptor) -> Any:
        """Cria uma instância do serviço baseado no descriptor"""
        
        # Se já tem instância (register_instance), retornar
        if descriptor.instance is not None:
            return descriptor.instance
        
        # Se tem factory, usar ela
        if descriptor.factory is not None:
            return self._invoke_with_dependencies(descriptor.factory)
        
        # Se tem implementation_type, criar instância
        if descriptor.implementation_type is not None:
            return self._create_instance_from_type(descriptor.implementation_type)
        
        # Fallback: tentar criar do próprio service_type
        return self._create_instance_from_type(descriptor.service_type)
    
    def _create_instance_from_type(self, target_type: Type) -> Any:
        """Cria instância de um tipo resolvendo suas dependências"""
        
        # Obter construtor
        constructor = target_type.__init__
        signature = inspect.signature(constructor)
        
        # Resolver parâmetros do construtor
        kwargs = {}
        for param_name, param in signature.parameters.items():
            if param_name == 'self':
                continue
            
            # Se tem type annotation, tentar resolver
            if param.annotation != inspect.Parameter.empty:
                try:
                    kwargs[param_name] = self.resolve(param.annotation)
                except (ServiceNotRegisteredError, CircularDependencyError):
                    # Se não conseguir resolver e não tem valor padrão, erro
                    if param.default == inspect.Parameter.empty:
                        raise ServiceNotRegisteredError(param.annotation)
                    # Caso contrário, usar valor padrão (não passando no kwargs)
        
        return target_type(**kwargs)
    
    def _invoke_with_dependencies(self, func: Callable) -> Any:
        """Invoca uma function resolvendo suas dependências"""
        
        signature = inspect.signature(func)
        kwargs = {}
        
        for param_name, param in signature.parameters.items():
            # Se tem type annotation, tentar resolver
            if param.annotation != inspect.Parameter.empty:
                try:
                    kwargs[param_name] = self.resolve(param.annotation)
                except (ServiceNotRegisteredError, CircularDependencyError):
                    # Se não conseguir resolver e não tem valor padrão, erro
                    if param.default == inspect.Parameter.empty:
                        raise ServiceNotRegisteredError(param.annotation)
                    # Caso contrário, usar valor padrão (não passando no kwargs)
        
        return func(**kwargs)
    
    def _extract_dependencies(self, target: Union[Type, Callable]) -> List[Type]:
        """Extrai dependências de um tipo ou callable analisando type annotations"""
        
        if target is None:
            return []
        
        dependencies = []
        
        try:
            # Se é tipo, analisar __init__
            if inspect.isclass(target):
                signature = inspect.signature(target.__init__)
            else:
                # Se é callable, analisar diretamente
                signature = inspect.signature(target)
            
            for param_name, param in signature.parameters.items():
                if param_name == 'self':
                    continue
                
                # Se tem type annotation e não é builtin, adicionar como dependência
                if (param.annotation != inspect.Parameter.empty and
                    not self._is_builtin_type(param.annotation)):
                    # Verificar se annotation é string (forward reference)
                    if isinstance(param.annotation, str):
                        # Para forward references, tentar resolver
                        try:
                            # Buscar no módulo atual ou namespace global
                            module = sys.modules.get(target.__module__)
                            if module and hasattr(module, param.annotation):
                                resolved_type = getattr(module, param.annotation)
                                dependencies.append(resolved_type)
                        except:
                            # Se não conseguir resolver, ignorar
                            pass
                    else:
                        dependencies.append(param.annotation)
                    
        except (ValueError, TypeError) as e:
            self._log('WARNING', f"Erro ao extrair dependências de {target}: {e}")
        
        return dependencies
    
    def _is_builtin_type(self, type_annotation: Type) -> bool:
        """Verifica se um tipo é builtin (str, int, bool, etc.)"""
        builtin_types = {
            str, int, float, bool, list, dict, tuple, set, 
            bytes, object, type(None)
        }
        
        return (type_annotation in builtin_types or
                getattr(type_annotation, '__module__', None) == 'builtins')


class DependencyScope:
    """Escopo para serviços scoped (implementação futura)"""
    
    def __init__(self, container: DependencyContainer):
        self._container = container
        self._scoped_instances: Dict[Type, Any] = {}
        self._disposed = False
    
    def resolve(self, service_type: Type) -> Any:
        """Resolve serviço no escopo atual"""
        if self._disposed:
            raise RuntimeError("Scope já foi disposed")
        
        # Para serviços scoped, criar uma instância por escopo
        descriptor = self._container._services.get(service_type)
        if descriptor and descriptor.lifetime == ServiceLifetime.SCOPED:
            if service_type not in self._scoped_instances:
                self._scoped_instances[service_type] = self._container._create_instance(descriptor)
            return self._scoped_instances[service_type]
        
        # Para outros tipos, delegar para container
        return self._container.resolve(service_type)
    
    def dispose(self):
        """Libera recursos do escopo"""
        if self._disposed:
            return
        
        # Chamar dispose em instâncias que implementam IDisposable (futuro)
        for instance in self._scoped_instances.values():
            if hasattr(instance, 'dispose'):
                try:
                    instance.dispose()
                except Exception as e:
                    print(f"Erro ao fazer dispose de {type(instance).__name__}: {e}")
        
        self._scoped_instances.clear()
        self._disposed = True
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.dispose()


def injectable(lifetime: ServiceLifetime = ServiceLifetime.SINGLETON):
    """
    Decorator para marcar classes como injetáveis
    
    Args:
        lifetime: Ciclo de vida do serviço
    
    Usage:
        @injectable(ServiceLifetime.SINGLETON)
        class MyService:
            def __init__(self, dependency: IDependency):
                self.dependency = dependency
    """
    def decorator(cls):
        cls.__injectable_lifetime__ = lifetime
        return cls
    return decorator


def auto_wire(container: DependencyContainer):
    """
    Decorator para auto-registrar uma classe no container
    
    Args:
        container: Container onde registrar
    
    Usage:
        @auto_wire(container)
        class MyService:
            pass
    """
    def decorator(cls):
        lifetime = getattr(cls, '__injectable_lifetime__', ServiceLifetime.SINGLETON)
        if lifetime == ServiceLifetime.SINGLETON:
            container.register_singleton(cls)
        else:
            container.register_transient(cls)
        return cls
    return decorator
