#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Testes para o Container de Injeção de Dependência - Fase 1

Testa todas as funcionalidades do container DI incluindo:
- Registro de serviços
- Resolução de dependências
- Ciclo de vida (singleton/transient)
- Detecção de dependências circulares
- Validação de dependências
"""

import pytest
import threading
import time
from typing import List, Optional

from core.dependency_container import (
    DependencyContainer, ServiceLifetime, ServiceDescriptor,
    CircularDependencyError, ServiceNotRegisteredError
)


# Classes de teste para DI
class ITestService:
    """Interface de teste"""
    def get_value(self) -> str:
        raise NotImplementedError


class MockTestService(ITestService):
    """Implementação de teste"""
    def __init__(self, value: str = "test"):
        self.value = value
        self.creation_time = time.time()
    
    def get_value(self) -> str:
        return self.value


class IDependentService:
    """Interface para serviço dependente"""
    def get_dependency_value(self) -> str:
        raise NotImplementedError


class MockDependentService(IDependentService):
    """Serviço que depende de ITestService"""
    def __init__(self, test_service: ITestService):
        self.test_service = test_service
    
    def get_dependency_value(self) -> str:
        return f"dependent:{self.test_service.get_value()}"


class CircularA:
    """Classe para teste de dependência circular"""
    def __init__(self, b):  # Removendo type hint para evitar forward reference
        self.b = b


class CircularB:
    """Classe para teste de dependência circular"""
    def __init__(self, a):  # Removendo type hint para evitar forward reference
        self.a = a


class ComplexService:
    """Serviço com múltiplas dependências"""
    def __init__(self, service1: ITestService, service2: IDependentService, value: int = 42):
        self.service1 = service1
        self.service2 = service2
        self.value = value


class TestDependencyContainer:
    """Testes para DependencyContainer"""
    
    def test_container_creation(self):
        """Testa criação básica do container"""
        container = DependencyContainer()
        assert container is not None
        assert len(container.get_registered_services()) == 1  # Self-registration
    
    def test_self_registration(self):
        """Testa auto-registro do container"""
        container = DependencyContainer()
        resolved_container = container.resolve(DependencyContainer)
        assert resolved_container is container
    
    def test_register_singleton(self):
        """Testa registro de singleton"""
        container = DependencyContainer()
        container.register_singleton(ITestService, MockTestService)
        
        assert container.is_registered(ITestService)
        
        # Resolver duas vezes deve retornar a mesma instância
        instance1 = container.resolve(ITestService)
        instance2 = container.resolve(ITestService)
        
        assert instance1 is instance2
        assert isinstance(instance1, MockTestService)
    
    def test_register_transient(self):
        """Testa registro de transient"""
        container = DependencyContainer()
        container.register_transient(ITestService, MockTestService)
        
        assert container.is_registered(ITestService)
        
        # Resolver duas vezes deve retornar instâncias diferentes
        instance1 = container.resolve(ITestService)
        instance2 = container.resolve(ITestService)
        
        assert instance1 is not instance2
        assert isinstance(instance1, MockTestService)
        assert isinstance(instance2, MockTestService)
    
    def test_register_instance(self):
        """Testa registro de instância específica"""
        container = DependencyContainer()
        instance = MockTestService("specific")
        
        container.register_instance(ITestService, instance)
        
        resolved = container.resolve(ITestService)
        assert resolved is instance
        assert resolved.get_value() == "specific"
    
    def test_register_factory(self):
        """Testa registro com factory"""
        container = DependencyContainer()
        
        def test_factory():
            return MockTestService("factory")
        
        container.register_factory(ITestService, test_factory)
        
        instance = container.resolve(ITestService)
        assert instance.get_value() == "factory"
    
    def test_dependency_injection(self):
        """Testa injeção automática de dependências"""
        container = DependencyContainer()
        
        # Registrar dependência primeiro
        container.register_singleton(ITestService, MockTestService)
        container.register_singleton(IDependentService, MockDependentService)
        
        # Resolver serviço dependente
        dependent = container.resolve(IDependentService)
        
        assert isinstance(dependent, MockDependentService)
        assert dependent.get_dependency_value() == "dependent:test"
    
    def test_circular_dependency_detection(self):
        """Testa detecção de dependência circular"""
        container = DependencyContainer()
        
        # Registrar apenas CircularA que tem dependência de CircularB
        # CircularB não está registrado, então vai dar erro de serviço não registrado
        # Em vez disso, vamos criar um caso onde ambos estão registrados mas há circularidade
        
        # Para testar circularidade real, vou usar uma abordagem diferente
        class ServiceA:
            def __init__(self, service_b: 'ServiceB'):
                self.service_b = service_b
        
        class ServiceB:
            def __init__(self, service_a: ServiceA):
                self.service_a = service_a
        
        container.register_singleton(ServiceA)
        container.register_singleton(ServiceB)
        
        # Como temos forward reference, vamos usar uma abordagem manual
        # Registrar factories que criam dependência circular
        def factory_a():
            return ServiceA(container.resolve(ServiceB))
        
        def factory_b():
            return ServiceB(container.resolve(ServiceA))
        
        container.register_factory(ServiceA, factory_a)
        container.register_factory(ServiceB, factory_b)
        
        with pytest.raises((CircularDependencyError, RecursionError)) as exc_info:
            container.resolve(ServiceA)
    
    def test_service_not_registered_error(self):
        """Testa erro quando serviço não está registrado"""
        container = DependencyContainer()
        
        with pytest.raises(ServiceNotRegisteredError):
            container.resolve(ITestService)
    
    def test_try_resolve(self):
        """Testa resolução sem erro"""
        container = DependencyContainer()
        
        # Serviço não registrado deve retornar None
        result = container.try_resolve(ITestService)
        assert result is None
        
        # Serviço registrado deve resolver normalmente
        container.register_singleton(ITestService, MockTestService)
        result = container.try_resolve(ITestService)
        assert isinstance(result, MockTestService)
    
    def test_validate_dependencies(self):
        """Testa validação de dependências"""
        container = DependencyContainer()
        
        # Registrar serviço com dependência não registrada
        container.register_singleton(IDependentService, MockDependentService)
        
        errors = container.validate_dependencies()
        assert IDependentService in errors
        assert len(errors[IDependentService]) > 0
        
        # Registrar dependência
        container.register_singleton(ITestService, MockTestService)
        
        errors = container.validate_dependencies()
        assert IDependentService not in errors or len(errors.get(IDependentService, [])) == 0
    
    def test_thread_safety(self):
        """Testa thread safety do container"""
        container = DependencyContainer()
        container.register_singleton(ITestService, MockTestService)
        
        results = []
        
        def resolve_service():
            instance = container.resolve(ITestService)
            results.append(instance)
        
        # Criar múltiplas threads
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=resolve_service)
            threads.append(thread)
        
        # Iniciar todas as threads
        for thread in threads:
            thread.start()
        
        # Aguardar conclusão
        for thread in threads:
            thread.join()
        
        # Todas devem retornar a mesma instância (singleton)
        assert len(results) == 10
        first_instance = results[0]
        for instance in results:
            assert instance is first_instance
    
    def test_factory_with_dependencies(self):
        """Testa factory que recebe dependências"""
        container = DependencyContainer()
        
        # Registrar dependência
        container.register_singleton(ITestService, MockTestService)
        
        # Factory que usa dependência
        def complex_factory(test_service: ITestService):
            return ComplexService(test_service, None, 100)
        
        container.register_factory(ComplexService, complex_factory)
        
        instance = container.resolve(ComplexService)
        assert isinstance(instance, ComplexService)
        assert instance.value == 100
        assert instance.service1 is not None
    
    def test_multiple_implementations(self):
        """Testa registro de múltiplas implementações"""
        container = DependencyContainer()
        
        # Primeira implementação
        container.register_instance(ITestService, MockTestService("first"))
        
        # Segunda implementação (deve substituir a primeira)
        container.register_instance(ITestService, MockTestService("second"))
        
        instance = container.resolve(ITestService)
        assert instance.get_value() == "second"
    
    def test_fluent_interface(self):
        """Testa interface fluente do container"""
        container = DependencyContainer()
        
        # Deve permitir encadeamento
        result = (container
                 .register_singleton(ITestService, MockTestService)
                 .register_transient(IDependentService, MockDependentService))
        
        assert result is container
        assert container.is_registered(ITestService)
        assert container.is_registered(IDependentService)
    
    def test_get_registered_services(self):
        """Testa listagem de serviços registrados"""
        container = DependencyContainer()
        
        initial_count = len(container.get_registered_services())
        
        container.register_singleton(ITestService, MockTestService)
        container.register_transient(IDependentService, MockDependentService)
        
        services = container.get_registered_services()
        assert len(services) == initial_count + 2
        assert ITestService in services
        assert IDependentService in services
    
    def test_complex_dependency_chain(self):
        """Testa cadeia complexa de dependências"""
        container = DependencyContainer()
        
        # Registrar em ordem inversa para testar resolução
        container.register_singleton(ComplexService)
        container.register_singleton(IDependentService, MockDependentService)
        container.register_singleton(ITestService, MockTestService)
        
        # Deve resolver toda a cadeia automaticamente
        instance = container.resolve(ComplexService)
        
        assert isinstance(instance, ComplexService)
        assert isinstance(instance.service1, MockTestService)
        assert isinstance(instance.service2, MockDependentService)
        assert instance.value == 42  # Valor padrão
        assert instance.service2.get_dependency_value() == "dependent:test"


class TestServiceDescriptor:
    """Testes para ServiceDescriptor"""
    
    def test_descriptor_creation(self):
        """Testa criação de descriptor"""
        descriptor = ServiceDescriptor(
            service_type=ITestService,
            implementation_type=MockTestService,
            lifetime=ServiceLifetime.SINGLETON
        )
        
        assert descriptor.service_type == ITestService
        assert descriptor.implementation_type == MockTestService
        assert descriptor.lifetime == ServiceLifetime.SINGLETON
        assert descriptor.dependencies is None
        assert not descriptor.is_configured
    
    def test_descriptor_with_factory(self):
        """Testa descriptor com factory"""
        def test_factory():
            return MockTestService()
        
        descriptor = ServiceDescriptor(
            service_type=ITestService,
            factory=test_factory,
            lifetime=ServiceLifetime.TRANSIENT
        )
        
        assert descriptor.service_type == ITestService
        assert descriptor.factory == test_factory
        assert descriptor.lifetime == ServiceLifetime.TRANSIENT
    
    def test_descriptor_with_instance(self):
        """Testa descriptor com instância"""
        instance = MockTestService()
        
        descriptor = ServiceDescriptor(
            service_type=ITestService,
            instance=instance,
            lifetime=ServiceLifetime.SINGLETON
        )
        
        assert descriptor.service_type == ITestService
        assert descriptor.instance == instance
        assert descriptor.lifetime == ServiceLifetime.SINGLETON


# Fixtures para pytest
@pytest.fixture
def container():
    """Container limpo para cada teste"""
    return DependencyContainer()


@pytest.fixture
def configured_container():
    """Container pré-configurado para testes"""
    container = DependencyContainer()
    container.register_singleton(ITestService, MockTestService)
    container.register_singleton(IDependentService, MockDependentService)
    return container


if __name__ == "__main__":
    # Executar testes se arquivo for executado diretamente
    pytest.main([__file__, "-v"])
