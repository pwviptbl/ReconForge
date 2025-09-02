#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interface para geração de relatórios - Fase 1 da Refatoração

Define contrato para geradores de relatório permitindo
diferentes formatos e implementações.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from enum import Enum


class ReportFormat(Enum):
    """Formatos de relatório suportados"""
    HTML = "html"
    JSON = "json"
    PDF = "pdf"
    CSV = "csv"
    XML = "xml"
    MARKDOWN = "markdown"


class ReportSection(Enum):
    """Seções padrão de um relatório"""
    SUMMARY = "summary"
    TARGETS = "targets"
    PORTS = "ports"
    SERVICES = "services"
    VULNERABILITIES = "vulnerabilities"
    RECOMMENDATIONS = "recommendations"
    TECHNICAL_DETAILS = "technical_details"
    APPENDIX = "appendix"


class IReportGenerator(ABC):
    """Interface para geradores de relatório"""
    
    @property
    @abstractmethod
    def supported_formats(self) -> List[ReportFormat]:
        """Formatos suportados por este gerador"""
        pass
    
    @abstractmethod
    def generate_report(self, data: Dict[str, Any], format: ReportFormat, 
                       output_path: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Gera relatório no formato especificado
        
        Args:
            data: Dados do pentest para incluir no relatório
            format: Formato desejado do relatório
            output_path: Caminho onde salvar o arquivo
            options: Opções específicas do formato
            
        Returns:
            Resultado da geração com metadados
        """
        pass
    
    @abstractmethod
    def validate_data(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Valida se os dados estão no formato correto para gerar relatório
        
        Args:
            data: Dados a validar
            
        Returns:
            Dicionário com erros encontrados por seção
        """
        pass
    
    @abstractmethod
    def get_template_schema(self, format: ReportFormat) -> Dict[str, Any]:
        """
        Retorna schema do template para o formato especificado
        
        Args:
            format: Formato do template
            
        Returns:
            Schema JSON descrevendo estrutura esperada
        """
        pass
    
    def supports_format(self, format: ReportFormat) -> bool:
        """
        Verifica se o formato é suportado
        
        Args:
            format: Formato a verificar
            
        Returns:
            True se suportado, False caso contrário
        """
        return format in self.supported_formats
    
    def get_default_options(self, format: ReportFormat) -> Dict[str, Any]:
        """
        Retorna opções padrão para o formato
        
        Args:
            format: Formato do relatório
            
        Returns:
            Dicionário com opções padrão
        """
        return {}


class ITemplateEngine(ABC):
    """Interface para engines de template"""
    
    @abstractmethod
    def render_template(self, template_path: str, context: Dict[str, Any]) -> str:
        """
        Renderiza template com contexto fornecido
        
        Args:
            template_path: Caminho para o arquivo de template
            context: Variáveis disponíveis no template
            
        Returns:
            Conteúdo renderizado
        """
        pass
    
    @abstractmethod
    def render_string(self, template_string: str, context: Dict[str, Any]) -> str:
        """
        Renderiza string template com contexto
        
        Args:
            template_string: Template como string
            context: Variáveis disponíveis no template
            
        Returns:
            Conteúdo renderizado
        """
        pass
    
    @abstractmethod
    def validate_template(self, template_path: str) -> List[str]:
        """
        Valida sintaxe do template
        
        Args:
            template_path: Caminho para o template
            
        Returns:
            Lista de erros encontrados (vazia se válido)
        """
        pass
