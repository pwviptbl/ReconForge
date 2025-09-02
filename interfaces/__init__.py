#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Arquivo __init__ para interfaces - Fase 1 da Refatoração

Exporta todas as interfaces principais para facilitar importação.
"""

from .scanner_module import (
    IScannerModule, IPortScanner, IServiceDetector, IVulnerabilityScanner,
    IWebScanner, IDNSResolver, ISubdomainEnumerator, IDirectoryScanner,
    ITechnologyDetector, IExploitSearcher, ScannerCapability, ScannerPriority
)

from .logger import ILogger, ILoggerFactory, LogLevel

from .report_generator import (
    IReportGenerator, ITemplateEngine, ReportFormat, ReportSection
)

from .persistence import (
    IPersistenceLayer, ICacheLayer, StorageBackend, DataFormat
)

from .orchestrator import (
    IOrchestrator, IExecutionStrategy, IDecisionEngine, 
    ExecutionMode, ExecutionStatus
)

__all__ = [
    # Scanner Module Interfaces
    'IScannerModule', 'IPortScanner', 'IServiceDetector', 'IVulnerabilityScanner',
    'IWebScanner', 'IDNSResolver', 'ISubdomainEnumerator', 'IDirectoryScanner',
    'ITechnologyDetector', 'IExploitSearcher', 'ScannerCapability', 'ScannerPriority',
    
    # Logger Interfaces
    'ILogger', 'ILoggerFactory', 'LogLevel',
    
    # Report Generator Interfaces
    'IReportGenerator', 'ITemplateEngine', 'ReportFormat', 'ReportSection',
    
    # Persistence Interfaces
    'IPersistenceLayer', 'ICacheLayer', 'StorageBackend', 'DataFormat',
    
    # Orchestrator Interfaces
    'IOrchestrator', 'IExecutionStrategy', 'IDecisionEngine', 
    'ExecutionMode', 'ExecutionStatus'
]
