"""
Módulo de Análise de Rede para VarreduraIA
Fornece análise completa de infraestrutura e topologia de rede
"""

from .network_mapper import NetworkMapperPlugin
from .ssl_analyzer import SSLAnalyzerPlugin
from .firewall_detector import FirewallDetectorPlugin
from .traffic_analyzer import TrafficAnalyzerPlugin

__all__ = [
    'NetworkMapperPlugin',
    'SSLAnalyzerPlugin', 
    'FirewallDetectorPlugin',
    'TrafficAnalyzerPlugin'
]

# Configurações padrão do módulo
DEFAULT_CONFIG = {
    'NetworkMapperPlugin': {
        'max_hops': 30,
        'timeout': 5,
        'parallel_threads': 10,
        'enable_traceroute': True,
        'enable_host_discovery': True,
        'enable_topology_mapping': True
    },
    'SSLAnalyzerPlugin': {
        'check_vulnerabilities': True,
        'verify_chain': True,
        'check_revocation': True,
        'analyze_ciphers': True,
        'check_hsts': True
    },
    'FirewallDetectorPlugin': {
        'stealth_mode': True,
        'timing_template': 'T3',
        'max_retries': 3,
        'detect_waf': True,
        'suggest_bypasses': True
    },
    'TrafficAnalyzerPlugin': {
        'capture_duration': 60,
        'analysis_window': 300,
        'anomaly_threshold': 2.5,
        'protocol_analysis': True,
        'bandwidth_measurement': True
    }
}
