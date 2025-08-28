#!/usr/bin/env python3
"""
Módulo de Varredura de Vulnerabilidades (Substituto OpenVAS)
Scanner de vulnerabilidades completo em Python puro - substitui OpenVAS
"""

import time
from datetime import datetime
from utils.logger import obter_logger
from modulos.scanner_vulnerabilidades import ScannerVulnerabilidades

class VarreduraOpenvas:
    def __init__(self):
        self.logger = obter_logger("VulnScan")
        self.scanner = ScannerVulnerabilidades()
    
    def scan_vulnerabilidades(self, alvo, portas_abertas=None):
        """Executa scan completo de vulnerabilidades"""
        self.logger.info(f"🔍 Iniciando scan de vulnerabilidades para {alvo}")
        
        inicio = time.time()
        
        try:
            # Executar scan
            resultado = self.scanner.scan_vulnerabilidades(alvo, portas_abertas)
            
            if 'erro' in resultado:
                return {
                    'alvo': alvo,
                    'sucesso': False,
                    'erro': resultado['erro'],
                    'timestamp': datetime.now().isoformat()
                }
            
            vulnerabilidades = resultado.get('vulnerabilidades', [])
            servicos = resultado.get('servicos_detectados', {})
            
            # Estatísticas
            alta = resultado.get('criticidade_alta', 0)
            media = resultado.get('criticidade_media', 0)
            baixa = resultado.get('criticidade_baixa', 0)
            
            self.logger.info(f"🎯 Serviços detectados: {len(servicos)}")
            self.logger.info(f"🚨 Vulnerabilidades: {alta} ALTA, {media} MÉDIA, {baixa} BAIXA")
            
            return {
                'alvo': alvo,
                'sucesso': True,
                'duracao_segundos': resultado.get('duracao_segundos', 0),
                'servicos_detectados': servicos,
                'total_servicos': len(servicos),
                'vulnerabilidades': vulnerabilidades,
                'total_vulnerabilidades': len(vulnerabilidades),
                'vulnerabilidades_alta': alta,
                'vulnerabilidades_media': media,
                'vulnerabilidades_baixa': baixa,
                'score_risco': self._calcular_score_risco(alta, media, baixa),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Erro no scan de vulnerabilidades: {e}")
            return {
                'alvo': alvo,
                'sucesso': False,
                'erro': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _calcular_score_risco(self, alta, media, baixa):
        """Calcula score de risco baseado nas vulnerabilidades"""
        # Score baseado em CVSS
        score = (alta * 8.5) + (media * 5.0) + (baixa * 2.0)
        
        # Normalizar para 0-100
        max_score = 100
        normalized_score = min(score, max_score)
        
        return round(normalized_score, 1)
    
    def scan_rapido(self, alvo):
        """Scan rápido de vulnerabilidades críticas"""
        self.logger.info(f"⚡ Iniciando scan rápido para {alvo}")
        
        # Usar apenas portas mais comuns para scan rápido
        portas_criticas = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432]
        
        return self.scan_vulnerabilidades(alvo, portas_criticas)

def main():
    """Teste do módulo"""
    scanner = VarreduraOpenvas()
    
    # Teste scan completo
    resultado = scanner.scan_vulnerabilidades('127.0.0.1')
    print("Scan completo:", resultado)
    
    # Teste scan rápido
    resultado_rapido = scanner.scan_rapido('127.0.0.1')
    print("Scan rápido:", resultado_rapido)

if __name__ == "__main__":
    main()
