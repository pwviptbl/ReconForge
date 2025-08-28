#!/usr/bin/env python3
"""
Módulo de Varredura Web (Substituto ZAP)
Scanner web completo em Python puro - substitui OWASP ZAP
"""

import time
from datetime import datetime
from utils.logger import obter_logger
from modulos.scanner_web_avancado import ScannerWebAvancado

class VarreduraZap:
    def __init__(self):
        self.logger = obter_logger("WebScan")
        self.scanner = ScannerWebAvancado()
    
    def spider_scan(self, alvo, max_depth=3, max_pages=100):
        """Spider scan usando scanner Python"""
        self.logger.info(f"🕷️ Iniciando spider scan para {alvo}")
        
        inicio = time.time()
        
        try:
            # Determinar protocolo
            if not alvo.startswith(('http://', 'https://')):
                # Tentar HTTPS primeiro, depois HTTP
                for protocolo in ['https', 'http']:
                    test_url = f"{protocolo}://{alvo}"
                    try:
                        import requests
                        resp = requests.get(test_url, timeout=5, verify=False)
                        if resp.status_code < 400:
                            alvo = test_url
                            break
                    except:
                        continue
                else:
                    alvo = f"http://{alvo}"
            
            # Configurar scanner
            self.scanner.max_depth = max_depth
            self.scanner.max_pages = max_pages
            
            # Executar spider
            resultado = self.scanner.scan_completo(alvo)
            
            duracao = time.time() - inicio
            
            return {
                'alvo': alvo,
                'sucesso': True,
                'duracao_segundos': round(duracao, 2),
                'urls_encontradas': resultado.get('urls_encontradas', []),
                'total_urls': resultado.get('total_urls', 0),
                'formularios': resultado.get('formularios', []),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Erro no spider scan: {e}")
            return {
                'alvo': alvo,
                'sucesso': False,
                'erro': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def active_scan(self, alvo, urls_encontradas=None):
        """Scan ativo de vulnerabilidades"""
        self.logger.info(f"🔍 Iniciando scan ativo para {alvo}")
        
        inicio = time.time()
        
        try:
            # Determinar protocolo se necessário
            if not alvo.startswith(('http://', 'https://')):
                alvo = f"http://{alvo}"
            
            # Executar scan completo
            resultado = self.scanner.scan_completo(alvo)
            
            duracao = time.time() - inicio
            
            vulnerabilidades = resultado.get('vulnerabilidades', [])
            
            # Organizar por criticidade
            alta = [v for v in vulnerabilidades if v.get('criticidade') == 'ALTA']
            media = [v for v in vulnerabilidades if v.get('criticidade') == 'MÉDIA']
            baixa = [v for v in vulnerabilidades if v.get('criticidade') == 'BAIXA']
            
            self.logger.info(f"🎯 Vulnerabilidades: {len(alta)} ALTA, {len(media)} MÉDIA, {len(baixa)} BAIXA")
            
            return {
                'alvo': alvo,
                'sucesso': True,
                'duracao_segundos': round(duracao, 2),
                'vulnerabilidades': vulnerabilidades,
                'total_vulnerabilidades': len(vulnerabilidades),
                'vulnerabilidades_alta': len(alta),
                'vulnerabilidades_media': len(media),
                'vulnerabilidades_baixa': len(baixa),
                'tecnologias': resultado.get('tecnologias', {}),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Erro no scan ativo: {e}")
            return {
                'alvo': alvo,
                'sucesso': False,
                'erro': str(e),
                'timestamp': datetime.now().isoformat()
            }

def main():
    """Teste do módulo"""
    scanner = VarreduraZap()
    
    # Teste spider
    resultado_spider = scanner.spider_scan('127.0.0.1')
    print("Spider:", resultado_spider)
    
    # Teste scan ativo
    resultado_ativo = scanner.active_scan('127.0.0.1')
    print("Ativo:", resultado_ativo)

if __name__ == "__main__":
    main()
