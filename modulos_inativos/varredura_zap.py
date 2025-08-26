#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de integração OWASP ZAP
Realiza varreduras de segurança web usando OWASP ZAP
"""

import os
import subprocess
import json
import logging
import time
import requests
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
import tempfile

from core.configuracao import obter_config
from utils.logger import obter_logger

class VarreduraZAP:
    """Classe para executar varreduras OWASP ZAP"""
    
    def __init__(self):
        """Inicializa o módulo de varredura ZAP"""
        self.logger = logging.getLogger(__name__)
        self.binario_zap = obter_config('zap.binario', 'zap.sh')
        self.host_api = obter_config('zap.host_api', '127.0.0.1')
        self.porta_api = obter_config('zap.porta_api', 8080)
        self.api_key = obter_config('zap.api_key', '')
        self.timeout_padrao = obter_config('zap.timeout_padrao', 1800)
        self.opcoes_padrao = obter_config('zap.opcoes_padrao', ['-daemon'])
        
        self.base_url_api = f"http://{self.host_api}:{self.porta_api}"
        self.zap_processo = None
        
        # Verificar se o ZAP está disponível
        self.verificar_zap()
    
    def verificar_zap(self) -> bool:
        """
        Verifica se o OWASP ZAP está instalado e acessível
        Returns:
            bool: True se ZAP está disponível, False caso contrário
        """
        try:
            # Tentar conectar à API do ZAP se já estiver rodando
            response = requests.get(f"{self.base_url_api}/JSON/core/view/version/", timeout=5)
            if response.status_code == 200:
                versao = response.json().get('version', 'Desconhecida')
                self.logger.info(f"ZAP já está rodando: {versao}")
                return True
        except:
            pass
        
        # Verificar se o binário existe
        try:
            resultado = subprocess.run(
                [self.binario_zap, '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                self.logger.info("ZAP encontrado")
                return True
            else:
                self.logger.error("ZAP não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.error(f"Binário ZAP não encontrado: {self.binario_zap}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout ao verificar versão do ZAP")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar ZAP: {str(e)}")
            return False
    
    def iniciar_zap(self) -> bool:
        """
        Inicia o ZAP em modo daemon
        Returns:
            bool: True se iniciado com sucesso
        """
        try:
            # Verificar se já está rodando
            if self._zap_esta_rodando():
                self.logger.info("ZAP já está rodando")
                return True
            
            comando = [
                self.binario_zap,
                '-daemon',
                '-port', str(self.porta_api),
                '-host', self.host_api
            ]
            
            if self.api_key:
                comando.extend(['-config', f'api.key={self.api_key}'])
            
            self.logger.info(f"Iniciando ZAP: {' '.join(comando)}")
            
            self.zap_processo = subprocess.Popen(
                comando,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Aguardar ZAP inicializar
            for tentativa in range(30):  # 30 segundos
                if self._zap_esta_rodando():
                    self.logger.info("ZAP iniciado com sucesso")
                    return True
                time.sleep(1)
            
            self.logger.error("Timeout ao iniciar ZAP")
            return False
            
        except Exception as e:
            self.logger.error(f"Erro ao iniciar ZAP: {str(e)}")
            return False
    
    def parar_zap(self) -> bool:
        """
        Para o ZAP
        Returns:
            bool: True se parado com sucesso
        """
        try:
            if self.zap_processo:
                self.zap_processo.terminate()
                self.zap_processo.wait(timeout=10)
                self.zap_processo = None
                self.logger.info("ZAP parado com sucesso")
                return True
            return True
        except Exception as e:
            self.logger.error(f"Erro ao parar ZAP: {str(e)}")
            return False
    
    def varredura_spider(self, url: str, max_depth: int = 5) -> Dict[str, Any]:
        """
        Executa spider no alvo
        Args:
            url (str): URL alvo
            max_depth (int): Profundidade máxima do spider
        Returns:
            Dict[str, Any]: Resultados do spider
        """
        if not self._zap_esta_rodando():
            if not self.iniciar_zap():
                return {'sucesso': False, 'erro': 'Não foi possível iniciar o ZAP'}
        
        try:
            # Configurar spider
            self._fazer_requisicao_api('spider/action/setOptionMaxDepth/', {'Integer': max_depth})
            
            # Iniciar spider
            response = self._fazer_requisicao_api('spider/action/scan/', {'url': url})
            scan_id = response.get('scan', '')
            
            if not scan_id:
                return {'sucesso': False, 'erro': 'Falha ao iniciar spider'}
            
            # Aguardar conclusão
            self._aguardar_scan_completar('spider', scan_id)
            
            # Obter resultados
            urls_encontradas = self._fazer_requisicao_api('spider/view/results/', {'scanId': scan_id})
            
            return {
                'sucesso': True,
                'tipo_varredura': 'varredura_spider',
                'timestamp': datetime.now().isoformat(),
                'dados': {
                    'scan_id': scan_id,
                    'urls_encontradas': urls_encontradas.get('results', []),
                    'resumo': {
                        'total_urls': len(urls_encontradas.get('results', [])),
                        'profundidade_maxima': max_depth
                    }
                }
            }
            
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro no spider: {str(e)}'}
    
    def varredura_ativa(self, url: str, policy: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa varredura ativa no alvo
        Args:
            url (str): URL alvo
            policy (str): Política de varredura
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        if not self._zap_esta_rodando():
            if not self.iniciar_zap():
                return {'sucesso': False, 'erro': 'Não foi possível iniciar o ZAP'}
        
        try:
            # Primeiro fazer spider
            spider_result = self.varredura_spider(url)
            if not spider_result['sucesso']:
                return spider_result
            
            # Configurar política se especificada
            if policy:
                self._fazer_requisicao_api('ascan/action/setScannerAttackStrength/', 
                                         {'id': 'all', 'attackStrength': policy})
            
            # Iniciar varredura ativa
            response = self._fazer_requisicao_api('ascan/action/scan/', {'url': url})
            scan_id = response.get('scan', '')
            
            if not scan_id:
                return {'sucesso': False, 'erro': 'Falha ao iniciar varredura ativa'}
            
            # Aguardar conclusão
            self._aguardar_scan_completar('ascan', scan_id)
            
            # Obter alertas
            alertas = self._fazer_requisicao_api('core/view/alerts/', {'baseurl': url})
            
            return {
                'sucesso': True,
                'tipo_varredura': 'varredura_ativa',
                'timestamp': datetime.now().isoformat(),
                'dados': {
                    'scan_id': scan_id,
                    'alertas': alertas.get('alerts', []),
                    'resumo': self._processar_alertas(alertas.get('alerts', []))
                }
            }
            
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro na varredura ativa: {str(e)}'}
    
    def varredura_passiva(self, url: str) -> Dict[str, Any]:
        """
        Executa varredura passiva no alvo
        Args:
            url (str): URL alvo
        Returns:
            Dict[str, Any]: Resultados da varredura
        """
        if not self._zap_esta_rodando():
            if not self.iniciar_zap():
                return {'sucesso': False, 'erro': 'Não foi possível iniciar o ZAP'}
        
        try:
            # Acessar URL para gerar tráfego
            self._fazer_requisicao_api('core/action/accessUrl/', {'url': url})
            
            # Aguardar varredura passiva processar
            time.sleep(10)
            
            # Obter alertas passivos
            alertas = self._fazer_requisicao_api('core/view/alerts/', {'baseurl': url})
            
            return {
                'sucesso': True,
                'tipo_varredura': 'varredura_passiva',
                'timestamp': datetime.now().isoformat(),
                'dados': {
                    'alertas': alertas.get('alerts', []),
                    'resumo': self._processar_alertas(alertas.get('alerts', []))
                }
            }
            
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro na varredura passiva: {str(e)}'}
    
    def gerar_relatorio_html(self, titulo: str = "Relatório ZAP") -> Dict[str, Any]:
        """
        Gera relatório HTML
        Args:
            titulo (str): Título do relatório
        Returns:
            Dict[str, Any]: Resultado da geração
        """
        if not self._zap_esta_rodando():
            return {'sucesso': False, 'erro': 'ZAP não está rodando'}
        
        try:
            # Criar arquivo temporário
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as temp_file:
                arquivo_relatorio = temp_file.name
            
            # Gerar relatório
            self._fazer_requisicao_api('reports/action/generate/', {
                'title': titulo,
                'template': 'traditional-html',
                'reportFileName': arquivo_relatorio
            })
            
            return {
                'sucesso': True,
                'arquivo_relatorio': arquivo_relatorio,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro ao gerar relatório: {str(e)}'}
    
    def _zap_esta_rodando(self) -> bool:
        """Verifica se ZAP está rodando"""
        try:
            response = requests.get(f"{self.base_url_api}/JSON/core/view/version/", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def _fazer_requisicao_api(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Faz requisição para API do ZAP"""
        url = f"{self.base_url_api}/JSON/{endpoint}"
        
        if params is None:
            params = {}
        
        if self.api_key:
            params['apikey'] = self.api_key
        
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        
        return response.json()
    
    def _aguardar_scan_completar(self, tipo_scan: str, scan_id: str) -> None:
        """Aguarda scan completar"""
        while True:
            status = self._fazer_requisicao_api(f'{tipo_scan}/view/status/', {'scanId': scan_id})
            progresso = int(status.get('status', 0))
            
            if progresso >= 100:
                break
            
            self.logger.info(f"Progresso do {tipo_scan}: {progresso}%")
            time.sleep(5)
    
    def _processar_alertas(self, alertas: List[Dict]) -> Dict[str, Any]:
        """Processa alertas do ZAP"""
        resumo = {
            'total_alertas': len(alertas),
            'por_risco': {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0},
            'por_confianca': {'High': 0, 'Medium': 0, 'Low': 0},
            'alertas_unicos': set()
        }
        
        for alerta in alertas:
            risco = alerta.get('risk', 'Low')
            confianca = alerta.get('confidence', 'Low')
            nome = alerta.get('name', '')
            
            if risco in resumo['por_risco']:
                resumo['por_risco'][risco] += 1
            
            if confianca in resumo['por_confianca']:
                resumo['por_confianca'][confianca] += 1
            
            if nome:
                resumo['alertas_unicos'].add(nome)
        
        resumo['alertas_unicos'] = len(resumo['alertas_unicos'])
        return resumo
    
    def gerar_relatorio_resumido(self, resultados: Dict[str, Any]) -> str:
        """
        Gera relatório resumido da varredura
        Args:
            resultados (Dict[str, Any]): Resultados da varredura
        Returns:
            str: Relatório em formato texto
        """
        if not resultados.get('sucesso'):
            return f"Erro na varredura: {resultados.get('erro', 'Erro desconhecido')}"
        
        dados = resultados.get('dados', {})
        resumo = dados.get('resumo', {})
        
        relatorio = []
        relatorio.append("=" * 60)
        relatorio.append(f"RELATÓRIO OWASP ZAP - {resultados['tipo_varredura'].upper()}")
        relatorio.append("=" * 60)
        relatorio.append(f"Timestamp: {resultados['timestamp']}")
        relatorio.append("")
        
        # Resumo
        if 'total_alertas' in resumo:
            relatorio.append("RESUMO:")
            relatorio.append(f"  Total de Alertas: {resumo.get('total_alertas', 0)}")
            relatorio.append(f"  Alertas Únicos: {resumo.get('alertas_unicos', 0)}")
            relatorio.append("")
            
            # Por risco
            por_risco = resumo.get('por_risco', {})
            if any(por_risco.values()):
                relatorio.append("POR NÍVEL DE RISCO:")
                for risco, count in por_risco.items():
                    if count > 0:
                        relatorio.append(f"  {risco}: {count}")
                relatorio.append("")
        
        # URLs encontradas (spider)
        if 'urls_encontradas' in dados:
            urls = dados['urls_encontradas']
            relatorio.append(f"URLs ENCONTRADAS: {len(urls)}")
            for url in urls[:10]:  # Máximo 10
                relatorio.append(f"  • {url}")
            if len(urls) > 10:
                relatorio.append(f"  ... e mais {len(urls) - 10} URLs")
        
        return "\n".join(relatorio)


if __name__ == "__main__":
    # Teste do módulo
    logger = obter_logger('VarreduraZAPCLI')
    varredura = VarreduraZAP()
    
    if varredura.verificar_zap():
        logger.info("OWASP ZAP está disponível!")
        
        url = input("Digite a URL para varredura: ").strip()
        if url:
            logger.info(f"Executando varredura passiva em {url}...")
            resultado = varredura.varredura_passiva(url)
            
            if resultado['sucesso']:
                logger.info("\nRelatório da Varredura:")
                logger.info(varredura.gerar_relatorio_resumido(resultado))
            else:
                logger.error(f"Erro na varredura: {resultado['erro']}")
    else:
        logger.error("OWASP ZAP não está disponível. Instale o ZAP para continuar.")