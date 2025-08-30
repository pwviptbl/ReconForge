#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integrador Web Gemini
Integra a funcionalidade de análise web com Gemini ao sistema VarreduraIA
"""

import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

# Garantir diretório raiz no path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modulos.navegacao_web_ia_gemini import NavegadorWebIAGemini, executar_analise_web_com_gemini
from modulos.varredura_scraper_multi_engine import EngineNavegador
from utils.logger import obter_logger


class IntegradorWebGemini:
    """Integra análise web com Gemini ao sistema principal"""
    
    def __init__(self):
        self.logger = obter_logger("IntegradorWebGemini")
        self.navegador_gemini = NavegadorWebIAGemini()
    
    def executar_para_orquestrador(self, alvo: str, credenciais: Optional[Dict[str, str]] = None,
                                  modo: str = "web", **kwargs) -> Dict[str, Any]:
        """
        Executa análise web com Gemini para o orquestrador
        
        Args:
            alvo: URL ou domínio alvo
            credenciais: Credenciais de login (opcional)
            modo: Modo de execução
            **kwargs: Parâmetros adicionais
            
        Returns:
            Dict padronizado para o orquestrador
        """
        self.logger.info(f"🚀 Iniciando análise web com Gemini para: {alvo}")
        
        inicio = datetime.now()
        
        try:
            # Normalizar URL
            url = self._normalizar_url(alvo)
            
            # Verificar se há credenciais
            if not credenciais:
                return self._executar_sem_credenciais(url)
            
            # Executar análise completa com login
            resultado_completo = self.navegador_gemini.executar_analise_completa(
                url=url,
                credenciais=credenciais,
                engine=EngineNavegador.PLAYWRIGHT_CHROMIUM,
                analisar_com_gemini=True
            )
            
            # Converter para formato do orquestrador
            resultado_orquestrador = self._converter_para_orquestrador(
                resultado_completo, alvo, inicio
            )
            
            return resultado_orquestrador
            
        except Exception as e:
            self.logger.error(f"❌ Erro na análise web com Gemini: {e}")
            return self._resultado_erro(alvo, str(e), inicio)
    
    def _normalizar_url(self, alvo: str) -> str:
        """Normaliza URL para análise"""
        if not alvo.startswith(('http://', 'https://')):
            # Tentar HTTPS primeiro, depois HTTP
            return f"https://{alvo}"
        return alvo
    
    def _executar_sem_credenciais(self, url: str) -> Dict[str, Any]:
        """Executa análise básica sem credenciais"""
        self.logger.info("ℹ️ Executando análise básica sem credenciais")
        
        try:
            # Usar navegador base para análise sem login
            from modulos.navegacao_web_ia import NavegadorWebIA
            navegador_base = NavegadorWebIA()
            
            resultado_base = navegador_base.executar(url)
            
            # Garantir que resultado_base seja um dicionário válido
            if resultado_base is None:
                resultado_base = {'sucesso': False, 'erro': 'Resultado None do navegador base'}
            
            # Log do resultado para debug
            self.logger.info(f"Resultado base do navegador: sucesso={resultado_base.get('sucesso', False)}")
            
            return {
                'sucesso': resultado_base.get('sucesso', False),
                'nome_modulo': 'navegador_web_gemini',
                'tipo_execucao': 'sem_credenciais',
                'dados': resultado_base.get('dados', {}),
                'timestamp': datetime.now().isoformat(),
                'observacoes': ['Análise executada sem credenciais de login'],
                'analises_detalhadas': [],
                'recomendacoes': [],
                'proximos_passos': []
            }
        except Exception as e:
            self.logger.error(f"Erro na execução sem credenciais: {str(e)}")
            return {
                'sucesso': False,
                'nome_modulo': 'navegador_web_gemini',
                'tipo_execucao': 'sem_credenciais',
                'dados': {},
                'timestamp': datetime.now().isoformat(),
                'erro': str(e),
                'observacoes': ['Erro na análise sem credenciais de login'],
                'analises_detalhadas': [],
                'recomendacoes': [],
                'proximos_passos': []
            }
    
    def _converter_para_orquestrador(self, resultado_completo: Dict[str, Any], 
                                   alvo: str, inicio: datetime) -> Dict[str, Any]:
        """Converte resultado para formato esperado pelo orquestrador"""
        
        sucesso_geral = resultado_completo.get('sucesso_geral', False)
        tempo_total = resultado_completo.get('tempo_total', 0)
        
        # Extrair dados principais
        navegacao = resultado_completo.get('navegacao', {})
        exploracao = resultado_completo.get('exploracao', {})
        analise_gemini = resultado_completo.get('analise_gemini', {})
        resumo_executivo = resultado_completo.get('resumo_executivo', {})
        descobertas = resultado_completo.get('descobertas_principais', {})
        
        # Dados padronizados para o orquestrador
        dados_orquestrador = {
            'url_base': navegacao.get('url_final', alvo),
            'login_realizado': resumo_executivo.get('login_realizado', False),
            'paginas_exploradas': resumo_executivo.get('paginas_exploradas', 0),
            'formularios': navegacao.get('formularios', []),
            'links': navegacao.get('links', []),
            'tecnologias': navegacao.get('tecnologias', {}),
            'cookies': navegacao.get('cookies', []),
            'screenshot_path': navegacao.get('screenshot_path'),
            
            # Métricas
            'total_formularios': descobertas.get('formularios_encontrados', 0),
            'total_links': descobertas.get('links_descobertos', 0),
            'total_tecnologias': descobertas.get('tecnologias_identificadas', 0),
            'total_cookies': descobertas.get('cookies_sessao', 0),
            
            # Análise IA
            'analise_ia_executada': analise_gemini.get('executada', False),
            'total_analises_ia': analise_gemini.get('total_analises', 0),
            'nivel_risco_ia': analise_gemini.get('resumo_geral', {}).get('nivel_risco_geral', 'BAIXO'),
            
            # Exploração
            'exploracao_executada': exploracao.get('executada', False),
            'urls_exploradas': exploracao.get('urls_tentadas', 0),
            'paginas_acessiveis': exploracao.get('paginas_acessiveis', 0),
            
            # Vulnerabilidades (formato compatível)
            'vulnerabilidades': self._extrair_vulnerabilidades_orquestrador(analise_gemini),
            'total_vulnerabilidades': len(self._extrair_vulnerabilidades_orquestrador(analise_gemini))
        }
        
        # Resultado final para orquestrador
        resultado_orquestrador = {
            'sucesso': sucesso_geral,
            'nome_modulo': 'navegador_web_gemini',
            'tipo_execucao': 'completa_com_gemini',
            'dados': dados_orquestrador,
            'timestamp': datetime.now().isoformat(),
            'tempo_execucao': tempo_total,
            'fases_executadas': resultado_completo.get('fases_executadas', []),
            
            # Informações adicionais
            'recomendacoes': resultado_completo.get('recomendacoes_finais', []),
            'proximos_passos': resultado_completo.get('proximos_passos', []),
            'engine_utilizada': resultado_completo.get('engine_utilizada', 'playwright_chromium'),
            
            # Análises detalhadas (para relatórios)
            'analises_detalhadas': analise_gemini.get('analises', []) if analise_gemini.get('executada') else [],
            
            # Resultado completo (para debug/logs)
            'resultado_completo_debug': resultado_completo if self.logger.level <= 10 else None  # DEBUG level
        }
        
        return resultado_orquestrador
    
    def _extrair_vulnerabilidades_orquestrador(self, analise_gemini: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrai vulnerabilidades em formato compatível com orquestrador"""
        vulnerabilidades = []
        
        if not analise_gemini.get('executada', False):
            return vulnerabilidades
        
        analises = analise_gemini.get('analises', [])
        
        for analise in analises:
            tipo_analise = analise.get('tipo', 'desconhecido')
            conteudo = (analise.get('analise_completa', '') or 
                       analise.get('analise_detalhada', '') or 
                       analise.get('analise_apis', ''))
            
            # Extrair vulnerabilidades do texto da análise IA (simplificado)
            vulnerabilidades_encontradas = self._extrair_vulnerabilidades_do_texto(conteudo, tipo_analise)
            vulnerabilidades.extend(vulnerabilidades_encontradas)
        
        return vulnerabilidades
    
    def _extrair_vulnerabilidades_do_texto(self, texto: str, tipo_analise: str) -> List[Dict[str, Any]]:
        """Extrai vulnerabilidades do texto de análise IA"""
        vulnerabilidades = []
        
        # Palavras-chave para identificar vulnerabilidades
        indicadores_vulnerabilidades = {
            'sql injection': 'ALTA',
            'xss': 'ALTA', 
            'cross-site scripting': 'ALTA',
            'csrf': 'MÉDIA',
            'cross-site request forgery': 'MÉDIA',
            'authentication bypass': 'CRÍTICA',
            'authorization bypass': 'CRÍTICA',
            'information disclosure': 'MÉDIA',
            'directory traversal': 'ALTA',
            'command injection': 'CRÍTICA',
            'file upload': 'MÉDIA',
            'weak authentication': 'ALTA',
            'session fixation': 'MÉDIA',
            'insecure direct object reference': 'ALTA'
        }
        
        texto_lower = texto.lower()
        
        for indicador, criticidade in indicadores_vulnerabilidades.items():
            if indicador in texto_lower:
                vulnerabilidades.append({
                    'tipo': indicador.replace(' ', '_').upper(),
                    'descricao': f"Possível {indicador} identificada na análise de {tipo_analise}",
                    'criticidade': criticidade,
                    'fonte': 'analise_gemini',
                    'tipo_analise': tipo_analise,
                    'timestamp': datetime.now().isoformat(),
                    'evidencia': self._extrair_evidencia_do_texto(texto, indicador)
                })
        
        return vulnerabilidades
    
    def _extrair_evidencia_do_texto(self, texto: str, indicador: str) -> str:
        """Extrai evidência específica do texto"""
        # Encontrar contexto ao redor do indicador
        texto_lower = texto.lower()
        pos = texto_lower.find(indicador)
        
        if pos == -1:
            return "Evidência não específica encontrada na análise"
        
        # Extrair contexto (100 caracteres antes e depois)
        inicio = max(0, pos - 100)
        fim = min(len(texto), pos + len(indicador) + 100)
        
        contexto = texto[inicio:fim].strip()
        return f"...{contexto}..."
    
    def _resultado_erro(self, alvo: str, erro: str, inicio: datetime) -> Dict[str, Any]:
        """Gera resultado de erro padronizado"""
        return {
            'sucesso': False,
            'nome_modulo': 'navegador_web_gemini',
            'tipo_execucao': 'erro',
            'erro': erro,
            'dados': {
                'url_base': alvo,
                'erro_detalhado': erro
            },
            'timestamp': datetime.now().isoformat(),
            'tempo_execucao': (datetime.now() - inicio).total_seconds()
        }


# Função de compatibilidade para o orquestrador
def executar_navegacao_web_gemini(alvo: str, credenciais: Optional[Dict[str, str]] = None,
                                 modo: str = "web", **kwargs) -> Dict[str, Any]:
    """
    Função de compatibilidade para integração com orquestrador
    
    Args:
        alvo: URL ou domínio alvo
        credenciais: Credenciais de login
        modo: Modo de execução
        **kwargs: Parâmetros adicionais
        
    Returns:
        Dict padronizado para orquestrador
    """
    integrador = IntegradorWebGemini()
    return integrador.executar_para_orquestrador(alvo, credenciais, modo, **kwargs)


if __name__ == "__main__":
    """Teste do integrador"""
    from utils.logger import obter_logger
    
    logger = obter_logger("IntegradorWebGeminiTest")
    
    # Teste com as credenciais do e-cidade
    alvo_teste = "http://localhost:8080/e-cidade/login.php"
    credenciais_teste = {
        'usuario': 'dbseller',
        'senha': ''
    }
    
    logger.info("🧪 Testando IntegradorWebGemini")
    logger.info(f"Alvo: {alvo_teste}")
    logger.info(f"Credenciais: {credenciais_teste['usuario']}")
    
    try:
        # Executar integração
        resultado = executar_navegacao_web_gemini(alvo_teste, credenciais_teste)
        
        # Exibir resultados
        logger.info("📊 Resultado da integração:")
        logger.info(f"✅ Sucesso: {resultado.get('sucesso', False)}")
        logger.info(f"🔧 Módulo: {resultado.get('nome_modulo', 'N/A')}")
        logger.info(f"⏱️ Tempo: {resultado.get('tempo_execucao', 0):.2f}s")
        
        dados = resultado.get('dados', {})
        logger.info(f"🔐 Login realizado: {dados.get('login_realizado', False)}")
        logger.info(f"📝 Formulários: {dados.get('total_formularios', 0)}")
        logger.info(f"🔗 Links: {dados.get('total_links', 0)}")
        logger.info(f"🧠 Análise IA: {dados.get('analise_ia_executada', False)}")
        logger.info(f"🚨 Vulnerabilidades: {dados.get('total_vulnerabilidades', 0)}")
        
        if dados.get('total_vulnerabilidades', 0) > 0:
            logger.info("🔍 Vulnerabilidades encontradas:")
            for vuln in dados.get('vulnerabilidades', []):
                logger.info(f"   • {vuln.get('tipo', 'N/A')} ({vuln.get('criticidade', 'N/A')})")
        
        logger.info("✅ Teste do integrador concluído com sucesso!")
        
    except Exception as e:
        logger.error(f"❌ Erro no teste: {e}")