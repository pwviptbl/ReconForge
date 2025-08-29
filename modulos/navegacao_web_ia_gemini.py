#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de Navegação Web com IA Gemini
Integra login automático com análise inteligente de páginas protegidas
Baseado no sistema VarreduraIA existente
"""

import json
import time
import base64
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass

import sys
from pathlib import Path

# Garantir diretório raiz no path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Imports do sistema existente
from modulos.navegacao_web_ia import NavegadorWebIA
from modulos.varredura_scraper_multi_engine import (
    VarreduraScraperMultiEngine,
    ConfiguracaoNavegador,
    EngineNavegador,
    ResultadoScraping
)
from modulos.decisao_ia import DecisaoIA
from utils.logger import obter_logger
from utils.anonimizador_ip import criar_contexto_seguro_para_ia


@dataclass
class ResultadoAnaliseGemini:
    """Resultado da análise com Gemini"""
    sucesso: bool
    url_analisada: str
    titulo_pagina: str
    analise_ia: str
    elementos_encontrados: Dict[str, Any]
    vulnerabilidades_potenciais: List[Dict[str, Any]]
    recomendacoes: List[str]
    nivel_risco: str
    tempo_analise: float
    screenshot_path: Optional[str] = None
    erro: Optional[str] = None


class NavegadorWebIAGemini:
    """Navegador web com análise inteligente usando Gemini"""
    
    def __init__(self):
        self.logger = obter_logger("NavegadorWebIAGemini")
        
        # Componentes do sistema
        self.navegador_base = NavegadorWebIA()
        self.decisao_ia = DecisaoIA()
        
        # Templates de prompts para análise de páginas
        self.templates_prompts = {
            'analisar_pagina_protegida': """
Analise esta página web protegida (após login) e forneça uma análise de segurança:

INFORMAÇÕES DA PÁGINA:
URL: {url}
Título: {titulo}
Status: {status_code}

FORMULÁRIOS ENCONTRADOS:
{formularios}

LINKS DESCOBERTOS:
{links_resumo}

TECNOLOGIAS DETECTADAS:
{tecnologias}

COOKIES DE SESSÃO:
{cookies_resumo}

CONTEÚDO DA PÁGINA (primeiros 2000 caracteres):
{conteudo_pagina}

Por favor, analise e forneça:

1. **RESUMO EXECUTIVO**: Visão geral da página e sua funcionalidade

2. **ELEMENTOS DE SEGURANÇA IDENTIFICADOS**:
   - Mecanismos de autenticação presentes
   - Proteções CSRF detectadas
   - Validações de entrada observadas
   - Controles de acesso visíveis

3. **VULNERABILIDADES POTENCIAIS**:
   - Possíveis pontos de entrada para ataques
   - Formulários sem proteção adequada
   - Exposição de informações sensíveis
   - Configurações inseguras detectadas

4. **SUPERFÍCIE DE ATAQUE**:
   - Endpoints críticos identificados
   - Parâmetros interessantes para testes
   - Funcionalidades de alto risco

5. **RECOMENDAÇÕES DE TESTE**:
   - Testes específicos a serem realizados
   - Payloads recomendados
   - Áreas prioritárias para investigação

6. **NÍVEL DE RISCO**: Classifique como CRÍTICO/ALTO/MÉDIO/BAIXO

Responda em português e seja específico sobre os achados de segurança.
""",

            'analisar_formularios_detalhado': """
Analise especificamente os formulários encontrados nesta página protegida:

{formularios_detalhados}

Para cada formulário, identifique:

1. **TIPO E PROPÓSITO**: Qual a função do formulário
2. **CAMPOS SENSÍVEIS**: Campos que processam dados críticos
3. **PROTEÇÕES PRESENTES**: Tokens CSRF, validações, sanitização
4. **VULNERABILIDADES POTENCIAIS**: 
   - SQL Injection
   - XSS (Cross-Site Scripting)
   - CSRF (Cross-Site Request Forgery)
   - Bypass de autenticação
   - Injeção de comandos
5. **PAYLOADS SUGERIDOS**: Payloads específicos para testar
6. **PRIORIDADE DE TESTE**: Alta/Média/Baixa

Responda em formato estruturado em português.
""",

            'analisar_apis_descobertas': """
Analise os endpoints de API descobertos nesta aplicação:

{endpoints_api}

CONTEXTO DA APLICAÇÃO:
- URL Base: {url_base}
- Tecnologias: {tecnologias}
- Status de Autenticação: Logado

Para cada endpoint, forneça:

1. **FUNCIONALIDADE PROVÁVEL**: O que o endpoint provavelmente faz
2. **MÉTODOS HTTP SUPORTADOS**: GET, POST, PUT, DELETE, etc.
3. **PARÂMETROS ESPERADOS**: Que dados o endpoint pode aceitar
4. **RISCOS DE SEGURANÇA**:
   - Exposição de dados sensíveis
   - Falta de autorização
   - Injeção de parâmetros
   - Bypass de controles
5. **TESTES RECOMENDADOS**: Como testar cada endpoint
6. **PRIORIDADE**: Crítica/Alta/Média/Baixa

Seja específico sobre técnicas de teste para APIs.
"""
        }
    
    def executar_analise_completa(self, url: str, credenciais: Dict[str, str], 
                                 engine: EngineNavegador = EngineNavegador.PLAYWRIGHT_CHROMIUM,
                                 analisar_com_gemini: bool = True) -> Dict[str, Any]:
        """
        Executa análise completa: login + navegação + análise IA
        
        Args:
            url: URL da página de login
            credenciais: {'usuario': str, 'senha': str}
            engine: Engine de navegador a usar
            analisar_com_gemini: Se deve usar Gemini para análise
            
        Returns:
            Dict com resultados completos
        """
        self.logger.info(f"🚀 Iniciando análise completa de {url}")
        inicio_total = time.time()
        
        resultado_completo = {
            'timestamp': datetime.now().isoformat(),
            'url_inicial': url,
            'credenciais_usuario': credenciais.get('usuario', 'N/A'),
            'engine_utilizada': engine.value,
            'fases_executadas': [],
            'sucesso_geral': False,
            'tempo_total': 0,
            'analise_gemini_habilitada': analisar_com_gemini
        }
        
        try:
            # Fase 1: Login e navegação básica
            self.logger.info("📝 Fase 1: Executando login e navegação...")
            resultado_navegacao = self._executar_login_navegacao(url, credenciais, engine)
            resultado_completo['navegacao'] = resultado_navegacao
            resultado_completo['fases_executadas'].append('navegacao')
            
            if not resultado_navegacao.get('sucesso', False):
                resultado_completo['erro'] = 'Falha na fase de navegação/login'
                return resultado_completo
            
            # Fase 2: Exploração de páginas protegidas
            self.logger.info("🔍 Fase 2: Explorando páginas protegidas...")
            resultado_exploracao = self._explorar_paginas_protegidas(
                resultado_navegacao, engine
            )
            resultado_completo['exploracao'] = resultado_exploracao
            resultado_completo['fases_executadas'].append('exploracao')
            
            # Fase 3: Análise com Gemini (se habilitada)
            if analisar_com_gemini:
                self.logger.info("🧠 Fase 3: Análise inteligente com Gemini...")
                resultado_analise = self._analisar_com_gemini(
                    resultado_navegacao, resultado_exploracao
                )
                resultado_completo['analise_gemini'] = resultado_analise
                resultado_completo['fases_executadas'].append('analise_gemini')
            else:
                self.logger.info("🧠 Fase 3: Análise Gemini desabilitada")
                resultado_completo['analise_gemini'] = {'habilitada': False}
            
            # Fase 4: Consolidação de resultados
            self.logger.info("📊 Fase 4: Consolidando resultados...")
            resultado_consolidado = self._consolidar_resultados(resultado_completo)
            resultado_completo.update(resultado_consolidado)
            resultado_completo['fases_executadas'].append('consolidacao')
            
            resultado_completo['sucesso_geral'] = True
            
        except Exception as e:
            self.logger.error(f"❌ Erro na análise completa: {e}")
            resultado_completo['erro'] = str(e)
        
        finally:
            resultado_completo['tempo_total'] = time.time() - inicio_total
            self.logger.info(f"⏱️ Análise completa finalizada em {resultado_completo['tempo_total']:.2f}s")
        
        return resultado_completo
    
    def _executar_login_navegacao(self, url: str, credenciais: Dict[str, str], 
                                 engine: EngineNavegador) -> Dict[str, Any]:
        """Executa login e navegação inicial"""
        try:
            # Usar o navegador base existente com engine específica
            config = ConfiguracaoNavegador(
                engine=engine,
                headless=True,
                timeout=30,
                wait_for_network=True
            )
            
            scraper = VarreduraScraperMultiEngine(config)
            resultado_scraping = scraper.executar_scraping(url, credenciais)
            
            # Converter resultado para formato compatível
            resultado_navegacao = {
                'sucesso': resultado_scraping.sucesso,
                'url_final': resultado_scraping.url,
                'titulo': resultado_scraping.titulo,
                'status_code': resultado_scraping.status_code,
                'formularios': resultado_scraping.formularios,
                'links': resultado_scraping.links,
                'tecnologias': resultado_scraping.tecnologias,
                'cookies': resultado_scraping.cookies,
                'screenshot_path': resultado_scraping.screenshot_path,
                'tempo_execucao': resultado_scraping.tempo_execucao,
                'engine_usado': resultado_scraping.engine_usado,
                'erro': resultado_scraping.erro
            }
            
            # Verificar se login foi bem-sucedido
            if resultado_navegacao['sucesso']:
                login_sucesso = self._verificar_sucesso_login(resultado_navegacao)
                resultado_navegacao['login_bem_sucedido'] = login_sucesso
                
                if login_sucesso:
                    self.logger.info("✅ Login realizado com sucesso!")
                else:
                    self.logger.warning("⚠️ Login pode não ter sido bem-sucedido")
            
            return resultado_navegacao
            
        except Exception as e:
            self.logger.error(f"Erro na navegação: {e}")
            return {
                'sucesso': False,
                'erro': str(e),
                'login_bem_sucedido': False
            }
    
    def _verificar_sucesso_login(self, resultado_navegacao: Dict[str, Any]) -> bool:
        """Verifica se o login foi bem-sucedido"""
        try:
            url_final = resultado_navegacao.get('url_final', '').lower()
            titulo = resultado_navegacao.get('titulo', '').lower()
            
            # Indicadores de login bem-sucedido
            indicadores_sucesso = [
                'dashboard', 'painel', 'sistema', 'home', 'inicio',
                'menu', 'principal', 'desktop', 'admin', 'user'
            ]
            
            # Indicadores de falha no login
            indicadores_falha = ['login', 'signin', 'auth', 'erro', 'error']
            
            # Verificar URL final
            if any(indicador in url_final for indicador in indicadores_falha):
                return False
            
            # Verificar título da página
            if any(indicador in titulo for indicador in indicadores_sucesso):
                return True
            
            # Verificar cookies de sessão
            cookies = resultado_navegacao.get('cookies', [])
            cookies_sessao = [c for c in cookies if 'session' in c.get('name', '').lower()]
            if cookies_sessao:
                return True
            
            # Se não tem indicadores de falha e não está na página de login, provavelmente sucesso
            if not any(indicador in url_final for indicador in indicadores_falha):
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Erro ao verificar login: {e}")
            return False
    
    def _explorar_paginas_protegidas(self, resultado_navegacao: Dict[str, Any], 
                                   engine: EngineNavegador) -> Dict[str, Any]:
        """Explora páginas protegidas após login bem-sucedido"""
        if not resultado_navegacao.get('login_bem_sucedido', False):
            return {
                'executada': False,
                'motivo': 'Login não foi bem-sucedido'
            }
        
        try:
            url_base = resultado_navegacao.get('url_final', '')
            links_descobertos = resultado_navegacao.get('links', [])
            
            # URLs comuns de sistemas web para explorar
            urls_explorar = set()
            
            # Adicionar URLs comuns
            from urllib.parse import urljoin, urlparse
            parsed_base = urlparse(url_base)
            base_url = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            caminhos_comuns = [
                '/admin', '/dashboard', '/painel', '/sistema', '/home',
                '/usuario', '/profile', '/config', '/settings', '/menu',
                '/api', '/rest', '/graphql', '/extension', '/desktop'
            ]
            
            for caminho in caminhos_comuns:
                urls_explorar.add(urljoin(base_url, caminho))
            
            # Adicionar links descobertos que parecem interessantes
            for link in links_descobertos[:20]:  # Limitar para performance
                if any(termo in link.lower() for termo in [
                    'admin', 'dashboard', 'panel', 'user', 'profile',
                    'config', 'settings', 'api', 'system'
                ]):
                    urls_explorar.add(link)
            
            # Explorar URLs
            paginas_exploradas = []
            config = ConfiguracaoNavegador(
                engine=engine,
                headless=True,
                timeout=15,
                wait_for_network=False  # Mais rápido para exploração
            )
            
            scraper = VarreduraScraperMultiEngine(config)
            
            for url in list(urls_explorar)[:10]:  # Limitar a 10 URLs
                try:
                    self.logger.debug(f"Explorando: {url}")
                    resultado = scraper.executar_scraping(url, None)  # Sem credenciais, usando sessão
                    
                    if resultado.sucesso and resultado.status_code == 200:
                        pagina_info = {
                            'url': resultado.url,
                            'titulo': resultado.titulo,
                            'formularios': len(resultado.formularios),
                            'links': len(resultado.links),
                            'tecnologias': resultado.tecnologias,
                            'tempo_carregamento': resultado.tempo_execucao
                        }
                        paginas_exploradas.append(pagina_info)
                        
                except Exception as e:
                    self.logger.debug(f"Erro ao explorar {url}: {e}")
                    continue
            
            return {
                'executada': True,
                'urls_tentadas': len(urls_explorar),
                'paginas_acessiveis': len(paginas_exploradas),
                'paginas_exploradas': paginas_exploradas,
                'tempo_exploracao': sum(p.get('tempo_carregamento', 0) for p in paginas_exploradas)
            }
            
        except Exception as e:
            self.logger.error(f"Erro na exploração: {e}")
            return {
                'executada': False,
                'erro': str(e)
            }
    
    def _analisar_com_gemini(self, resultado_navegacao: Dict[str, Any], 
                           resultado_exploracao: Dict[str, Any]) -> Dict[str, Any]:
        """Executa análise inteligente com Gemini"""
        try:
            # Conectar ao Gemini
            if not self.decisao_ia.conectado and not self.decisao_ia.conectar_gemini():
                return {
                    'executada': False,
                    'erro': 'Não foi possível conectar ao Gemini'
                }
            
            analises_realizadas = []
            
            # Análise 1: Página principal pós-login
            if resultado_navegacao.get('login_bem_sucedido', False):
                analise_principal = self._analisar_pagina_principal(resultado_navegacao)
                if analise_principal:
                    analises_realizadas.append(analise_principal)
            
            # Análise 2: Formulários encontrados
            formularios = resultado_navegacao.get('formularios', [])
            if formularios:
                analise_formularios = self._analisar_formularios_gemini(formularios, resultado_navegacao)
                if analise_formularios:
                    analises_realizadas.append(analise_formularios)
            
            # Análise 3: APIs descobertas (se houver)
            if self._tem_apis_descobertas(resultado_navegacao, resultado_exploracao):
                analise_apis = self._analisar_apis_gemini(resultado_navegacao, resultado_exploracao)
                if analise_apis:
                    analises_realizadas.append(analise_apis)
            
            # Consolidar análises
            return {
                'executada': True,
                'total_analises': len(analises_realizadas),
                'analises': analises_realizadas,
                'resumo_geral': self._gerar_resumo_analises(analises_realizadas)
            }
            
        except Exception as e:
            self.logger.error(f"Erro na análise Gemini: {e}")
            return {
                'executada': False,
                'erro': str(e)
            }
    
    def _analisar_pagina_principal(self, resultado_navegacao: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analisa a página principal pós-login com Gemini"""
        try:
            # Preparar dados para análise (contexto seguro)
            dados_pagina = {
                'url': resultado_navegacao.get('url_final', ''),
                'titulo': resultado_navegacao.get('titulo', ''),
                'status_code': resultado_navegacao.get('status_code', 0),
                'formularios': resultado_navegacao.get('formularios', []),
                'links': resultado_navegacao.get('links', []),
                'tecnologias': resultado_navegacao.get('tecnologias', {}),
                'cookies': resultado_navegacao.get('cookies', [])
            }
            
            # Criar contexto seguro para IA
            contexto_seguro = criar_contexto_seguro_para_ia(dados_pagina)
            
            # Preparar dados para o prompt
            prompt_data = {
                'url': contexto_seguro.get('url', 'N/A'),
                'titulo': contexto_seguro.get('titulo', 'N/A'),
                'status_code': contexto_seguro.get('status_code', 0),
                'formularios': json.dumps(contexto_seguro.get('formularios', []), indent=2, ensure_ascii=False),
                'links_resumo': f"{len(contexto_seguro.get('links', []))} links encontrados",
                'tecnologias': json.dumps(contexto_seguro.get('tecnologias', {}), indent=2, ensure_ascii=False),
                'cookies_resumo': f"{len(contexto_seguro.get('cookies', []))} cookies de sessão",
                'conteudo_pagina': f"[Página {contexto_seguro.get('titulo', 'sem título')} carregada com sucesso]"
            }
            
            # Gerar prompt
            prompt = self.templates_prompts['analisar_pagina_protegida'].format(**prompt_data)
            
            # Executar análise
            resposta_ia = self.decisao_ia._executar_consulta_gemini(prompt, "analise_pagina_protegida")
            
            if resposta_ia:
                return {
                    'tipo': 'pagina_principal',
                    'url_analisada': dados_pagina['url'],  # URL original para logs
                    'titulo': dados_pagina['titulo'],
                    'analise_completa': resposta_ia,
                    'elementos_analisados': {
                        'formularios': len(dados_pagina['formularios']),
                        'links': len(dados_pagina['links']),
                        'tecnologias': len(dados_pagina['tecnologias']),
                        'cookies': len(dados_pagina['cookies'])
                    },
                    'timestamp': datetime.now().isoformat()
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Erro na análise da página principal: {e}")
            return None
    
    def _analisar_formularios_gemini(self, formularios: List[Dict], 
                                   resultado_navegacao: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analisa formulários específicos com Gemini"""
        try:
            if not formularios:
                return None
            
            # Preparar dados dos formulários (contexto seguro)
            dados_formularios = {'formularios': formularios}
            contexto_seguro = criar_contexto_seguro_para_ia(dados_formularios)
            
            formularios_detalhados = json.dumps(
                contexto_seguro.get('formularios', []), 
                indent=2, 
                ensure_ascii=False
            )
            
            # Gerar prompt
            prompt = self.templates_prompts['analisar_formularios_detalhado'].format(
                formularios_detalhados=formularios_detalhados
            )
            
            # Executar análise
            resposta_ia = self.decisao_ia._executar_consulta_gemini(prompt, "analise_formularios")
            
            if resposta_ia:
                return {
                    'tipo': 'formularios',
                    'total_formularios': len(formularios),
                    'analise_detalhada': resposta_ia,
                    'formularios_analisados': [
                        {
                            'action': form.get('action', ''),
                            'method': form.get('method', 'GET'),
                            'inputs': len(form.get('inputs', []))
                        }
                        for form in formularios
                    ],
                    'timestamp': datetime.now().isoformat()
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Erro na análise de formulários: {e}")
            return None
    
    def _tem_apis_descobertas(self, resultado_navegacao: Dict[str, Any], 
                            resultado_exploracao: Dict[str, Any]) -> bool:
        """Verifica se há APIs descobertas para analisar"""
        # Verificar links que parecem ser APIs
        links = resultado_navegacao.get('links', [])
        apis_encontradas = [
            link for link in links 
            if any(termo in link.lower() for termo in ['/api/', '/rest/', '/graphql', '.json'])
        ]
        
        return len(apis_encontradas) > 0
    
    def _analisar_apis_gemini(self, resultado_navegacao: Dict[str, Any], 
                            resultado_exploracao: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analisa APIs descobertas com Gemini"""
        try:
            # Extrair endpoints de API
            links = resultado_navegacao.get('links', [])
            endpoints_api = [
                link for link in links 
                if any(termo in link.lower() for termo in ['/api/', '/rest/', '/graphql', '.json'])
            ]
            
            if not endpoints_api:
                return None
            
            # Preparar dados para análise (contexto seguro)
            dados_apis = {
                'endpoints_api': endpoints_api,
                'url_base': resultado_navegacao.get('url_final', ''),
                'tecnologias': resultado_navegacao.get('tecnologias', {})
            }
            
            contexto_seguro = criar_contexto_seguro_para_ia(dados_apis)
            
            # Gerar prompt
            prompt = self.templates_prompts['analisar_apis_descobertas'].format(
                endpoints_api=json.dumps(contexto_seguro.get('endpoints_api', []), indent=2, ensure_ascii=False),
                url_base=contexto_seguro.get('url_base', 'N/A'),
                tecnologias=json.dumps(contexto_seguro.get('tecnologias', {}), indent=2, ensure_ascii=False)
            )
            
            # Executar análise
            resposta_ia = self.decisao_ia._executar_consulta_gemini(prompt, "analise_apis")
            
            if resposta_ia:
                return {
                    'tipo': 'apis',
                    'total_endpoints': len(endpoints_api),
                    'analise_apis': resposta_ia,
                    'endpoints_descobertos': endpoints_api,  # URLs originais para logs
                    'timestamp': datetime.now().isoformat()
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Erro na análise de APIs: {e}")
            return None
    
    def _gerar_resumo_analises(self, analises: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Gera resumo consolidado das análises"""
        try:
            resumo = {
                'total_analises_realizadas': len(analises),
                'tipos_analise': [analise.get('tipo', 'desconhecido') for analise in analises],
                'elementos_totais_analisados': 0,
                'principais_achados': [],
                'nivel_risco_geral': 'BAIXO'
            }
            
            # Consolidar elementos analisados
            for analise in analises:
                if analise.get('tipo') == 'pagina_principal':
                    elementos = analise.get('elementos_analisados', {})
                    resumo['elementos_totais_analisados'] += sum(elementos.values())
                elif analise.get('tipo') == 'formularios':
                    resumo['elementos_totais_analisados'] += analise.get('total_formularios', 0)
                elif analise.get('tipo') == 'apis':
                    resumo['elementos_totais_analisados'] += analise.get('total_endpoints', 0)
            
            # Extrair principais achados (simplificado)
            for analise in analises:
                conteudo = analise.get('analise_completa', '') or analise.get('analise_detalhada', '') or analise.get('analise_apis', '')
                
                # Procurar por indicadores de risco
                if any(termo in conteudo.lower() for termo in ['crítico', 'crítica', 'grave', 'vulnerabilidade']):
                    resumo['nivel_risco_geral'] = 'ALTO'
                    resumo['principais_achados'].append(f"Possíveis vulnerabilidades identificadas em {analise.get('tipo', 'análise')}")
                elif any(termo in conteudo.lower() for termo in ['médio', 'atenção', 'cuidado']):
                    if resumo['nivel_risco_geral'] == 'BAIXO':
                        resumo['nivel_risco_geral'] = 'MÉDIO'
                    resumo['principais_achados'].append(f"Pontos de atenção encontrados em {analise.get('tipo', 'análise')}")
            
            return resumo
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar resumo: {e}")
            return {
                'total_analises_realizadas': len(analises),
                'erro_resumo': str(e)
            }
    
    def _consolidar_resultados(self, resultado_completo: Dict[str, Any]) -> Dict[str, Any]:
        """Consolida todos os resultados em um formato final"""
        try:
            consolidacao = {
                'resumo_executivo': {
                    'login_realizado': resultado_completo.get('navegacao', {}).get('login_bem_sucedido', False),
                    'paginas_exploradas': resultado_completo.get('exploracao', {}).get('paginas_acessiveis', 0),
                    'analise_ia_executada': resultado_completo.get('analise_gemini', {}).get('executada', False),
                    'tempo_total_execucao': resultado_completo.get('tempo_total', 0)
                },
                
                'descobertas_principais': {
                    'formularios_encontrados': len(resultado_completo.get('navegacao', {}).get('formularios', [])),
                    'links_descobertos': len(resultado_completo.get('navegacao', {}).get('links', [])),
                    'tecnologias_identificadas': len(resultado_completo.get('navegacao', {}).get('tecnologias', {})),
                    'cookies_sessao': len(resultado_completo.get('navegacao', {}).get('cookies', []))
                },
                
                'recomendacoes_finais': self._gerar_recomendacoes_finais(resultado_completo),
                
                'proximos_passos': self._sugerir_proximos_passos(resultado_completo)
            }
            
            return consolidacao
            
        except Exception as e:
            self.logger.error(f"Erro na consolidação: {e}")
            return {
                'erro_consolidacao': str(e)
            }
    
    def _gerar_recomendacoes_finais(self, resultado_completo: Dict[str, Any]) -> List[str]:
        """Gera recomendações finais baseadas nos resultados"""
        recomendacoes = []
        
        try:
            navegacao = resultado_completo.get('navegacao', {})
            exploracao = resultado_completo.get('exploracao', {})
            analise_gemini = resultado_completo.get('analise_gemini', {})
            
            # Recomendações baseadas no login
            if navegacao.get('login_bem_sucedido', False):
                recomendacoes.append("✅ Login automático funcionou - considere testar bypass de autenticação")
            else:
                recomendacoes.append("❌ Falha no login - verificar credenciais ou mecanismos de proteção")
            
            # Recomendações baseadas na exploração
            paginas_acessiveis = exploracao.get('paginas_acessiveis', 0)
            if paginas_acessiveis > 5:
                recomendacoes.append(f"🔍 {paginas_acessiveis} páginas acessíveis - superfície de ataque ampla")
            elif paginas_acessiveis > 0:
                recomendacoes.append(f"🔍 {paginas_acessiveis} páginas acessíveis - investigar funcionalidades")
            
            # Recomendações baseadas na análise IA
            if analise_gemini.get('executada', False):
                total_analises = analise_gemini.get('total_analises', 0)
                if total_analises > 0:
                    recomendacoes.append(f"🧠 {total_analises} análises IA realizadas - revisar achados detalhados")
                    
                    resumo = analise_gemini.get('resumo_geral', {})
                    nivel_risco = resumo.get('nivel_risco_geral', 'BAIXO')
                    if nivel_risco == 'ALTO':
                        recomendacoes.append("🚨 Nível de risco ALTO detectado - priorizar testes de segurança")
                    elif nivel_risco == 'MÉDIO':
                        recomendacoes.append("⚠️ Nível de risco MÉDIO - investigar pontos identificados")
            
            # Recomendações baseadas nos elementos encontrados
            formularios = len(navegacao.get('formularios', []))
            if formularios > 0:
                recomendacoes.append(f"📝 {formularios} formulários encontrados - testar injeções e validações")
            
            # Recomendação geral
            if not recomendacoes:
                recomendacoes.append("ℹ️ Análise básica concluída - considere testes manuais adicionais")
            
            return recomendacoes[:5]  # Máximo 5 recomendações
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar recomendações: {e}")
            return ["❌ Erro ao gerar recomendações - revisar logs para detalhes"]
    
    def _sugerir_proximos_passos(self, resultado_completo: Dict[str, Any]) -> List[str]:
        """Sugere próximos passos baseados nos resultados"""
        proximos_passos = []
        
        try:
            navegacao = resultado_completo.get('navegacao', {})
            exploracao = resultado_completo.get('exploracao', {})
            
            # Passos baseados no sucesso do login
            if navegacao.get('login_bem_sucedido', False):
                proximos_passos.append("1. Executar testes de autorização em páginas protegidas")
                proximos_passos.append("2. Testar bypass de autenticação com diferentes usuários")
                
                # Se há formulários, sugerir testes específicos
                if navegacao.get('formularios', []):
                    proximos_passos.append("3. Executar testes de injeção SQL e XSS nos formulários")
                
                # Se há páginas exploradas, sugerir análise manual
                if exploracao.get('paginas_acessiveis', 0) > 0:
                    proximos_passos.append("4. Realizar análise manual das páginas descobertas")
                
                proximos_passos.append("5. Testar funcionalidades críticas identificadas")
                
            else:
                proximos_passos.append("1. Verificar credenciais e tentar diferentes combinações")
                proximos_passos.append("2. Analisar mecanismos de proteção do login")
                proximos_passos.append("3. Testar bypass de autenticação")
                proximos_passos.append("4. Verificar vulnerabilidades na página de login")
            
            return proximos_passos[:5]  # Máximo 5 passos
            
        except Exception as e:
            self.logger.error(f"Erro ao sugerir próximos passos: {e}")
            return ["1. Revisar logs de erro e repetir análise"]


# Função de compatibilidade para integração com sistema existente
def executar_analise_web_com_gemini(url: str, usuario: str, senha: str,
                                   engine: str = "playwright_chromium") -> Dict[str, Any]:
    """
    Função de compatibilidade para executar análise web com Gemini
    
    Args:
        url: URL da página de login
        usuario: Nome de usuário
        senha: Senha
        engine: Engine de navegador (padrão: playwright_chromium)
        
    Returns:
        Dict com resultados da análise
    """
    # Mapear string para enum
    engine_map = {
        'selenium_chrome': EngineNavegador.SELENIUM_CHROME,
        'selenium_firefox': EngineNavegador.SELENIUM_FIREFOX,
        'playwright_chromium': EngineNavegador.PLAYWRIGHT_CHROMIUM,
        'playwright_firefox': EngineNavegador.PLAYWRIGHT_FIREFOX,
        'mechanicalsoup': EngineNavegador.MECHANICALSOUP,
        'requests_html': EngineNavegador.REQUESTS_HTML
    }
    
    engine_obj = engine_map.get(engine, EngineNavegador.PLAYWRIGHT_CHROMIUM)
    credenciais = {'usuario': usuario, 'senha': senha}
    
    navegador = NavegadorWebIAGemini()
    return navegador.executar_analise_completa(url, credenciais, engine_obj)


if __name__ == "__main__":
    """Teste do módulo"""
    import sys
    from utils.logger import obter_logger
    
    logger = obter_logger("NavegadorWebIAGeminiTest")
    
    # Configuração de teste
    url_teste = "http://localhost:8080/e-cidade/login.php"
    credenciais_teste = {
        'usuario': 'dbseller',
        'senha': ''
    }
    
    logger.info("🧪 Iniciando teste do NavegadorWebIAGemini")
    logger.info(f"URL: {url_teste}")
    logger.info(f"Usuário: {credenciais_teste['usuario']}")
    
    try:
        # Criar instância do navegador
        navegador = NavegadorWebIAGemini()
        
        # Executar análise completa
        resultado = navegador.executar_analise_completa(
            url=url_teste,
            credenciais=credenciais_teste,
            engine=EngineNavegador.PLAYWRIGHT_CHROMIUM,
            analisar_com_gemini=True
        )
        
        # Exibir resultados
        logger.info("📊 Resultados da análise:")
        logger.info(f"✅ Sucesso geral: {resultado.get('sucesso_geral', False)}")
        logger.info(f"⏱️ Tempo total: {resultado.get('tempo_total', 0):.2f}s")
        logger.info(f"🔧 Fases executadas: {', '.join(resultado.get('fases_executadas', []))}")
        
        # Resumo executivo
        resumo = resultado.get('resumo_executivo', {})
        logger.info(f"🔐 Login realizado: {resumo.get('login_realizado', False)}")
        logger.info(f"🔍 Páginas exploradas: {resumo.get('paginas_exploradas', 0)}")
        logger.info(f"🧠 Análise IA executada: {resumo.get('analise_ia_executada', False)}")
        
        # Descobertas principais
        descobertas = resultado.get('descobertas_principais', {})
        logger.info(f"📝 Formulários: {descobertas.get('formularios_encontrados', 0)}")
        logger.info(f"🔗 Links: {descobertas.get('links_descobertos', 0)}")
        logger.info(f"🔧 Tecnologias: {descobertas.get('tecnologias_identificadas', 0)}")
        
        # Recomendações
        recomendacoes = resultado.get('recomendacoes_finais', [])
        if recomendacoes:
            logger.info("💡 Recomendações:")
            for rec in recomendacoes:
                logger.info(f"   {rec}")
        
        # Próximos passos
        proximos_passos = resultado.get('proximos_passos', [])
        if proximos_passos:
            logger.info("🎯 Próximos passos:")
            for passo in proximos_passos:
                logger.info(f"   {passo}")
        
        # Salvar resultado completo em arquivo JSON para análise
        import json
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        arquivo_resultado = f"resultado_analise_gemini_{timestamp}.json"
        
        with open(arquivo_resultado, 'w', encoding='utf-8') as f:
            json.dump(resultado, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"💾 Resultado completo salvo em: {arquivo_resultado}")
        
    except Exception as e:
        logger.error(f"❌ Erro no teste: {e}")
        sys.exit(1)
    
    logger.info("✅ Teste concluído com sucesso!")