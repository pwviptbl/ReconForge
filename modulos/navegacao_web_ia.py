#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo NavegadorWebIA
Wrapper reutilizável de automação de navegador para estudo inicial de páginas web,
utilizável pelo Orquestrador e pela IA dentro do LOOP.

Padrões:
- Tenta Selenium (Chrome headless) primeiro
- Fallback automático para Playwright (Chromium headless) se Selenium falhar
- Segundo fallback para Playwright (Firefox headless) se Chromium falhar
- Aceita credenciais opcionais (usuario/senha) para tentar login básico
- Retorna dicionário padronizado para o orquestrador
"""

from typing import Optional, Dict, Any
from datetime import datetime

from utils.logger import obter_logger

# Engines multi-navegador
from modulos.varredura_scraper_multi_engine import (
    VarreduraScraperMultiEngine,
    ConfiguracaoNavegador,
    EngineNavegador
)


class NavegadorWebIA:
    """Wrapper de navegador para estudo web, integrável no LOOP-IA."""

    def __init__(self):
        self.logger = obter_logger("NavegadorWebIA")

    def executar(self, alvo: str, credenciais: Optional[Dict[str, str]] = None,
                 headless: bool = True, timeout: int = 30, user_agent: Optional[str] = None) -> Dict[str, Any]:
        """
        Executa estudo web com navegador.
        Tenta Selenium/Chrome; em falha, tenta Playwright/Chromium.

        Args:
            alvo: URL ou host (sem protocolo)
            credenciais: {'usuario': str, 'senha': str} (opcional)
            headless: executar sem UI
            timeout: timeout base
            user_agent: UA custom (opcional)

        Returns:
            Dict padronizado:
            {
              'sucesso': bool,
              'nome_modulo': 'navegador_web',
              'dados': {...},
              'timestamp': iso
            }
        """
        url = self._normalizar_url(alvo)

        # 1) Tentar Selenium Chrome
        try:
            self.logger.info(f"[NavegadorWebIA] Estudando via Selenium Chrome: {url}")
            dados = self._rodar_engine(
                url=url,
                engine=EngineNavegador.SELENIUM_CHROME,
                credenciais=credenciais,
                headless=headless,
                timeout=timeout,
                user_agent=user_agent
            )
            if dados.get('sucesso'):
                return {
                    'sucesso': True,
                    'nome_modulo': 'navegador_web',
                    'dados': dados,
                    'timestamp': datetime.now().isoformat()
                }
            self.logger.warning(f"[NavegadorWebIA] Selenium não obteve sucesso: {dados.get('erro', 'sem detalhe')}")
        except Exception as e:
            self.logger.warning(f"[NavegadorWebIA] Erro Selenium: {str(e)}")

        # 2) Fallback: Playwright Chromium
        try:
            self.logger.info(f"[NavegadorWebIA] Fallback via Playwright Chromium: {url}")
            dados = self._rodar_engine(
                url=url,
                engine=EngineNavegador.PLAYWRIGHT_CHROMIUM,
                credenciais=credenciais,
                headless=headless,
                timeout=timeout,
                user_agent=user_agent
            )
            if dados.get('sucesso'):
                return {
                    'sucesso': True,
                    'nome_modulo': 'navegador_web',
                    'dados': dados,
                    'timestamp': datetime.now().isoformat()
                }
            self.logger.warning(f"[NavegadorWebIA] Playwright Chromium falhou: {dados.get('erro', 'sem detalhe')}")
        except Exception as e:
            self.logger.warning(f"[NavegadorWebIA] Erro Playwright Chromium: {str(e)}")

        # 3) Segundo fallback: Playwright Firefox (mais compatível)
        try:
            self.logger.info(f"[NavegadorWebIA] Segundo fallback via Playwright Firefox: {url}")
            dados = self._rodar_engine(
                url=url,
                engine=EngineNavegador.PLAYWRIGHT_FIREFOX,
                credenciais=credenciais,
                headless=headless,
                timeout=timeout,
                user_agent=user_agent
            )
            if dados.get('sucesso'):
                return {
                    'sucesso': True,
                    'nome_modulo': 'navegador_web',
                    'dados': dados,
                    'timestamp': datetime.now().isoformat()
                }
            self.logger.error(f"[NavegadorWebIA] Playwright Firefox também falhou: {dados.get('erro', 'sem detalhe')}")
            return {
                'sucesso': False,
                'nome_modulo': 'navegador_web',
                'erro': dados.get('erro', 'Falha em todas as engines de navegador'),
                'dados': dados,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"[NavegadorWebIA] Erro Playwright Firefox: {str(e)}")
            return {
                'sucesso': False,
                'nome_modulo': 'navegador_web',
                'erro': f"Erro crítico em todas as engines: {str(e)}",
                'dados': {},
                'timestamp': datetime.now().isoformat()
            }

    def _rodar_engine(self, url: str, engine: EngineNavegador, credenciais: Optional[Dict[str, str]],
                      headless: bool, timeout: int, user_agent: Optional[str]) -> Dict[str, Any]:
        """
        Executa a engine especificada e normaliza o retorno para o orquestrador.
        """
        try:
            config = ConfiguracaoNavegador(
                engine=engine,
                headless=headless,
                timeout=timeout,
                user_agent=user_agent
            )
            scraper = VarreduraScraperMultiEngine(config)
            resultado = scraper.executar_scraping(url, credenciais)

            dados = self._resultado_para_dict(resultado)
            # Padronizar campos esperados pelo orquestrador
            dados['url_base'] = dados.get('url', url)
            # Coluna de vulnerabilidades não é foco desse estudo; manter compatível
            dados.setdefault('vulnerabilidades', [])
            dados.setdefault('total_vulnerabilidades', 0)

            return {
                'sucesso': bool(resultado.sucesso),
                'engine_usada': dados.get('engine_usado', engine.value),
                **dados
            }
        except Exception as e:
            return {
                'sucesso': False,
                'erro': str(e),
                'engine_usada': engine.value
            }

    def _resultado_para_dict(self, res) -> Dict[str, Any]:
        """
        Converte ResultadoScraping (dataclass) em dicionário simples.
        """
        try:
            return {
                'url': getattr(res, 'url', ''),
                'titulo': getattr(res, 'titulo', ''),
                'status_code': getattr(res, 'status_code', 0),
                'formularios': getattr(res, 'formularios', []) or [],
                'links': getattr(res, 'links', []) or [],
                'tecnologias': getattr(res, 'tecnologias', {}) or {},
                'cookies': getattr(res, 'cookies', []) or [],
                'screenshot_path': getattr(res, 'screenshot_path', None),
                'tempo_execucao': getattr(res, 'tempo_execucao', 0.0),
                'engine_usado': getattr(res, 'engine_usado', ''),
                # Métricas simples
                'total_formularios': len(getattr(res, 'formularios', []) or []),
                'total_links': len(getattr(res, 'links', []) or []),
            }
        except Exception as e:
            self.logger.debug(f"[NavegadorWebIA] Erro convertendo resultado: {e}")
            return {
                'url': '',
                'titulo': '',
                'status_code': 0,
                'formularios': [],
                'links': [],
                'tecnologias': {},
                'cookies': [],
                'screenshot_path': None,
                'tempo_execucao': 0.0,
                'engine_usado': '',
                'total_formularios': 0,
                'total_links': 0,
            }

    def _normalizar_url(self, alvo: str) -> str:
        """
        Normaliza o alvo para URL. Se não vier com esquema, usa http://
        (SSL/TLS pode falhar em ambientes de teste; http é mais permissivo.)
        """
        alvo = (alvo or '').strip()
        if alvo.startswith('http://') or alvo.startswith('https://'):
            return alvo
        return f"http://{alvo}".rstrip('/')


if __name__ == "__main__":
    # Teste rápido manual (ajustar URL conforme ambiente)
    nav = NavegadorWebIA()
    resp = nav.executar("example.com")
    print(resp)