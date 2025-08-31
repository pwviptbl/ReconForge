#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Orquestrador Inteligente com Loop Adaptativo

Fluxos suportados:
- Modo rede (padrão): DNS → RustScan (todas as portas) → LOOP-IA
- Modo web (--web-scan): Estudo com navegador (Selenium com fallback Playwright) → LOOP-IA

Política de falhas da IA:
- Em erro de consulta à IA (RuntimeError): aguardar 30s e tentar novamente
- Após 5 falhas consecutivas: parar execução e gerar relatório
"""

import json
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from utils.logger import obter_logger, log_manager
from utils.rede import extrair_ips_para_scan
from utils.anonimizador_ip import criar_contexto_seguro_para_ia

# Novo: Agente IA Central (Fase 1)
from core.agente_ia_central import AgenteIACentral


@dataclass
class ContextoExecucao:
    """Contexto acumulativo de execução"""
    alvo_original: str
    timestamp_inicio: str
    ips_descobertos: List[str] = field(default_factory=list)
    portas_abertas: Dict[str, List[int]] = field(default_factory=dict)
    servicos_detectados: Dict[str, Dict] = field(default_factory=dict)
    vulnerabilidades_encontradas: List[Dict] = field(default_factory=list)
    modulos_executados: List[str] = field(default_factory=list)
    resultados_por_modulo: Dict[str, Dict] = field(default_factory=dict)
    decisoes_ia: List[Dict] = field(default_factory=list)
    pontuacao_risco: int = 0
    finalizado: bool = False
    motivo_finalizacao: str = ""


class OrquestradorInteligente:
    """Orquestrador com loop inteligente baseado em IA"""

    def __init__(self, resolver_dns, scanner_portas, scanner_nmap, decisao_ia, logger_func=obter_logger):
        self.logger = logger_func('OrquestradorInteligente')
        self.resolver_dns = resolver_dns
        self.scanner_portas = scanner_portas
        self.scanner_nmap = scanner_nmap
        self.decisao_ia = decisao_ia

        # Novo: Agente IA Central (Fase 1)
        self.agente_ia_central = None
        self._inicializar_agente_central()

        # Verificar Gemini (obrigatório)
        if not self._verificar_gemini_obrigatorio():
            raise RuntimeError(" Sistema requer Gemini AI ativo. Configure a chave API no config/default.yaml")

        self.modulos_disponiveis: Dict[str, Any] = {}
        self._carregar_modulos()

        # Estado dinâmico
        self.credenciais_web: Optional[Dict[str, str]] = None

        # Configuração do loop
        self.max_iteracoes = 50
        self.min_intervalo_iteracao = 2

        self.logger.info("Orquestrador Inteligente inicializado")
        self.logger.info(f"Módulos disponíveis: {list(self.modulos_disponiveis.keys())}")

    def _inicializar_agente_central(self):
        """Inicializa o Agente IA Central (Fase 1)"""
        try:
            import yaml
            import os
            config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'default.yaml')
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            config_ia = config.get('ia_centralizada', {})
            
            # Usar chave API do Gemini se não estiver definida na seção ia_centralizada
            if not config_ia.get('chave_api'):
                config_ia['chave_api'] = config.get('api', {}).get('gemini', {}).get('chave_api')
            
            self.logger.info(f"Config IA carregada: habilitar={config_ia.get('habilitar_agente_autonomo', False)}")
            self.logger.info(f"Chave API presente: {bool(config_ia.get('chave_api'))}")
            
            if config_ia.get('habilitar_agente_autonomo', False):
                self.logger.info("Inicializando Agente IA Central...")
                self.agente_ia_central = AgenteIACentral(config_ia, self.logger)
                self.logger.info("✅ Agente IA Central habilitado com sucesso!")
            else:
                self.logger.info("Agente IA Central desabilitado (configuração)")
        except Exception as e:
            self.logger.error(f"Erro ao inicializar Agente IA Central: {e}. Usando modo legado.")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            self.agente_ia_central = None

    def _verificar_gemini_obrigatorio(self) -> bool:
        try:
            self.logger.info(" Verificando Gemini AI (OBRIGATÓRIO)...")
            if not self.decisao_ia.conectar_gemini():
                self.logger.error(" Falha ao conectar com Gemini AI")
                return False
            teste_prompt = "Responda apenas: TESTE_OK"
            resposta = self.decisao_ia._executar_consulta_gemini(teste_prompt)
            if resposta and "TESTE_OK" in resposta:
                self.logger.info(" Gemini AI verificado e funcionando!")
                return True
            self.logger.error(" Gemini AI não respondeu corretamente ao teste")
            return False
        except Exception as e:
            self.logger.error(f" Erro na verificação do Gemini: {str(e)}")
            return False

    def _carregar_modulos(self):
        """Carrega dinamicamente módulos e registra no dicionário."""
        try:
            # Varreduras web
            # from modulos.varredura_feroxbuster import VarreduraFeroxbuster  # REMOVIDO - substituído por scanner_diretorios_python
            # from modulos.varredura_whatweb import VarreduraWhatWeb  # REMOVIDO - substituído por detector_tecnologias_python
            from modulos.varredura_nuclei import VarreduraNuclei

            # Descoberta
            # from modulos.varredura_subfinder import VarreduraSubfinder  # REMOVIDO - substituído por enumerador_subdominios_python
            # from modulos.varredura_sublist3r import VarreduraSublist3r  # REMOVIDO - substituído por enumerador_subdominios_python

            # Exploração
            from modulos.varredura_sqlmap import VarreduraSQLMap
            # from modulos.varredura_searchsploit import VarreduraSearchSploit  # REMOVIDO - substituído por buscador_exploits_python

            # Scanners
            from modulos.scanner_vulnerabilidades import ScannerVulnerabilidades
            from modulos.scanner_web_avancado import ScannerWebAvancado
            from modulos.varredura_scraper_auth import VarreduraScraperAuth
            from modulos.navegacao_web_ia import NavegadorWebIA
            
            # Navegação Web com Gemini
            from modulos.integrador_web_gemini import IntegradorWebGemini

            # Novos módulos Python puro
            from modulos.scanner_portas_python import ScannerPortasPython
            from modulos.enumerador_subdominios_python import EnumeradorSubdominiosPython
            from modulos.detector_tecnologias_python import DetectorTecnologiasPython
            from modulos.scanner_diretorios_python import ScannerDiretoriosPython
            from modulos.buscador_exploits_python import BuscadorExploitsPython
            from modulos.analisador_vulnerabilidades_web import AnalisadorVulnerabilidadesWeb

            self.modulos_disponiveis = {
                # Módulos antigos removidos - substituídos por versões Python puro
                # 'feroxbuster_basico': VarreduraFeroxbuster(),  # REMOVIDO
                # 'feroxbuster_recursivo': VarreduraFeroxbuster(),  # REMOVIDO
                # 'whatweb_scan': VarreduraWhatWeb(),  # REMOVIDO
                'nuclei_scan': VarreduraNuclei(),
                # 'subfinder_enum': VarreduraSubfinder(),  # REMOVIDO
                # 'sublist3r_enum': VarreduraSublist3r(),  # REMOVIDO
                'sqlmap_teste_url': VarreduraSQLMap(),
                'sqlmap_teste_formulario': VarreduraSQLMap(),
                # 'searchsploit_check': VarreduraSearchSploit(),  # REMOVIDO
                'scanner_vulnerabilidades': ScannerVulnerabilidades(),
                'scanner_web_avancado': ScannerWebAvancado(),
                'scraper_auth': VarreduraScraperAuth(),
                'navegador_web': NavegadorWebIA(),
                
                # Navegação Web com Gemini
                'navegador_web_gemini': IntegradorWebGemini(),

                # Novos módulos Python puro
                'scanner_portas_python': ScannerPortasPython(),
                'enumerador_subdominios_python': EnumeradorSubdominiosPython(),
                'detector_tecnologias_python': DetectorTecnologiasPython(),
                'scanner_diretorios_python': ScannerDiretoriosPython(),
                'buscador_exploits_python': BuscadorExploitsPython(),
                'analisador_vulnerabilidades_web_python': AnalisadorVulnerabilidadesWeb(),

                # Nmap (instâncias)
                'nmap_varredura_basica': self.scanner_nmap,
                'nmap_varredura_completa': self.scanner_nmap,
                'nmap_varredura_vulnerabilidades': self.scanner_nmap,
                'nmap_varredura_servicos_web': self.scanner_nmap,
                'nmap_varredura_smb': self.scanner_nmap,
                'nmap_descoberta_rede': self.scanner_nmap,
            }
            self.logger.info(f"✓ {len(self.modulos_disponiveis)} módulos carregados")
        except ImportError as e:
            self.logger.warning(f"Alguns módulos não puderam ser carregados: {e}")
            self.modulos_disponiveis = {
                'nmap_varredura_basica': self.scanner_nmap,
                'nmap_varredura_completa': self.scanner_nmap,
                'nmap_varredura_vulnerabilidades': self.scanner_nmap,
            }

    def _atualizar_contexto_com_resultado(self, contexto: ContextoExecucao, nome_modulo: str, resultado: Dict[str, Any]):
        """Atualiza o contexto com o resultado de um módulo executado."""
        contexto.resultados_por_modulo[nome_modulo] = resultado
        contexto.modulos_executados.append(nome_modulo)
        self.logger.debug(f"Resultado do módulo '{nome_modulo}' adicionado ao contexto")

        # Novo: Notificar Agente IA Central (Fase 1)
        if self.agente_ia_central:
            try:
                self.agente_ia_central.atualizar_estado(resultado)
            except Exception as e:
                self.logger.warning(f"Erro ao atualizar Agente IA Central: {e}")

    def executar_pentest_inteligente(self, alvo: str, modo: str = 'rede', credenciais_web: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Executa o fluxo escolhido (rede ou web) e entra no LOOP-IA."""
        self.logger.info(f" Iniciando pentest inteligente para {alvo} (modo={modo})")

        # Iniciar sessão de histórico
        try:
            sessao_id = self.decisao_ia.historico.iniciar_sessao(alvo, "pentest_inteligente")
            self.logger.info(f" Sessão de histórico iniciada: {sessao_id}")
        except Exception as e:
            self.logger.warning(f"Erro ao iniciar sessão de histórico: {e}")

        contexto = ContextoExecucao(
            alvo_original=alvo,
            timestamp_inicio=datetime.now().isoformat()
        )

        try:
            if modo == 'web_gemini':
                # Fluxo WEB com GEMINI
                self.credenciais_web = credenciais_web
                self.logger.info("=== FASE 1 (WEB + GEMINI): Análise Inteligente com Login Automático ===")
                resultado_web_gemini = self._executar_estudo_web_gemini_preloop(alvo, contexto, credenciais_web)
                if not resultado_web_gemini.get('sucesso'):
                    return self._finalizar_com_erro(contexto, f"Falha no estudo web com Gemini: {resultado_web_gemini.get('erro')}")

                self.logger.info("=== FASE 2: Loop Inteligente ===")
                self._executar_loop_inteligente(contexto)

                self.logger.info("=== FASE 3: Finalização ===")
                return self._finalizar_pentest(contexto)
            
            elif modo == 'web':
                # Fluxo WEB
                self.credenciais_web = credenciais_web
                self.logger.info("=== FASE 1 (WEB): Estudo com Navegador ===")
                resultado_web = self._executar_estudo_web_preloop(alvo, contexto, credenciais_web)
                if not resultado_web.get('sucesso'):
                    return self._finalizar_com_erro(contexto, f"Falha no estudo web: {resultado_web.get('erro')}")

                self.logger.info("=== FASE 2: Loop Inteligente ===")
                self._executar_loop_inteligente(contexto)

                self.logger.info("=== FASE 3: Finalização ===")
                return self._finalizar_pentest(contexto)

            # Fluxo REDE
            self.logger.info("=== FASE 1: Resolução DNS ===")
            resultado_dns = self._executar_resolucao_dns(alvo, contexto)
            if not resultado_dns.get('sucesso'):
                return self._finalizar_com_erro(contexto, f"Falha na resolução DNS: {resultado_dns.get('erro')}")

            self.logger.info("=== FASE 2: Scan Inicial de Portas ===")
            resultado_scan = self._executar_scan_inicial(contexto)
            if not resultado_scan.get('sucesso'):
                return self._finalizar_com_erro(contexto, f"Falha no scan inicial: {resultado_scan.get('erro')}")

            self.logger.info("=== FASE 3: Loop Inteligente ===")
            self._executar_loop_inteligente(contexto)

            self.logger.info("=== FASE 4: Finalização ===")
            return self._finalizar_pentest(contexto)

        except Exception as e:
            self.logger.error(f"Erro crítico no pentest: {str(e)}")
            return self._finalizar_com_erro(contexto, f"Erro crítico: {str(e)}")

    def _executar_estudo_web_gemini_preloop(self, alvo: str, contexto: ContextoExecucao, credenciais: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Executa estudo web com Gemini e atualiza o contexto."""
        try:
            if 'navegador_web_gemini' not in self.modulos_disponiveis:
                return {'sucesso': False, 'erro': 'Módulo navegador_web_gemini não disponível'}

            modulo = self.modulos_disponiveis['navegador_web_gemini']

            url = (alvo or '').strip()
            if not url.startswith('http://') and not url.startswith('https://'):
                url = f"http://{url}"

            self.logger.info(f"🚀 Executando análise web com Gemini para: {url}")
            if credenciais:
                self.logger.info(f"🔐 Usando credenciais: {credenciais.get('usuario', 'N/A')}")

            # Executar análise completa com Gemini
            resultado_bruto = modulo.executar_para_orquestrador(
                alvo=url,
                credenciais=credenciais,
                modo='web_gemini'
            )

            # Verificar se resultado_bruto é válido
            if resultado_bruto is None:
                self.logger.error("Resultado bruto é None - módulo retornou None")
                return {'sucesso': False, 'erro': 'Módulo retornou resultado None'}

            # Garantir que seja um dicionário
            if not isinstance(resultado_bruto, dict):
                self.logger.error(f"Resultado bruto não é dicionário: {type(resultado_bruto)}")
                return {'sucesso': False, 'erro': f'Resultado inválido do módulo: {type(resultado_bruto)}'}

            self.logger.info(f"Resultado bruto recebido: sucesso={resultado_bruto.get('sucesso', 'N/A')}")

            resultado_por_alvo = {
                url: {
                    'sucesso': bool(resultado_bruto.get('sucesso', False)),
                    'dados': resultado_bruto.get('dados', {}),
                    'timestamp': resultado_bruto.get('timestamp', datetime.now().isoformat())
                }
            }

            resultado_normalizado = {
                'nome_modulo': 'navegador_web_gemini',
                'sucesso': bool(resultado_bruto.get('sucesso', False)),
                'resultados_por_alvo': resultado_por_alvo,
                'parametros_utilizados': {'credenciais': bool(credenciais), 'gemini_habilitado': True},
                'alvos_executados': [url],
                'alvos_ia_originais': [url],
                'timestamp': datetime.now().isoformat(),
                'sucesso_geral': bool(resultado_bruto.get('sucesso', False)),
                'analise_gemini': resultado_bruto.get('analises_detalhadas', []),
                'recomendacoes': resultado_bruto.get('recomendacoes', []),
                'proximos_passos': resultado_bruto.get('proximos_passos', [])
            }

            # Adicionar mensagem de erro se o resultado não foi bem-sucedido
            if not resultado_normalizado['sucesso']:
                erro_msg = resultado_bruto.get('erro', 'Análise web falhou - navegadores não conseguiram executar')
                resultado_normalizado['erro'] = erro_msg
                self.logger.warning(f"Análise web com Gemini falhou: {erro_msg}")

            self._atualizar_contexto_com_resultado(contexto, 'navegador_web_gemini', resultado_normalizado)
            
            # Log dos resultados principais
            dados = resultado_bruto.get('dados', {})
            self.logger.info(f"✅ Análise Gemini concluída:")
            self.logger.info(f"   🔐 Login realizado: {dados.get('login_realizado', False)}")
            self.logger.info(f"   📝 Formulários: {dados.get('total_formularios', 0)}")
            self.logger.info(f"   🔗 Links: {dados.get('total_links', 0)}")
            self.logger.info(f"   🧠 Análise IA: {dados.get('analise_ia_executada', False)}")
            self.logger.info(f"   🚨 Vulnerabilidades: {dados.get('total_vulnerabilidades', 0)}")
            
            return resultado_normalizado
            
        except Exception as e:
            self.logger.error(f"Erro no estudo web com Gemini: {str(e)}")
            return {'sucesso': False, 'erro': f'Erro no estudo web com Gemini: {str(e)}'}

    def _executar_estudo_web_preloop(self, alvo: str, contexto: ContextoExecucao, credenciais: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Executa estudo web com 'navegador_web' e atualiza o contexto."""
        try:
            if 'navegador_web' not in self.modulos_disponiveis:
                return {'sucesso': False, 'erro': 'Módulo navegador_web não disponível'}

            modulo = self.modulos_disponiveis['navegador_web']

            url = (alvo or '').strip()
            if not url.startswith('http://') and not url.startswith('https://'):
                url = f"http://{url}"

            resultado_bruto = modulo.executar(url, credenciais)

            resultado_por_alvo = {
                url: {
                    'sucesso': bool(resultado_bruto.get('sucesso', False)),
                    'dados': resultado_bruto.get('dados', {}),
                    'timestamp': resultado_bruto.get('timestamp', datetime.now().isoformat())
                }
            }

            resultado_normalizado = {
                'nome_modulo': 'navegador_web',
                'sucesso': bool(resultado_bruto.get('sucesso', False)),
                'resultados_por_alvo': resultado_por_alvo,
                'parametros_utilizados': {'credenciais': bool(credenciais)},
                'alvos_executados': [url],
                'alvos_ia_originais': [url],
                'timestamp': datetime.now().isoformat(),
                'sucesso_geral': bool(resultado_bruto.get('sucesso', False))
            }

            self._atualizar_contexto_com_resultado(contexto, 'navegador_web', resultado_normalizado)
            return {'sucesso': bool(resultado_bruto.get('sucesso', False)), 'dados': resultado_bruto}
        except Exception as e:
            self.logger.error(f"Erro no estudo web pré-loop: {str(e)}")
            return {'sucesso': False, 'erro': f'Erro no estudo web: {str(e)}'}

    def _executar_resolucao_dns(self, alvo: str, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Executa resolução DNS e atualiza contexto."""
        try:
            resultado_dns = self.resolver_dns.resolver_dns(alvo)
            if resultado_dns.get('sucesso'):
                ips_para_scan = extrair_ips_para_scan(resultado_dns)
                contexto.ips_descobertos = ips_para_scan
                contexto.resultados_por_modulo['resolucao_dns'] = resultado_dns
                contexto.modulos_executados.append('resolucao_dns')
                self.logger.info(f"✓ DNS resolvido: {len(ips_para_scan)} IPs descobertos")
            return resultado_dns
        except Exception as e:
            self.logger.error(f"Erro na resolução DNS: {str(e)}")
            return {'sucesso': False, 'erro': f'Erro na resolução DNS: {str(e)}'}

    def _executar_scan_inicial(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Executa scan inicial de portas (RustScan via wrapper scanner_portas)."""
        try:
            if not contexto.ips_descobertos:
                return {'sucesso': False, 'erro': 'Nenhum IP disponível para scan'}

            resultados_scan: Dict[str, Any] = {}
            for ip in contexto.ips_descobertos:
                self.logger.info(f" Escaneando portas em {ip}")
                resultado_scan = self.scanner_portas.varredura_completa(ip)
                resultados_scan[ip] = resultado_scan

                if resultado_scan.get('sucesso'):
                    portas_abertas = self._extrair_portas_abertas(resultado_scan)
                    contexto.portas_abertas[ip] = portas_abertas
                    self.logger.info(f"✓ {len(portas_abertas)} portas abertas em {ip}")
                else:
                    self.logger.warning(f" Falha no scan de {ip}")

            contexto.resultados_por_modulo['scan_inicial'] = resultados_scan
            contexto.modulos_executados.append('scan_inicial')
            contexto.pontuacao_risco = self._calcular_pontuacao_risco(contexto)
            return {'sucesso': True, 'resultados': resultados_scan}
        except Exception as e:
            self.logger.error(f"Erro no scan inicial: {str(e)}")
            return {'sucesso': False, 'erro': f'Erro no scan inicial: {str(e)}'}

    def _executar_loop_inteligente(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Loop principal com política de retry de IA (30s; 5 falhas)."""
        iteracao = 0
        falhas_consecutivas = 0

        while not contexto.finalizado and iteracao < self.max_iteracoes:
            iteracao += 1
            self.logger.info(f" Iteração {iteracao} do loop inteligente")
            try:
                decisao_ia = self._consultar_ia_proximos_passos(contexto)
                falhas_consecutivas = 0
                contexto.decisoes_ia.append(decisao_ia)

                acao = decisao_ia.get('acao', 'parar')
                self.logger.info(f" IA decidiu: {acao}")

                if acao == 'parar':
                    contexto.finalizado = True
                    contexto.motivo_finalizacao = decisao_ia.get('justificativa', 'IA decidiu parar')
                    self.logger.info(f" IA decidiu parar: {contexto.motivo_finalizacao}")
                    break

                if acao == 'executar_modulo':
                    modulo_escolhido = decisao_ia.get('modulo', '')
                    nome_exec = modulo_escolhido
                    if modulo_escolhido not in self.modulos_disponiveis:
                        nome_mapeado = self._mapear_categoria_para_modulo(modulo_escolhido)
                        if nome_mapeado:
                            self.logger.info(f" Mapeando '{modulo_escolhido}' → {nome_mapeado}")
                            nome_exec = nome_mapeado
                        else:
                            self.logger.warning(f" Módulo desconhecido: {modulo_escolhido}")
                            continue

                    resultado_modulo = self._executar_modulo(nome_exec, contexto, decisao_ia)
                    self._atualizar_contexto_com_resultado(contexto, nome_exec, resultado_modulo)
                    contexto.pontuacao_risco = self._calcular_pontuacao_risco(contexto)

            except RuntimeError as e:
                falhas_consecutivas += 1
                self.logger.error(f" ERRO DE IA: {str(e)} (falhas consecutivas: {falhas_consecutivas}/5)")
                if falhas_consecutivas >= 5:
                    contexto.finalizado = True
                    contexto.motivo_finalizacao = f"IA falhou 5 vezes consecutivas: {str(e)}"
                    break
                self.logger.info(" Aguardando 30s antes de tentar novamente...")
                time.sleep(30)
                continue
            except Exception as e:
                self.logger.error(f"Erro na iteração {iteracao}: {str(e)}")
                contexto.finalizado = True
                contexto.motivo_finalizacao = f"Erro na iteração {iteracao}: {str(e)}"
                break

        if iteracao >= self.max_iteracoes:
            contexto.finalizado = True
            contexto.motivo_finalizacao = f"Limite máximo de iterações atingido ({self.max_iteracoes})"
            self.logger.warning(f" {contexto.motivo_finalizacao}")

        return {'iteracoes_executadas': iteracao, 'contexto_final': contexto}

    def _consultar_ia_proximos_passos(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Consulta IA com contexto seguro e retorna decisão em JSON."""
        # Novo: Usar Agente IA Central se disponível (Fase 1)
        if self.agente_ia_central:
            try:
                self.logger.info("🤖 Usando Agente IA Central para decisão...")
                contexto_completo = self._montar_contexto_completo(contexto)
                modulos_disp = list(self.modulos_disponiveis.keys())
                decisao = self.agente_ia_central.tomar_decisao(contexto_completo, modulos_disp)
                self.logger.info("🤖 Decisão do Agente IA Central obtida")
                return decisao
            except Exception as e:
                self.logger.warning(f"Erro no Agente IA Central: {e}. Usando Gemini fallback.")

        # Fallback: Método original com Gemini
        # Montar contexto completo (origem) e seguro (para IA)
        contexto_completo = self._montar_contexto_completo(contexto)
        contexto_seguro = criar_contexto_seguro_para_ia(contexto_completo)
        prompt_contexto = self._gerar_prompt_contexto_completo_seguro(contexto_seguro, contexto)

        prompt_universal = f"""
CONTEXTO ATUAL DO PENTEST (IPs anonimizados por segurança):
{prompt_contexto}

MÓDULOS DISPONÍVEIS:
{self._listar_modulos_disponiveis()}

MÓDULOS JÁ EXECUTADOS:
{', '.join(contexto.modulos_executados)}

Com base no contexto atual, decida o próximo passo. Você pode:
1. Executar um módulo específico
2. Parar e gerar relatório final

IMPORTANTE SOBRE SEGURANÇA:
- Os IPs foram anonimizados para proteger a privacidade
- A estrutura e tipos de rede foram preservados para análise
- Suas decisões serão aplicadas aos alvos reais pelo sistema

Responda APENAS em formato JSON:
{{
    "acao": "executar_modulo|parar",
    "modulo": "nome_do_modulo_se_aplicavel",
    "alvos": ["use_alvos_descobertos"],
    "parametros": {{"parametros_especiais": "se_necessario"}},
    "justificativa": "explicação_da_decisão",
    "prioridade": "alta|media|baixa",
    "expectativa": "o_que_espera_descobrir"
}}

IMPORTANTE:
- Use EXATAMENTE os nomes dos módulos listados acima
- Para alvos, use sempre "use_alvos_descobertos"
- Evite repetir análises já feitas
- Pare quando análise estiver completa
- Priorize módulos que podem revelar vulnerabilidades críticas
"""

        self.logger.info("🔒 Consultando Gemini AI com contexto seguro...")
        resposta_ia = self.decisao_ia._executar_consulta_gemini(prompt_universal, "decisao_loop_seguro")
        if not resposta_ia:
            raise RuntimeError(" Gemini AI não retornou resposta válida")

        decisao = self._parsear_decisao_ia_loop(resposta_ia)
        if not decisao:
            raise RuntimeError(" Não foi possível parsear resposta da IA")

        self.logger.info(f"🧠 IA decidiu: {decisao.get('acao', 'N/A')}")
        self.logger.info("🔒 Contexto enviado com IPs anonimizados - privacidade preservada")
        return decisao

    def _montar_contexto_completo(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        return {
            'alvo_original': contexto.alvo_original,
            'timestamp_inicio': contexto.timestamp_inicio,
            'tempo_decorrido': self._calcular_tempo_decorrido(contexto),
            'pontuacao_risco': contexto.pontuacao_risco,
            'ips_descobertos': contexto.ips_descobertos,
            'portas_abertas': contexto.portas_abertas,
            'servicos_detectados': contexto.servicos_detectados,
            'vulnerabilidades_encontradas': contexto.vulnerabilidades_encontradas,
            'modulos_executados': contexto.modulos_executados,
            'ultimos_resultados': {
                modulo: resultado
                for modulo, resultado in list(contexto.resultados_por_modulo.items())[-3:]
            }
        }

    def _gerar_prompt_contexto_completo_seguro(self, contexto_seguro: Dict[str, Any], contexto_original: ContextoExecucao) -> str:
        prompt = f"""
ALVO ORIGINAL: {contexto_seguro.get('alvo_original', '[ANONIMIZADO]')}
TEMPO DECORRIDO: {contexto_seguro.get('tempo_decorrido', 'N/A')}
PONTUAÇÃO DE RISCO ATUAL: {contexto_seguro.get('pontuacao_risco', 0)}/100

IPS DESCOBERTOS: {', '.join(contexto_seguro.get('ips_descobertos', []))}

PORTAS ABERTAS POR HOST:
"""
        for ip, portas in contexto_seguro.get('portas_abertas', {}).items():
            prompt += f"  {ip}: {', '.join(map(str, portas))}\n"

        servicos_detectados = contexto_seguro.get('servicos_detectados', {})
        prompt += f"\nSERVIÇOS DETECTADOS: {sum(len(s) for s in servicos_detectados.values())}\n"
        for ip, servicos in servicos_detectados.items():
            prompt += f"  {ip}: {len(servicos)} serviços\n"

        vulnerabilidades = contexto_seguro.get('vulnerabilidades_encontradas', [])
        prompt += f"\nVULNERABILIDADES ENCONTRADAS: {len(vulnerabilidades)}\n"
        if vulnerabilidades:
            for vuln in vulnerabilidades[-3:]:
                tipo = vuln.get('tipo', 'N/A')
                descricao = vuln.get('descricao', 'N/A')[:100]
                prompt += f"  - {tipo}: {descricao}...\n"

        prompt += f"\nRESUMO DOS ÚLTIMOS RESULTADOS:\n"
        for modulo in contexto_original.modulos_executados[-3:]:
            resultado = contexto_original.resultados_por_modulo.get(modulo, {})
            if resultado.get('sucesso_geral', resultado.get('sucesso', False)):
                prompt += f"  ✓ {modulo}: executado com sucesso\n"
            else:
                prompt += f"  ✗ {modulo}: falha na execução\n"

        aviso = contexto_seguro.get('_aviso_anonimizacao', {})
        prompt += f"\n📋 INFORMAÇÕES DE SEGURANÇA:\n"
        if aviso:
            prompt += f"  • {aviso.get('status', 'IPs anonimizados')}\n"
            prompt += f"  • {aviso.get('preservado', 'Estrutura mantida')}\n"
            prompt += f"  • Total anonimizado: {aviso.get('total_anonimizado', 0)}\n"

        return prompt

    def _listar_modulos_disponiveis(self) -> str:
        categorias = {
            'Varredura Web': [
                # 'feroxbuster_basico', 'feroxbuster_recursivo',  # REMOVIDOS
                # 'whatweb_scan',  # REMOVIDO
                'nuclei_scan', 'scraper_auth', 'navegador_web'
            ],
            'Navegação Web com IA': [
                'navegador_web_gemini'
            ],
            'Descoberta de Subdomínios': [
                # 'subfinder_enum', 'sublist3r_enum',  # REMOVIDOS
                'enumerador_subdominios_python'
            ],
            'Exploração': [
                'sqlmap_teste_url', 'sqlmap_teste_formulario',
                # 'searchsploit_check',  # REMOVIDO
                'buscador_exploits_python'
            ],
            'Scanner de Vulnerabilidades': ['scanner_vulnerabilidades', 'scanner_web_avancado'],
            'Testes de Vulnerabilidades Web': ['analisador_vulnerabilidades_web_python'],
            'Testes de Segurança de API': ['analisador_vulnerabilidades_web_python'],
            'Testes de Segurança Mobile/Web': ['analisador_vulnerabilidades_web_python'],
            'Novos Módulos Python Puro': [
                'scanner_portas_python', 'enumerador_subdominios_python',
                'detector_tecnologias_python', 'scanner_diretorios_python',
                'buscador_exploits_python', 'analisador_vulnerabilidades_web_python'
            ],
            'Nmap Especializado': [
                'nmap_varredura_completa', 'nmap_varredura_vulnerabilidades',
                'nmap_varredura_servicos_web', 'nmap_varredura_smb'
            ]
        }
        lista = ""
        for categoria, modulos in categorias.items():
            lista += f"\n{categoria}:\n"
            for modulo in modulos:
                if modulo in self.modulos_disponiveis:
                    lista += f"  - {modulo}\n"
        return lista

    def _mapear_categoria_para_modulo(self, nome_categoria: str) -> Optional[str]:
        nome_lower = nome_categoria.lower().strip()
        mapeamento_categorias = {
            'varredura web': 'scanner_diretorios_python',
            'varredura de web': 'scanner_diretorios_python',
            'web scanner': 'scanner_web_avancado',
            'scanner web': 'scanner_web_avancado',
            'web scan': 'scanner_diretorios_python',
            # 'feroxbuster': 'feroxbuster_basico',  # REMOVIDO
            # 'whatweb': 'whatweb_scan',  # REMOVIDO
            'nuclei': 'nuclei_scan',
            'scraper': 'scraper_auth',
            'scraping': 'scraper_auth',
            'web scraping': 'navegador_web',
            'selenium': 'navegador_web',
            'navegador': 'navegador_web',
            'browser': 'navegador_web',
            'navegador gemini': 'navegador_web_gemini',
            'web gemini': 'navegador_web_gemini',
            'analise web ia': 'navegador_web_gemini',
            'login automatico': 'navegador_web_gemini',
            'analise pagina protegida': 'navegador_web_gemini',
            'nmap': 'scanner_portas_python',
            'nmap completo': 'scanner_portas_python',
            'scan de vulnerabilidades': 'scanner_vulnerabilidades',
            'scanner de vulnerabilidades': 'scanner_vulnerabilidades',
            'sqlmap': 'sqlmap_teste_url',
            # 'subfinder': 'subfinder_enum',  # REMOVIDO
            # 'sublist3r': 'sublist3r_enum',  # REMOVIDO
            'enumerador subdominios': 'enumerador_subdominios_python',
            'subdomain enumerator': 'enumerador_subdominios_python',
            # 'searchsploit': 'searchsploit_check',  # REMOVIDO
            'exploit search': 'buscador_exploits_python',
            'teste vulnerabilidades web': 'analisador_vulnerabilidades_web_python',
            'teste xss': 'analisador_vulnerabilidades_web_python',
            'teste sql injection': 'analisador_vulnerabilidades_web_python',
            'teste lfi': 'analisador_vulnerabilidades_web_python',
            'teste command injection': 'analisador_vulnerabilidades_web_python',
            'teste csrf': 'analisador_vulnerabilidades_web_python',
            'teste open redirect': 'analisador_vulnerabilidades_web_python',
            'teste api': 'analisador_vulnerabilidades_web_python',
            'teste seguranca api': 'analisador_vulnerabilidades_web_python',
            'teste autenticacao api': 'analisador_vulnerabilidades_web_python',
            'teste injection api': 'analisador_vulnerabilidades_web_python',
            'teste idor': 'analisador_vulnerabilidades_web_python',
            'teste rate limiting': 'analisador_vulnerabilidades_web_python',
            'teste cors': 'analisador_vulnerabilidades_web_python',
            'teste graphql': 'analisador_vulnerabilidades_web_python',
            'teste mobile': 'analisador_vulnerabilidades_web_python',
            'teste pwa': 'analisador_vulnerabilidades_web_python',
            'teste ssl': 'analisador_vulnerabilidades_web_python',
            'teste certificado': 'analisador_vulnerabilidades_web_python',
            'teste service worker': 'analisador_vulnerabilidades_web_python',
            'teste manifest': 'analisador_vulnerabilidades_web_python',
            'scanner portas python': 'scanner_portas_python',
            'scanner portas puro': 'scanner_portas_python',
            'port scanner python': 'scanner_portas_python',
            'enumerador subdominios python': 'enumerador_subdominios_python',
            'enumerador subdominios puro': 'enumerador_subdominios_python',
            'subdomain enumerator python': 'enumerador_subdominios_python',
            'detector tecnologias python': 'detector_tecnologias_python',
            'detector tecnologias puro': 'detector_tecnologias_python',
            'technology detector python': 'detector_tecnologias_python',
            'scanner diretorios python': 'scanner_diretorios_python',
            'scanner diretorios puro': 'scanner_diretorios_python',
            'directory scanner python': 'scanner_diretorios_python',
            'buscador exploits python': 'buscador_exploits_python',
            'buscador exploits puro': 'buscador_exploits_python',
            'exploit search python': 'buscador_exploits_python',
            'analisador vulnerabilidades web python': 'analisador_vulnerabilidades_web_python',
            'analisador vulnerabilidades web puro': 'analisador_vulnerabilidades_web_python',
            'web vulnerability analyzer python': 'analisador_vulnerabilidades_web_python',
        }
        if nome_lower in mapeamento_categorias:
            modulo = mapeamento_categorias[nome_lower]
            if modulo in self.modulos_disponiveis:
                return modulo
        return None

    def _parsear_decisao_ia_loop(self, resposta_ia: str) -> Optional[Dict[str, Any]]:
        try:
            resposta_limpa = resposta_ia.strip()
            inicio_json = resposta_limpa.find('{')
            fim_json = resposta_limpa.rfind('}') + 1
            if inicio_json >= 0 and fim_json > inicio_json:
                decisao = json.loads(resposta_limpa[inicio_json:fim_json])
                if 'acao' in decisao and 'justificativa' in decisao:
                    return decisao
            return None
        except json.JSONDecodeError as e:
            self.logger.warning(f"Erro ao parsear JSON da IA: {str(e)}")
            return None

    def _executar_modulo(self, nome_modulo: str, contexto: ContextoExecucao, decisao_ia: Dict) -> Dict[str, Any]:
        self.logger.info(f"⚡ Executando módulo: {nome_modulo}")
        try:
            modulo = self.modulos_disponiveis[nome_modulo]
            alvos_ia = decisao_ia.get('alvos', [])
            parametros = decisao_ia.get('parametros', {})

            # Adicionar credenciais para módulos web se disponíveis
            if nome_modulo in ['navegador_web', 'navegador_web_gemini'] and 'credenciais' not in parametros and getattr(self, 'credenciais_web', None):
                parametros = {**parametros, 'credenciais': self.credenciais_web}

            alvos_reais = self._resolver_alvos_para_execucao(alvos_ia, contexto)
            resultados: Dict[str, Any] = {}

            for alvo in alvos_reais:
                try:
                    self.logger.info(f"   Executando {nome_modulo} em {alvo}")
                    if nome_modulo.startswith('nmap_'):
                        resultado = self._executar_modulo_nmap(nome_modulo, alvo, modulo, parametros)
                    elif nome_modulo.startswith('feroxbuster_'):
                        resultado = self._executar_modulo_feroxbuster(nome_modulo, alvo, modulo, parametros)
                    elif nome_modulo.startswith('sqlmap_'):
                        resultado = self._executar_modulo_sqlmap(nome_modulo, alvo, modulo, parametros)
                    elif nome_modulo.startswith('scanner_'):
                        resultado = self._executar_modulo_scanner(nome_modulo, alvo, modulo, parametros)
                    elif nome_modulo == 'navegador_web_gemini':
                        resultado = self._executar_modulo_navegador_web_gemini(alvo, modulo, parametros)
                    elif nome_modulo == 'scanner_portas_python':
                        resultado = self._executar_modulo_scanner_portas_python(alvo, modulo, parametros)
                    elif nome_modulo == 'enumerador_subdominios_python':
                        resultado = self._executar_modulo_enumerador_subdominios_python(alvo, modulo, parametros)
                    elif nome_modulo == 'detector_tecnologias_python':
                        resultado = self._executar_modulo_detector_tecnologias_python(alvo, modulo, parametros)
                    elif nome_modulo == 'scanner_diretorios_python':
                        resultado = self._executar_modulo_scanner_diretorios_python(alvo, modulo, parametros)
                    elif nome_modulo == 'buscador_exploits_python':
                        resultado = self._executar_modulo_buscador_exploits_python(alvo, modulo, parametros)
                    elif nome_modulo == 'analisador_vulnerabilidades_web_python':
                        resultado = self._executar_modulo_analisador_vulnerabilidades_web_python(alvo, modulo, parametros)
                    else:
                        resultado = self._executar_modulo_generico(nome_modulo, alvo, modulo, parametros)

                    resultados[alvo] = resultado
                    if resultado.get('sucesso'):
                        self.logger.info(f"  ✅ {nome_modulo} executado com sucesso em {alvo}")
                    else:
                        self.logger.warning(f"  ⚠️ Falha em {nome_modulo} para {alvo}: {resultado.get('erro')}")
                except Exception as e:
                    self.logger.error(f"Erro ao executar {nome_modulo} em {alvo}: {str(e)}")
                    resultados[alvo] = {'sucesso': False, 'erro': f'Erro na execução: {str(e)}', 'timestamp': datetime.now().isoformat()}

            return {
                'nome_modulo': nome_modulo,
                'resultados_por_alvo': resultados,
                'parametros_utilizados': parametros,
                'alvos_executados': alvos_reais,
                'alvos_ia_originais': alvos_ia,
                'timestamp': datetime.now().isoformat(),
                'sucesso_geral': any(r.get('sucesso', False) for r in resultados.values())
            }
        except Exception as e:
            self.logger.error(f"Erro crítico ao executar {nome_modulo}: {str(e)}")
            return {'nome_modulo': nome_modulo, 'sucesso_geral': False, 'erro': f'Erro crítico: {str(e)}', 'timestamp': datetime.now().isoformat()}

    def _resolver_alvos_para_execucao(self, alvos_ia: List[str], contexto: ContextoExecucao) -> List[str]:
        if not alvos_ia:
            return contexto.ips_descobertos
        alvos_reais: List[str] = []
        for alvo_ia in alvos_ia:
            if alvo_ia == "use_alvos_descobertos":
                alvos_reais.extend(contexto.ips_descobertos)
            elif alvo_ia.startswith("[") and alvo_ia.endswith("]"):
                self.logger.warning(f"Alvo anonimizado detectado: {alvo_ia}, usando todos os IPs descobertos")
                alvos_reais.extend(contexto.ips_descobertos)
            else:
                self.logger.info(f"Resolvendo alvo da IA: {alvo_ia} → usando IPs descobertos")
                alvos_reais.extend(contexto.ips_descobertos)
        alvos_unicos: List[str] = []
        for a in alvos_reais:
            if a not in alvos_unicos:
                alvos_unicos.append(a)
        if not alvos_unicos:
            alvos_unicos = contexto.ips_descobertos
        self.logger.info(f"🎯 Alvos resolvidos: {len(alvos_unicos)} IPs")
        return alvos_unicos

    def _executar_modulo_nmap(self, nome_modulo: str, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        mapa_metodos = {
            'nmap_varredura_basica': modulo.varredura_basica,
            'nmap_varredura_completa': modulo.varredura_completa,
            'nmap_varredura_vulnerabilidades': modulo.varredura_vulnerabilidades,
            'nmap_varredura_servicos_web': modulo.varredura_servicos_web,
            'nmap_varredura_smb': modulo.varredura_smb,
            'nmap_descoberta_rede': modulo.varredura_descoberta_rede,
        }
        metodo = mapa_metodos.get(nome_modulo)
        if metodo:
            return metodo(alvo, **parametros)
        return {'sucesso': False, 'erro': f'Método não encontrado para {nome_modulo}'}

    def _executar_modulo_feroxbuster(self, nome_modulo: str, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        url = f"http://{alvo}" if not alvo.startswith('http') else alvo
        if nome_modulo == 'feroxbuster_basico':
            return modulo.varredura_basica(url, **parametros)
        if nome_modulo == 'feroxbuster_recursivo':
            return modulo.varredura_recursiva(url, **parametros)
        return {'sucesso': False, 'erro': f'Método não encontrado para {nome_modulo}'}

    def _executar_modulo_sqlmap(self, nome_modulo: str, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        url = f"http://{alvo}" if not alvo.startswith('http') else alvo
        if nome_modulo == 'sqlmap_teste_url':
            return modulo.testar_url(url, **parametros)
        if nome_modulo == 'sqlmap_teste_formulario':
            return modulo.testar_formulario(url, **parametros)
        return {'sucesso': False, 'erro': f'Método não encontrado para {nome_modulo}'}

    def _executar_modulo_scanner(self, nome_modulo: str, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        try:
            if nome_modulo == 'scanner_vulnerabilidades':
                portas_abertas = parametros.get('portas_abertas', None)
                return modulo.scan_vulnerabilidades(alvo, portas_abertas)
            if nome_modulo == 'scanner_web_avancado':
                url = f"http://{alvo}" if not alvo.startswith('http') else alvo
                resultado_scanner = modulo.scan_completo(url)
                if 'erro' in resultado_scanner:
                    return {'sucesso': False, 'erro': resultado_scanner['erro'], 'timestamp': datetime.now().isoformat()}
                return {'sucesso': True, 'dados': resultado_scanner, 'timestamp': datetime.now().isoformat()}
            return {'sucesso': False, 'erro': f'Scanner não implementado: {nome_modulo}'}
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro no scanner: {str(e)}'}

    def _executar_modulo_generico(self, nome_modulo: str, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        try:
            if hasattr(modulo, 'executar'):
                return modulo.executar(alvo, **parametros)
            if hasattr(modulo, 'scan'):
                return modulo.scan(alvo, **parametros)
            if hasattr(modulo, 'varredura'):
                return modulo.varredura(alvo, **parametros)
            if hasattr(modulo, 'analise'):
                return modulo.analise(alvo, **parametros)
            return {'sucesso': False, 'erro': f'Método de execução não encontrado para {nome_modulo}'}
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro na execução genérica: {str(e)}'}

    def _executar_modulo_testador_vulnerabilidades_web(self, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        try:
            url = f"http://{alvo}" if not alvo.startswith('http') else alvo
            return modulo.executar_teste_completo(url)
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro no teste de vulnerabilidades web: {str(e)}'}

    def _executar_modulo_testador_seguranca_api(self, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        try:
            base_url = f"http://{alvo}" if not alvo.startswith('http') else alvo
            return modulo.executar_teste_completo_api(base_url)
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro no teste de segurança de API: {str(e)}'}

    def _executar_modulo_testador_seguranca_mobile_web(self, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        try:
            url = f"https://{alvo}" if not alvo.startswith('http') else alvo
            return modulo.executar_teste_completo_mobile_web(url)
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro no teste de segurança mobile/web: {str(e)}'}

    def _executar_modulo_navegador_web_gemini(self, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        """Executa módulo de navegação web com Gemini"""
        try:
            # Normalizar URL
            url = alvo
            if not alvo.startswith(('http://', 'https://')):
                url = f"http://{alvo}"
            
            # Extrair credenciais dos parâmetros
            credenciais = parametros.get('credenciais')
            modo = parametros.get('modo', 'web')
            
            # Executar análise completa com Gemini
            resultado = modulo.executar_para_orquestrador(
                alvo=url,
                credenciais=credenciais,
                modo=modo,
                **parametros
            )
            
            return resultado
            
        except Exception as e:
            self.logger.error(f"Erro no navegador web com Gemini: {e}")
            return {
                'sucesso': False,
                'erro': f'Erro no navegador web com Gemini: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }

    def _executar_modulo_scanner_portas_python(self, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        """Executa scanner de portas Python puro"""
        try:
            tipo_scan = parametros.get('tipo_scan', 'rapido')  # rapido, completo, ou personalizado
            portas_personalizadas = parametros.get('portas', None)

            if tipo_scan == 'rapido':
                resultado = modulo.scan_rapido(alvo)
            elif tipo_scan == 'completo':
                resultado = modulo.scan_completo(alvo)
            elif tipo_scan == 'personalizado' and portas_personalizadas:
                resultado = modulo.scan_personalizado(alvo, portas_personalizadas)
            else:
                resultado = modulo.scan_rapido(alvo)

            return {
                'sucesso': 'erro' not in resultado,
                'dados': resultado,
                'tipo_scan': tipo_scan,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro no scanner de portas: {str(e)}'}

    def _executar_modulo_enumerador_subdominios_python(self, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        """Executa enumerador de subdomínios Python puro"""
        try:
            wordlist_customizada = parametros.get('wordlist', None)
            verificar_ssl = parametros.get('verificar_ssl', True)
            timeout = parametros.get('timeout', 5)

            resultado = modulo.enumerar_subdominios(
                dominio=alvo,
                wordlist_customizada=wordlist_customizada,
                verificar_ssl=verificar_ssl,
                timeout=timeout
            )

            return {
                'sucesso': 'erro' not in resultado,
                'dados': resultado,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro no enumerador de subdomínios: {str(e)}'}

    def _executar_modulo_detector_tecnologias_python(self, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        """Executa detector de tecnologias Python puro"""
        try:
            url = f"https://{alvo}" if not alvo.startswith('http') else alvo
            modo_deteccao = parametros.get('modo', 'completo')  # completo, rapido, headers_only

            if modo_deteccao == 'completo':
                resultado = modulo.detectar_tecnologias_completo(url)
            elif modo_deteccao == 'rapido':
                resultado = modulo.detectar_tecnologias_rapido(url)
            elif modo_deteccao == 'headers_only':
                resultado = modulo.detectar_por_headers(url)
            else:
                resultado = modulo.detectar_tecnologias_completo(url)

            return {
                'sucesso': 'erro' not in resultado,
                'dados': resultado,
                'modo_deteccao': modo_deteccao,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro no detector de tecnologias: {str(e)}'}

    def _executar_modulo_scanner_diretorios_python(self, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        """Executa scanner de diretórios Python puro"""
        try:
            url = f"https://{alvo}" if not alvo.startswith('http') else alvo
            wordlist_customizada = parametros.get('wordlist', None)
            recursivo = parametros.get('recursivo', False)
            max_profundidade = parametros.get('max_profundidade', 2)
            testar_extensoes = parametros.get('testar_extensoes', True)

            resultado = modulo.scan_completo(
                url_base=url,
                wordlist_customizada=wordlist_customizada,
                testar_extensoes=testar_extensoes,
                recursivo=recursivo,
                max_profundidade=max_profundidade
            )

            return {
                'sucesso': 'erro' not in resultado,
                'dados': resultado,
                'recursivo': recursivo,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro no scanner de diretórios: {str(e)}'}

    def _executar_modulo_buscador_exploits_python(self, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        """Executa buscador de exploits Python puro"""
        try:
            termo_busca = parametros.get('termo_busca', alvo)
            fontes = parametros.get('fontes', ['exploit_db', 'packet_storm'])
            tipo = parametros.get('tipo', None)  # remote, local, dos, etc.
            plataforma = parametros.get('plataforma', None)  # windows, linux, etc.

            resultado = modulo.buscar_exploits(
                termo_busca=termo_busca,
                fontes=fontes,
                tipo=tipo,
                plataforma=plataforma
            )

            return {
                'sucesso': 'erro' not in resultado,
                'dados': resultado,
                'termo_busca': termo_busca,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro no buscador de exploits: {str(e)}'}

    def _executar_modulo_analisador_vulnerabilidades_web_python(self, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        """Executa analisador de vulnerabilidades web Python puro"""
        try:
            url = f"https://{alvo}" if not alvo.startswith('http') else alvo
            testes_completos = parametros.get('testes_completos', True)
            testar_payloads = parametros.get('testar_payloads', True)

            resultado = modulo.analisar_url(
                url=url,
                testes_completos=testes_completos,
                testar_payloads=testar_payloads
            )

            return {
                'sucesso': 'erro' not in resultado,
                'dados': resultado,
                'testes_completos': testes_completos,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro no analisador de vulnerabilidades web: {str(e)}'}

    def _calcular_pontuacao_risco(self, contexto: ContextoExecucao) -> int:
        """
        Calcula a pontuação de risco baseada nos dados do contexto de execução.
        Retorna um valor de 0-100 representando o nível de risco identificado.
        """
        try:
            pontuacao = 0

            # Fator 1: Vulnerabilidades encontradas (peso alto - 40 pontos max)
            num_vulnerabilidades = len(contexto.vulnerabilidades_encontradas)
            if num_vulnerabilidades > 0:
                # Cada vulnerabilidade crítica adiciona 20 pontos, média 10, baixa 5
                for vuln in contexto.vulnerabilidades_encontradas:
                    severidade = vuln.get('severidade', 'media').lower()
                    if severidade == 'critica' or severidade == 'alta':
                        pontuacao += 20
                    elif severidade == 'media':
                        pontuacao += 10
                    else:
                        pontuacao += 5
                # Limitar a 40 pontos para vulnerabilidades
                pontuacao = min(pontuacao, 40)

            # Fator 2: Portas abertas (peso médio - 25 pontos max)
            total_portas_abertas = sum(len(portas) for portas in contexto.portas_abertas.values())
            if total_portas_abertas > 0:
                # Portas perigosas têm peso maior
                portas_perigosas = 0
                for ip, portas in contexto.portas_abertas.items():
                    for porta in portas:
                        if porta in [21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 993, 995, 3389]:
                            portas_perigosas += 1

                # Cada porta perigosa = 5 pontos, outras = 2 pontos
                pontuacao += (portas_perigosas * 5) + ((total_portas_abertas - portas_perigosas) * 2)
                # Limitar a 25 pontos para portas
                pontuacao = min(pontuacao, 65)  # 40 (vulns) + 25 (portas)

            # Fator 3: Serviços detectados (peso médio - 20 pontos max)
            total_servicos = sum(len(servicos) for servicos in contexto.servicos_detectados.values())
            if total_servicos > 0:
                # Serviços web têm peso maior
                servicos_web = 0
                for ip, servicos in contexto.servicos_detectados.items():
                    for servico in servicos:
                        nome_servico = servico.get('nome', '').lower()
                        if any(web in nome_servico for web in ['http', 'apache', 'nginx', 'iis', 'tomcat']):
                            servicos_web += 1

                # Cada serviço web = 4 pontos, outros = 2 pontos
                pontuacao += (servicos_web * 4) + ((total_servicos - servicos_web) * 2)
                # Limitar a 20 pontos para serviços
                pontuacao = min(pontuacao, 85)  # 40 + 25 + 20

            # Fator 4: IPs descobertos (peso baixo - 10 pontos max)
            num_ips = len(contexto.ips_descobertos)
            if num_ips > 1:
                # Múltiplos IPs podem indicar rede maior = mais risco
                pontuacao += min(num_ips * 2, 10)
                pontuacao = min(pontuacao, 95)  # 40 + 25 + 20 + 10

            # Fator 5: Módulos executados (peso baixo - 5 pontos max)
            # Mais módulos executados = análise mais completa = potencialmente mais descobertas
            num_modulos = len(contexto.modulos_executados)
            if num_modulos > 5:
                pontuacao += min((num_modulos - 5), 5)
                pontuacao = min(pontuacao, 100)  # Máximo absoluto

            # Garantir que a pontuação esteja entre 0 e 100
            return max(0, min(100, pontuacao))

        except Exception as e:
            self.logger.warning(f"Erro ao calcular pontuação de risco: {str(e)}")
            # Em caso de erro, retorna pontuação baseada apenas no número de vulnerabilidades
            return min(len(contexto.vulnerabilidades_encontradas) * 10, 100)

    def _calcular_tempo_decorrido(self, contexto: ContextoExecucao) -> str:
        """
        Calcula o tempo decorrido desde o início da execução.
        Retorna uma string formatada com o tempo.
        """
        try:
            inicio = datetime.fromisoformat(contexto.timestamp_inicio)
            delta = datetime.now() - inicio
            minutos = int(delta.total_seconds() / 60)
            if minutos < 60:
                return f"{minutos} minutos"
            horas = minutos // 60
            min_rest = minutos % 60
            return f"{horas}h{min_rest}m"
        except Exception:
            return "N/A"

    def _finalizar_pentest(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        timestamp_fim = datetime.now().isoformat()
        resumo_final = {
            'alvo_original': contexto.alvo_original,
            'timestamp_inicio': contexto.timestamp_inicio,
            'timestamp_fim': timestamp_fim,
            'tempo_total': self._calcular_tempo_decorrido(contexto),
            'sucesso_geral': any(
                r.get('sucesso', False)
                for r in contexto.resultados_por_modulo.values()
                if isinstance(r, dict)
            ),
            'estatisticas': {
                'ips_descobertos': len(contexto.ips_descobertos),
                'total_portas_abertas': sum(len(p) for p in contexto.portas_abertas.values()),
                'servicos_detectados': sum(len(s) for s in contexto.servicos_detectados.values()),
                'vulnerabilidades_encontradas': len(contexto.vulnerabilidades_encontradas),
                'modulos_executados': len(contexto.modulos_executados),
                'pontuacao_risco_final': contexto.pontuacao_risco
            },
            'contexto_execucao': {
                'ips_descobertos': contexto.ips_descobertos,
                'portas_abertas': contexto.portas_abertas,
                'servicos_detectados': contexto.servicos_detectados,
                'vulnerabilidades_encontradas': contexto.vulnerabilidades_encontradas,
                'modulos_executados': contexto.modulos_executados,
                'motivo_finalizacao': contexto.motivo_finalizacao
            },
            'resultados_por_modulo': contexto.resultados_por_modulo,
            'decisoes_ia': contexto.decisoes_ia
        }

        # Log da sessão
        try:
            log_manager.log_sessao_pentest('pentest_inteligente', {
                'alvo': contexto.alvo_original,
                'ips_descobertos': len(contexto.ips_descobertos),
                'modulos_executados': len(contexto.modulos_executados),
                'vulnerabilidades': len(contexto.vulnerabilidades_encontradas),
                'pontuacao_risco': contexto.pontuacao_risco,
                'tempo_total_min': int((datetime.fromisoformat(timestamp_fim) - datetime.fromisoformat(contexto.timestamp_inicio)).total_seconds() / 60)
            })
        except Exception as e:
            self.logger.warning(f"Erro ao registrar sessão: {e}")

        self.logger.info(" Estatísticas finais:")
        self.logger.info(f"  • IPs: {resumo_final['estatisticas']['ips_descobertos']}")
        self.logger.info(f"  • Portas: {resumo_final['estatisticas']['total_portas_abertas']}")
        self.logger.info(f"  • Serviços: {resumo_final['estatisticas']['servicos_detectados']}")
        self.logger.info(f"  • Vulnerabilidades: {resumo_final['estatisticas']['vulnerabilidades_encontradas']}")
        self.logger.info(f"  • Módulos: {resumo_final['estatisticas']['modulos_executados']}")
        self.logger.info(f"  • Risco: {resumo_final['estatisticas']['pontuacao_risco_final']}/100")
        return resumo_final

    def _finalizar_com_erro(self, contexto: ContextoExecucao, erro: str) -> Dict[str, Any]:
        return {
            'alvo_original': contexto.alvo_original,
            'timestamp_inicio': contexto.timestamp_inicio,
            'timestamp_fim': datetime.now().isoformat(),
            'sucesso_geral': False,
            'erro': erro,
            'contexto_parcial': {
                'modulos_executados': contexto.modulos_executados,
                'resultados_parciais': contexto.resultados_por_modulo
            }
        }


if __name__ == "__main__":
    # Teste básico do orquestrador
    from utils.logger import obter_logger as _get_logger

    logger = _get_logger('OrquestradorInteligenteCLI')
    logger.info("🧪 Teste do Orquestrador Inteligente")

    class MockModulo:
        def resolver_dns(self, alvo):
            return {'sucesso': True, 'dados': {'ips_resolvidos': ['192.168.1.100']}}

        def varredura_completa(self, ip):
            return {'sucesso': True, 'dados': {'portas_abertas': [22, 80, 443]}}

        def varredura_basica(self, ip):
            return {'sucesso': True, 'dados': {'portas': [{'numero': 80, 'estado': 'open'}]}}

    mock = MockModulo()
    try:
        from modulos.decisao_ia import DecisaoIA
        decisao_ia = DecisaoIA()
        if decisao_ia.conectar_gemini():
            logger.info("✓ Gemini conectado para teste")
        else:
            logger.error(" Gemini não disponível - sistema requer IA")
            exit(1)
    except Exception as e:
        logger.error(f" Erro ao conectar Gemini - sistema requer IA: {e}")
        exit(1)

    orq = OrquestradorInteligente(
        resolver_dns=mock,
        scanner_portas=mock,
        scanner_nmap=mock,
        decisao_ia=decisao_ia
    )
    logger.info("✓ Orquestrador Inteligente inicializado com sucesso!")
    logger.info(" Pronto para execução com loop adaptativo!")
