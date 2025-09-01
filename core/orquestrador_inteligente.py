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
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import obter_logger, log_manager
from utils.rede import extrair_ips_para_scan
from utils.anonimizador_ip import criar_contexto_seguro_para_ia

# Novo: Agente IA Central (Fase 1)
from core.agente_ia_central import AgenteIACentral


@dataclass
class Evento:
    """Representa um evento no sistema"""
    tipo: str
    dados: Dict[str, Any]
    timestamp: str
    prioridade: str = "media"  # alta, media, baixa
    fonte: str = "sistema"


class EventManager:
    """Gerenciador de eventos para sistema orientado a eventos (Fase 3)"""
    
    def __init__(self, logger_func=None):
        if logger_func:
            self.logger = logger_func('EventManager')
        else:
            self.logger = print
        self.eventos: List[Evento] = []
        self.listeners: Dict[str, List[Callable]] = {}
        self.eventos_ativos: Dict[str, bool] = {}
        self.lock = threading.Lock()
        
    def registrar_listener(self, tipo_evento: str, callback: Callable):
        """Registra um listener para um tipo de evento"""
        with self.lock:
            if tipo_evento not in self.listeners:
                self.listeners[tipo_evento] = []
            self.listeners[tipo_evento].append(callback)
            if hasattr(self.logger, 'info'):
                self.logger.info(f"✅ Listener registrado para evento: {tipo_evento}")
            else:
                print(f"✅ Listener registrado para evento: {tipo_evento}")
    
    def disparar_evento(self, evento: Evento):
        """Dispara um evento e notifica todos os listeners"""
        with self.lock:
            self.eventos.append(evento)
            if hasattr(self.logger, 'info'):
                self.logger.info(f"🔥 Evento disparado: {evento.tipo} (prioridade: {evento.prioridade})")
            else:
                print(f"🔥 Evento disparado: {evento.tipo} (prioridade: {evento.prioridade})")
            
            # Notificar listeners
            if evento.tipo in self.listeners:
                for callback in self.listeners[evento.tipo]:
                    try:
                        threading.Thread(target=callback, args=(evento,), daemon=True).start()
                    except Exception as e:
                        if hasattr(self.logger, 'error'):
                            self.logger.error(f"❌ Erro ao executar listener para {evento.tipo}: {e}")
                        else:
                            print(f"❌ Erro ao executar listener para {evento.tipo}: {e}")
    
    def obter_eventos_recentes(self, limite: int = 10) -> List[Evento]:
        """Retorna os eventos mais recentes"""
        with self.lock:
            return self.eventos[-limite:]
    
    def limpar_eventos_antigos(self, max_eventos: int = 100):
        """Limpa eventos antigos para evitar uso excessivo de memória"""
        with self.lock:
            if len(self.eventos) > max_eventos:
                self.eventos = self.eventos[-max_eventos:]


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
    # Novo: Sistema de eventos (Fase 3)
    eventos: List[Evento] = field(default_factory=list)


class OrquestradorInteligente:
    """Orquestrador com loop inteligente baseado em IA"""

    def __init__(self, resolver_dns, scanner_portas, scanner_nmap, decisao_ia, logger_func=obter_logger):
        self.logger = logger_func('OrquestradorInteligente')
        self.resolver_dns = resolver_dns
        self.scanner_portas = scanner_portas
        self.scanner_nmap = scanner_nmap
        self.decisao_ia = decisao_ia

        # Novo: Sistema de eventos (Fase 3)
        self.event_manager = EventManager(logger_func)
        self._registrar_listeners_eventos()

        # Novo: Executor para paralelização (Fase 3)
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="scanner")
        self.logger.info("✅ Executor de threads inicializado para paralelização")

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

    def _registrar_listeners_eventos(self):
        """Registra listeners para eventos do sistema (Fase 3)"""
        # Evento: Detecção de anomalia
        self.event_manager.registrar_listener("anomalia_detectada", self._handle_anomalia_detectada)
        
        # Evento: Vulnerabilidade crítica encontrada
        self.event_manager.registrar_listener("vulnerabilidade_critica", self._handle_vulnerabilidade_critica)
        
        # Evento: Novo host descoberto
        self.event_manager.registrar_listener("novo_host_descoberto", self._handle_novo_host)
        
        # Evento: Serviço web detectado
        self.event_manager.registrar_listener("servico_web_detectado", self._handle_servico_web)
        
        # Evento: Feedback do ML
        self.event_manager.registrar_listener("feedback_ml", self._handle_feedback_ml)
        
        self.logger.info("✅ Listeners de eventos registrados")

    def _handle_anomalia_detectada(self, evento: Evento):
        """Handler para evento de anomalia detectada (Fase 3)"""
        self.logger.warning(f"🚨 Anomalia detectada: {evento.dados}")
        
        # Disparar varredura adicional automaticamente
        anomalia = evento.dados.get('anomalia', {})
        if anomalia.get('tipo') == 'tráfego_suspeito':
            # Executar scanner de vulnerabilidades
            threading.Thread(
                target=self._executar_modulo_emergencial,
                args=("scanner_vulnerabilidades", evento.dados),
                daemon=True
            ).start()
        elif anomalia.get('tipo') == 'porta_suspeita':
            # Executar nmap detalhado
            threading.Thread(
                target=self._executar_modulo_emergencial,
                args=("nmap_varredura_vulnerabilidades", evento.dados),
                daemon=True
            ).start()

    def _handle_vulnerabilidade_critica(self, evento: Evento):
        """Handler para vulnerabilidade crítica (Fase 3)"""
        self.logger.error(f"🔴 Vulnerabilidade crítica encontrada: {evento.dados}")
        
        # Aumentar prioridade de scans relacionados
        vuln = evento.dados.get('vulnerabilidade', {})
        if 'sql' in vuln.get('tipo', '').lower():
            threading.Thread(
                target=self._executar_modulo_emergencial,
                args=("sqlmap_teste_url", evento.dados),
                daemon=True
            ).start()

    def _handle_novo_host(self, evento: Evento):
        """Handler para novo host descoberto (Fase 3)"""
        self.logger.info(f"🆕 Novo host descoberto: {evento.dados}")
        
        # Executar scan de portas no novo host
        threading.Thread(
            target=self._executar_modulo_emergencial,
            args=("scanner_portas_python", evento.dados),
            daemon=True
        ).start()

    def _handle_servico_web(self, evento: Evento):
        """Handler para serviço web detectado (Fase 3)"""
        self.logger.info(f"🌐 Serviço web detectado: {evento.dados}")
        
        # Executar análise web
        threading.Thread(
            target=self._executar_modulo_emergencial,
            args=("scanner_web_avancado", evento.dados),
            daemon=True
        ).start()

    def _handle_feedback_ml(self, evento: Evento):
        """Handler para feedback do sistema ML (Fase 3)"""
        self.logger.info(f"🧠 Feedback ML recebido: {evento.dados}")
        
        # Ajustar comportamento baseado no feedback
        feedback = evento.dados.get('feedback', {})
        if feedback.get('tipo') == 'sucesso_modulo':
            # Aumentar prioridade do módulo bem-sucedido
            self.logger.info(f"📈 Módulo {feedback.get('modulo')} teve sucesso - prioridade aumentada")
        elif feedback.get('tipo') == 'falha_modulo':
            # Reduzir uso do módulo com falha
            self.logger.warning(f"📉 Módulo {feedback.get('modulo')} falhou - uso reduzido")

    def _executar_modulo_emergencial(self, nome_modulo: str, dados_contexto: Dict[str, Any]):
        """Executa módulo de forma emergencial em thread separada (Fase 3)"""
        try:
            self.logger.info(f"🚀 Executando módulo emergencial: {nome_modulo}")
            
            if nome_modulo not in self.modulos_disponiveis:
                self.logger.warning(f"Módulo {nome_modulo} não disponível para execução emergencial")
                return
            
            modulo = self.modulos_disponiveis[nome_modulo]
            
            # Preparar parâmetros baseados nos dados do evento
            parametros = self._preparar_parametros_emergenciais(nome_modulo, dados_contexto)
            
            # Executar módulo
            resultado = modulo.executar(**parametros)
            
            # Log do resultado
            if resultado.get('sucesso'):
                self.logger.info(f"✅ Módulo emergencial {nome_modulo} executado com sucesso")
            else:
                self.logger.warning(f"⚠️ Módulo emergencial {nome_modulo} falhou: {resultado.get('erro')}")
                
        except Exception as e:
            self.logger.error(f"❌ Erro na execução emergencial de {nome_modulo}: {e}")

    def _preparar_parametros_emergenciais(self, nome_modulo: str, dados: Dict[str, Any]) -> Dict[str, Any]:
        """Prepara parâmetros para execução emergencial baseada no tipo de módulo"""
        base_params = {'logger': self.logger}
        
        if 'scanner_portas' in nome_modulo:
            return {**base_params, 'alvos': dados.get('hosts', [])}
        elif 'nmap' in nome_modulo:
            return {**base_params, 'alvos': dados.get('hosts', []), 'tipo_scan': 'vulnerabilidades'}
        elif 'scanner_vulnerabilidades' in nome_modulo:
            return {**base_params, 'alvos': dados.get('hosts', [])}
        elif 'sqlmap' in nome_modulo:
            return {**base_params, 'url': dados.get('url', ''), 'formulario': dados.get('formulario')}
        elif 'scanner_web' in nome_modulo:
            return {**base_params, 'url': dados.get('url', '')}
        
        return base_params

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
        # Verificar se resultado é um dicionário válido
        if not isinstance(resultado, dict):
            self.logger.warning(f"Resultado do módulo {nome_modulo} não é um dicionário válido: {type(resultado)}")
            resultado = {
                'sucesso': False,
                'erro': f'Formato de resultado inválido: {type(resultado)}',
                'timestamp': datetime.now().isoformat()
            }
        
        # Verificar e garantir estruturas internas corretas
        if 'resultados_por_alvo' in resultado and not isinstance(resultado['resultados_por_alvo'], dict):
            self.logger.warning(f"resultados_por_alvo para {nome_modulo} não é um dicionário: {type(resultado['resultados_por_alvo'])}")
            resultado['resultados_por_alvo'] = {}
            
        # Garantir que o resultado contém os campos básicos necessários
        if 'timestamp' not in resultado:
            resultado['timestamp'] = datetime.now().isoformat()
            
        if 'sucesso' not in resultado and 'sucesso_geral' not in resultado:
            resultado['sucesso'] = False
            resultado['erro'] = 'Status de sucesso não informado pelo módulo'
        
        # Processar e normalizar eventuais dados críticos
        # Detector de tecnologias
        if nome_modulo == 'detector_tecnologias_python' and 'dados' in resultado:
            # Garantir que o campo 'tecnologias' existe e é um dicionário
            dados = resultado.get('dados', {})
            if 'tecnologias' in dados and not isinstance(dados['tecnologias'], dict):
                self.logger.warning(f"Campo tecnologias em detector_tecnologias_python não é um dicionário: {type(dados['tecnologias'])}")
                dados['tecnologias'] = {}
                
        contexto.resultados_por_modulo[nome_modulo] = resultado
        contexto.modulos_executados.append(nome_modulo)
        self.logger.debug(f"Resultado do módulo '{nome_modulo}' adicionado ao contexto")

        # Novo: Disparar eventos baseados no resultado (Fase 3)
        self._disparar_eventos_baseados_resultado(contexto, nome_modulo, resultado)

        # Novo: Notificar Agente IA Central (Fase 1)
        if self.agente_ia_central:
            try:
                # Passar informações completas para atualização do estado
                resultado_completo = {
                    'modulo': nome_modulo,
                    'sucesso': resultado.get('sucesso_geral', resultado.get('sucesso', False)),
                    'vulnerabilidades': resultado.get('vulnerabilidades_encontradas', []),
                    'tempo_execucao': resultado.get('tempo_execucao', 0),
                    'resultado': resultado
                }
                self.agente_ia_central.atualizar_estado(resultado_completo)
                self.logger.debug(f"Estado do Agente IA Central atualizado com resultado de {nome_modulo}")
            except Exception as e:
                self.logger.warning(f"Erro ao atualizar Agente IA Central: {e}")

    def _disparar_eventos_baseados_resultado(self, contexto: ContextoExecucao, nome_modulo: str, resultado: Dict[str, Any]):
        """Dispara eventos baseados no resultado do módulo (Fase 3)"""
        try:
            # Proteção contra tipos inválidos de resultado
            if not isinstance(resultado, dict):
                self.logger.warning(f"Resultado de {nome_modulo} não é um dicionário: {type(resultado)}")
                return

            # Evento: Novos hosts descobertos
            if 'ips_descobertos' in resultado:
                try:
                    novos_ips = resultado['ips_descobertos']
                    # Verificar se é uma lista
                    if not isinstance(novos_ips, list):
                        self.logger.warning(f"ips_descobertos em {nome_modulo} não é uma lista: {type(novos_ips)}")
                        if novos_ips is not None:
                            # Tentar converter para lista se possível
                            if isinstance(novos_ips, str):
                                novos_ips = [novos_ips]
                            else:
                                novos_ips = []
                        else:
                            novos_ips = []
                            
                    # Verificar se contexto.ips_descobertos é uma lista
                    if not isinstance(contexto.ips_descobertos, list):
                        self.logger.warning(f"contexto.ips_descobertos não é uma lista: {type(contexto.ips_descobertos)}")
                        contexto.ips_descobertos = []
                            
                    # Agora é seguro iterar
                    if novos_ips:
                        for ip in novos_ips:
                            if ip and ip not in contexto.ips_descobertos:
                                contexto.ips_descobertos.append(ip)
                                evento = Evento(
                                    tipo="novo_host_descoberto",
                                    dados={'host': ip, 'fonte': nome_modulo},
                                    timestamp=datetime.now().isoformat(),
                                    prioridade="alta"
                                )
                                contexto.eventos.append(evento)
                                self.event_manager.disparar_evento(evento)
                except Exception as e:
                    self.logger.warning(f"Erro ao processar ips_descobertos em {nome_modulo}: {e}")

            # Evento: Portas abertas descobertas
            if 'portas_abertas' in resultado:
                try:
                    portas_novas = resultado['portas_abertas']
                    
                    # Verificar se é um dicionário
                    if not isinstance(portas_novas, dict):
                        self.logger.warning(f"portas_abertas em {nome_modulo} não é um dicionário: {type(portas_novas)}")
                        # Tentar converter formatos conhecidos
                        if isinstance(portas_novas, list) and all(isinstance(p, int) for p in portas_novas):
                            # Lista de portas associada ao primeiro IP conhecido
                            if contexto.ips_descobertos and len(contexto.ips_descobertos) > 0:
                                portas_novas = {contexto.ips_descobertos[0]: portas_novas}
                            else:
                                portas_novas = {}
                        else:
                            portas_novas = {}
                    
                    # Verificar se contexto.portas_abertas é um dicionário
                    if not isinstance(contexto.portas_abertas, dict):
                        self.logger.warning(f"contexto.portas_abertas não é um dicionário: {type(contexto.portas_abertas)}")
                        contexto.portas_abertas = {}
                            
                    # Agora é seguro iterar
                    for ip, portas in portas_novas.items():
                        if ip not in contexto.portas_abertas:
                            # Garantir que portas é uma lista de inteiros
                            if isinstance(portas, list):
                                # Filtrar somente inteiros
                                contexto.portas_abertas[ip] = [p for p in portas if isinstance(p, int)]
                            elif isinstance(portas, int):
                                # Único valor
                                contexto.portas_abertas[ip] = [portas]
                            else:
                                # Valor inválido
                                contexto.portas_abertas[ip] = []
                                self.logger.warning(f"Valor de portas para {ip} não é lista nem inteiro: {type(portas)}")
                        else:
                            # Garantir que o que temos é uma lista
                            if not isinstance(contexto.portas_abertas[ip], list):
                                self.logger.warning(f"contexto.portas_abertas[{ip}] não é uma lista: {type(contexto.portas_abertas[ip])}")
                                contexto.portas_abertas[ip] = []
                            
                            # Garantir que portas é uma lista
                            if not isinstance(portas, list):
                                if isinstance(portas, int):
                                    portas = [portas]
                                else:
                                    self.logger.warning(f"portas para {ip} não é lista nem inteiro: {type(portas)}")
                                    portas = []
                            
                            # Adicionar portas novas com verificação de tipos
                            portas_existentes = set()
                            for p in contexto.portas_abertas[ip]:
                                if isinstance(p, int):
                                    portas_existentes.add(p)
                                    
                            portas_novas_set = set()
                            for p in portas:
                                if isinstance(p, int):
                                    portas_novas_set.add(p)
                                    
                            portas_adicionadas = portas_novas_set - portas_existentes
                            if portas_adicionadas:
                                contexto.portas_abertas[ip].extend(list(portas_adicionadas))
                                
                                # Verificar portas suspeitas (ex: 3389, 445, etc.)
                                portas_suspeitas = [p for p in portas_adicionadas if p in [3389, 445, 135, 139, 1433, 3306]]
                                if portas_suspeitas:
                                    evento = Evento(
                                        tipo="anomalia_detectada",
                                        dados={
                                            'tipo': 'porta_suspeita',
                                            'host': ip,
                                            'portas': list(portas_suspeitas),
                                            'fonte': nome_modulo
                                        },
                                        timestamp=datetime.now().isoformat(),
                                        prioridade="alta"
                                    )
                                    contexto.eventos.append(evento)
                                    self.event_manager.disparar_evento(evento)
                except Exception as e:
                    self.logger.warning(f"Erro ao processar portas_abertas em {nome_modulo}: {e}")
                    import traceback
                    self.logger.warning(f"Traceback: {traceback.format_exc()}")

            # Evento: Serviços web detectados - com verificação ultra-ultra-robusta
            if 'servicos_detectados' in resultado:
                try:
                    servicos = resultado['servicos_detectados']
                    
                    # Verificar se contexto.servicos_detectados é um dicionário
                    if not isinstance(contexto.servicos_detectados, dict):
                        self.logger.warning(f"contexto.servicos_detectados não é um dicionário: {type(contexto.servicos_detectados)}")
                        contexto.servicos_detectados = {}
                    
                    # VERIFICAÇÃO INICIAL: Verificação extrema do tipo dos dados recebidos
                    # Adicionar log detalhado para debug
                    self.logger.debug(f"servicos_detectados em {nome_modulo} é de tipo {type(servicos).__name__}")
                    
                    # Casos específicos para diferentes tipos de dados
                    if servicos is None:
                        # Caso 1: None
                        self.logger.warning(f"servicos_detectados em {nome_modulo} é None - ignorando")
                        # Nada a adicionar neste caso
                    
                    elif isinstance(servicos, int):
                        # Caso 2: Inteiro (causa original do erro)
                        self.logger.warning(f"servicos_detectados em {nome_modulo} é um inteiro: {servicos}")
                        # Criar uma entrada de contagem associada ao nome do módulo
                        chave_temp = f"contador_{nome_modulo}"
                        contexto.servicos_detectados[chave_temp] = {"count": servicos}
                        # Não há serviços web para processar aqui
                    
                    elif isinstance(servicos, str):
                        # Caso 3: String
                        self.logger.warning(f"servicos_detectados em {nome_modulo} é uma string")
                        chave_temp = f"info_{nome_modulo}"
                        contexto.servicos_detectados[chave_temp] = {"info": servicos}
                        # Verificar se a string contém informações sobre web
                        if any(web in servicos.lower() for web in ['http', 'https', 'web']):
                            evento = Evento(
                                tipo="servico_web_detectado",
                                dados={
                                    'host': chave_temp,
                                    'servico': "possível serviço web (string)",
                                    'fonte': nome_modulo
                                },
                                timestamp=datetime.now().isoformat(),
                                prioridade="baixa"
                            )
                            contexto.eventos.append(evento)
                            self.event_manager.disparar_evento(evento)
                    
                    elif isinstance(servicos, list):
                        # Caso 4: Lista
                        self.logger.warning(f"servicos_detectados em {nome_modulo} é uma lista - convertendo")
                        # Processar cada item da lista de forma segura
                        for i, item in enumerate(servicos):
                            if item is not None:
                                # Gerar chave temporária baseada no índice
                                chave_temp = f"item_{i}"
                                
                                # Usar o host como chave se disponível
                                if isinstance(item, dict) and 'host' in item:
                                    chave_temp = item['host']
                                
                                # Adicionar ao contexto
                                contexto.servicos_detectados[chave_temp] = item
                                
                                # Verificar se contém serviço web
                                if isinstance(item, dict):
                                    for k, v in item.items():
                                        if isinstance(v, str) and any(web in v.lower() for web in ['http', 'https', 'web']):
                                            evento = Evento(
                                                tipo="servico_web_detectado",
                                                dados={
                                                    'host': chave_temp,
                                                    'servico': v,
                                                    'fonte': nome_modulo
                                                },
                                                timestamp=datetime.now().isoformat(),
                                                prioridade="media"
                                            )
                                            contexto.eventos.append(evento)
                                            self.event_manager.disparar_evento(evento)
                                            break
                    
                    elif isinstance(servicos, dict):
                        # Caso 5: Dicionário (caso ideal)
                        self.logger.debug(f"servicos_detectados em {nome_modulo} é um dicionário com {len(servicos) if hasattr(servicos, '__len__') else 'valor não iterável'} chaves")
                        # Iterar com segurança
                        for ip, servicos_ip in servicos.items():
                            if ip not in contexto.servicos_detectados:
                                # CRIAÇÃO: Validações ultra-robustas para diferentes tipos de dados
                                if isinstance(servicos_ip, dict):
                                    # Cópia segura
                                    try:
                                        contexto.servicos_detectados[ip] = servicos_ip.copy()
                                    except (AttributeError, TypeError):
                                        # Se copy falhar, criar novo dict e copiar chave por chave
                                        contexto.servicos_detectados[ip] = {}
                                        for k, v in servicos_ip.items():
                                            contexto.servicos_detectados[ip][k] = v
                                elif isinstance(servicos_ip, list):
                                    # Converter lista para dicionário com segurança
                                    contexto.servicos_detectados[ip] = {}
                                    for i, item in enumerate(servicos_ip):
                                        if item is not None:
                                            contexto.servicos_detectados[ip][f"item_{i}"] = item
                                elif isinstance(servicos_ip, int):
                                    # Número direto = contagem
                                    contexto.servicos_detectados[ip] = {"count": servicos_ip}
                                elif servicos_ip is None:
                                    # Tratar None de forma explícita
                                    contexto.servicos_detectados[ip] = {"valor": "nenhum"}
                                else:
                                    # Qualquer outro tipo, converter para string
                                    try:
                                        valor_str = str(servicos_ip)
                                    except:
                                        valor_str = "Erro ao converter para string"
                                    contexto.servicos_detectados[ip] = {"valor": valor_str}
                            else:
                                # ATUALIZAÇÃO: Verificar se o dicionário atual é válido
                                if not isinstance(contexto.servicos_detectados[ip], dict):
                                    # Se não for dicionário, substituir com novo
                                    try:
                                        valor_antigo_str = str(contexto.servicos_detectados[ip])
                                    except:
                                        valor_antigo_str = "Erro ao converter valor antigo"
                                    contexto.servicos_detectados[ip] = {"valor_antigo": valor_antigo_str}
                                
                                # Agora atualizar conforme o tipo dos novos serviços com muita segurança
                                if isinstance(servicos_ip, dict):
                                    # Mesclar dicionários um item por vez
                                    for k, v in servicos_ip.items():
                                        contexto.servicos_detectados[ip][k] = v
                                elif isinstance(servicos_ip, list):
                                    # Converter lista para dicionário e mesclar item por item
                                    for i, item in enumerate(servicos_ip):
                                        if item is not None:
                                            contexto.servicos_detectados[ip][f"lista_item_{i}"] = item
                                elif isinstance(servicos_ip, int):
                                    # Adicionar como contador
                                    contexto.servicos_detectados[ip]["count"] = servicos_ip
                                elif servicos_ip is None:
                                    # Tratar None de forma explícita
                                    contexto.servicos_detectados[ip]["valor"] = "nenhum"
                                else:
                                    # Qualquer outro tipo, converter para string com proteção
                                    try:
                                        valor_str = str(servicos_ip)
                                    except:
                                        valor_str = "Erro ao converter para string"
                                    contexto.servicos_detectados[ip]["valor"] = valor_str
                            
                            # Verificar serviços web com tratamento ultra-defensivo
                            try:
                                # Apenas processar se for um dicionário
                                if isinstance(servicos_ip, dict):
                                    for chave, servico in servicos_ip.items():
                                        is_servico_web = False
                                        servico_nome = ""
                                        porta = None
                                        
                                        # Proteções extensivas para diferentes estruturas
                                        if isinstance(servico, dict) and 'servico' in servico:
                                            # Formato estruturado {servico: "http", ...}
                                            try:
                                                servico_nome = str(servico.get('servico', '')).lower()
                                            except:
                                                servico_nome = "erro-ao-converter"
                                                
                                            try:
                                                porta = servico.get('porta')
                                                # Validar que é um número inteiro
                                                if porta is not None and not isinstance(porta, int):
                                                    try:
                                                        porta = int(porta)
                                                    except:
                                                        porta = None
                                            except:
                                                porta = None
                                                
                                            if any(web in servico_nome for web in ['http', 'https', 'web']):
                                                is_servico_web = True
                                        elif isinstance(servico, str):
                                            # String direta, verificar se contém termos web
                                            try:
                                                servico_nome = servico.lower()
                                                if any(web in servico_nome for web in ['http', 'https', 'web']):
                                                    is_servico_web = True
                                            except:
                                                pass
                                        
                                        # Se detectamos um serviço web válido, disparar evento
                                        if is_servico_web:
                                            evento = Evento(
                                                tipo="servico_web_detectado",
                                                dados={
                                                    'host': ip,
                                                    'porta': porta,
                                                    'servico': servico_nome,
                                                    'fonte': nome_modulo
                                                },
                                                timestamp=datetime.now().isoformat(),
                                                prioridade="media"
                                            )
                                            contexto.eventos.append(evento)
                                            self.event_manager.disparar_evento(evento)
                            except Exception as e:
                                self.logger.warning(f"Erro ao processar serviços web para {ip}: {e}")
                    else:
                        # Caso 6: Qualquer outro tipo não esperado
                        self.logger.warning(f"servicos_detectados em {nome_modulo} é tipo inesperado: {type(servicos).__name__}")
                        # Tentar converter para string e armazenar como informação
                        try:
                            valor_str = str(servicos)
                        except:
                            valor_str = f"Objeto de tipo {type(servicos).__name__} não conversível para string"
                        
                        # Armazenar como informação genérica
                        chave_temp = f"valor_desconhecido_{nome_modulo}"
                        contexto.servicos_detectados[chave_temp] = {"valor": valor_str}
                except Exception as e:
                    self.logger.warning(f"Erro ao processar servicos_detectados em {nome_modulo}: {e}")
                    import traceback
                    self.logger.warning(f"Traceback: {traceback.format_exc()}")

            # Evento: Vulnerabilidades encontradas
            if 'vulnerabilidades_encontradas' in resultado:
                try:
                    vulns = resultado['vulnerabilidades_encontradas']
                    
                    # Verificar se é uma lista
                    if not isinstance(vulns, list):
                        self.logger.warning(f"vulnerabilidades_encontradas em {nome_modulo} não é uma lista: {type(vulns)}")
                        if isinstance(vulns, dict):
                            # Um único item, convertemos para lista
                            vulns = [vulns]
                        else:
                            vulns = []
                            
                    # Verificar se contexto.vulnerabilidades_encontradas é uma lista
                    if not isinstance(contexto.vulnerabilidades_encontradas, list):
                        self.logger.warning(f"contexto.vulnerabilidades_encontradas não é uma lista: {type(contexto.vulnerabilidades_encontradas)}")
                        contexto.vulnerabilidades_encontradas = []
                            
                    # Agora é seguro processar
                    if vulns:
                        contexto.vulnerabilidades_encontradas.extend(vulns)
                        
                        # Verificar vulnerabilidades críticas
                        for vuln in vulns:
                            if not isinstance(vuln, dict):
                                continue
                                
                            try:
                                severidade = str(vuln.get('severidade', '')).lower()
                            except:
                                severidade = ''
                                
                            try:
                                tipo = str(vuln.get('tipo', '')).lower()
                            except:
                                tipo = ''
                            
                            if severidade in ['critica', 'critical', 'alta', 'high'] or any(t in tipo for t in ['sql', 'rce', 'xss', 'injection']):
                                evento = Evento(
                                    tipo="vulnerabilidade_critica",
                                    dados={
                                        'vulnerabilidade': vuln,
                                        'host': vuln.get('host', 'desconhecido'),
                                        'fonte': nome_modulo
                                    },
                                    timestamp=datetime.now().isoformat(),
                                    prioridade="alta"
                                )
                                contexto.eventos.append(evento)
                                self.event_manager.disparar_evento(evento)
                except Exception as e:
                    self.logger.warning(f"Erro ao processar vulnerabilidades_encontradas em {nome_modulo}: {e}")

            # Evento: Feedback para ML com validações ultra-defensivas
            try:
                sucesso = False
                
                # Verificar sucesso com várias opções
                if 'sucesso_geral' in resultado:
                    # Converter para boolean explicitamente
                    sucesso = bool(resultado.get('sucesso_geral'))
                elif 'sucesso' in resultado:
                    # Converter para boolean explicitamente
                    sucesso = bool(resultado.get('sucesso'))
                    
                # Tempo de execução com valor padrão 0
                tempo_execucao = 0
                if 'tempo_execucao' in resultado:
                    try:
                        tempo_execucao = float(resultado.get('tempo_execucao', 0))
                    except:
                        tempo_execucao = 0
                
                # Mensagem de erro com valor padrão
                erro = "Erro desconhecido"
                if 'erro' in resultado:
                    try:
                        erro = str(resultado.get('erro', erro))
                    except:
                        erro = "Erro ao converter mensagem de erro"
                
                # Criar evento apropriado
                if sucesso:
                    evento = Evento(
                        tipo="feedback_ml",
                        dados={
                            'tipo': 'sucesso_modulo',
                            'modulo': nome_modulo,
                            'tempo_execucao': tempo_execucao,
                            'resultado': resultado
                        },
                        timestamp=datetime.now().isoformat(),
                        prioridade="baixa"
                    )
                else:
                    evento = Evento(
                        tipo="feedback_ml",
                        dados={
                            'tipo': 'falha_modulo',
                            'modulo': nome_modulo,
                            'erro': erro,
                            'resultado': resultado
                        },
                        timestamp=datetime.now().isoformat(),
                        prioridade="baixa"
                    )
                
                # Verificar que contexto.eventos é uma lista
                if not isinstance(contexto.eventos, list):
                    self.logger.warning(f"contexto.eventos não é uma lista: {type(contexto.eventos)}")
                    contexto.eventos = []
                    
                contexto.eventos.append(evento)
                self.event_manager.disparar_evento(evento)
            except Exception as e:
                self.logger.warning(f"Erro ao processar feedback ML em {nome_modulo}: {e}")

        except Exception as e:
            self.logger.warning(f"Erro ao disparar eventos para {nome_modulo}: {e}")
            import traceback
            self.logger.warning(f"Traceback: {traceback.format_exc()}")

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
                if not isinstance(ips_para_scan, list):
                    self.logger.warning(f"⚠️ extrair_ips_para_scan retornou {type(ips_para_scan)}, convertendo para lista")
                    contexto.ips_descobertos = []
                else:
                    contexto.ips_descobertos = ips_para_scan
                contexto.resultados_por_modulo['resolucao_dns'] = resultado_dns
                contexto.modulos_executados.append('resolucao_dns')
                self.logger.info(f"✓ DNS resolvido: {len(contexto.ips_descobertos)} IPs descobertos")
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

    def _extrair_portas_abertas(self, resultado_scan: Dict[str, Any]) -> List[int]:
        """Extrai lista de portas abertas do resultado do scan"""
        portas_abertas = []
        
        if not resultado_scan.get('sucesso'):
            return portas_abertas
            
        dados = resultado_scan.get('dados', {})
        hosts = dados.get('hosts', [])
        
        for host in hosts:
            portas = host.get('portas', [])
            for porta_info in portas:
                if isinstance(porta_info, dict) and porta_info.get('estado') == 'open':
                    numero_porta = porta_info.get('numero')
                    if isinstance(numero_porta, int):
                        portas_abertas.append(numero_porta)
                elif isinstance(porta_info, int):
                    # Fallback para formato simples (apenas número da porta)
                    portas_abertas.append(porta_info)
        
        return portas_abertas

    def _executar_loop_inteligente(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Loop principal com política de retry de IA (30s; 5 falhas) e sistema de eventos (Fase 3)."""
        # Debug detalhado para encontrar o problema
        self.logger.warning("INICIO DEBUG DETALHADO - Estruturas contexto")
        
        # Verificar tipo do contexto.ips_descobertos
        self.logger.warning(f"contexto.ips_descobertos tipo: {type(contexto.ips_descobertos)} valor: {contexto.ips_descobertos}")
        
        # Verificar tipo do contexto.decisoes_ia
        self.logger.warning(f"contexto.decisoes_ia tipo: {type(contexto.decisoes_ia)} valor: {contexto.decisoes_ia}")
        
        # Verificar tipo do contexto.portas_abertas
        self.logger.warning(f"contexto.portas_abertas tipo: {type(contexto.portas_abertas)} valor: {contexto.portas_abertas}")
        
        # Verificar tipo do contexto.servicos_detectados
        self.logger.warning(f"contexto.servicos_detectados tipo: {type(contexto.servicos_detectados)} valor: {contexto.servicos_detectados}")
        
        # Verificar tipo do contexto.vulnerabilidades_encontradas
        self.logger.warning(f"contexto.vulnerabilidades_encontradas tipo: {type(contexto.vulnerabilidades_encontradas)} valor: {contexto.vulnerabilidades_encontradas}")
        
        # Verificar tipo do contexto.modulos_executados
        self.logger.warning(f"contexto.modulos_executados tipo: {type(contexto.modulos_executados)} valor: {contexto.modulos_executados}")
        
        # Verificar tipo do contexto.resultados_por_modulo
        self.logger.warning(f"contexto.resultados_por_modulo tipo: {type(contexto.resultados_por_modulo)} valor: chaves: {list(contexto.resultados_por_modulo.keys()) if isinstance(contexto.resultados_por_modulo, dict) else 'INVÁLIDO'}")
        
        self.logger.warning("FIM DEBUG DETALHADO")
        
        # Verificar e corrigir estruturas de dados no contexto
        if not isinstance(contexto.ips_descobertos, list):
            self.logger.warning("⚠️ contexto.ips_descobertos não é uma lista, inicializando como lista vazia")
            contexto.ips_descobertos = []
        
        # Garantir que decisoes_ia é uma lista
        if not isinstance(contexto.decisoes_ia, list):
            self.logger.warning("⚠️ contexto.decisoes_ia não é uma lista, inicializando como lista vazia")
            contexto.decisoes_ia = []
            
        # Garantir que portas_abertas é um dicionário
        if not isinstance(contexto.portas_abertas, dict):
            self.logger.warning("⚠️ contexto.portas_abertas não é um dicionário, inicializando como dicionário vazio")
            contexto.portas_abertas = {}
            
        # Garantir que servicos_detectados é um dicionário
        if not isinstance(contexto.servicos_detectados, dict):
            self.logger.warning("⚠️ contexto.servicos_detectados não é um dicionário, inicializando como dicionário vazio")
            contexto.servicos_detectados = {}
            
        # Garantir que vulnerabilidades_encontradas é uma lista
        if not isinstance(contexto.vulnerabilidades_encontradas, list):
            self.logger.warning("⚠️ contexto.vulnerabilidades_encontradas não é uma lista, inicializando como lista vazia")
            contexto.vulnerabilidades_encontradas = []
            
        # Garantir que modulos_executados é uma lista
        if not isinstance(contexto.modulos_executados, list):
            self.logger.warning("⚠️ contexto.modulos_executados não é uma lista, inicializando como lista vazia")
            contexto.modulos_executados = []
            
        # Garantir que resultados_por_modulo é um dicionário
        if not isinstance(contexto.resultados_por_modulo, dict):
            self.logger.warning("⚠️ contexto.resultados_por_modulo não é um dicionário, inicializando como dicionário vazio")
            contexto.resultados_por_modulo = {}
            
        iteracao = 0
        falhas_consecutivas = 0
        tarefas_paralelas = []  # Lista de tarefas em execução paralela

        while not contexto.finalizado and iteracao < self.max_iteracoes:
            iteracao += 1
            self.logger.info(f"🔄 Iteração {iteracao} do loop inteligente (Fase 3)")

            # Novo: Verificar eventos pendentes (Fase 3)
            self._processar_eventos_pendentes(contexto)

            # Novo: Verificar conclusão de tarefas paralelas (Fase 3)
            tarefas_concluidas = self._verificar_tarefas_paralelas(tarefas_paralelas, contexto)
            if tarefas_concluidas:
                self.logger.info(f"✅ {len(tarefas_concluidas)} tarefas paralelas concluídas")

            try:
                decisao_ia = self._consultar_ia_proximos_passos(contexto)
                falhas_consecutivas = 0
                contexto.decisoes_ia.append(decisao_ia)

                acao = decisao_ia.get('acao', 'parar')
                self.logger.info(f"🤖 IA decidiu: {acao}")

                if acao == 'parar':
                    contexto.finalizado = True
                    contexto.motivo_finalizacao = decisao_ia.get('justificativa', 'IA decidiu parar')
                    self.logger.info(f"🛑 IA decidiu parar: {contexto.motivo_finalizacao}")
                    break

                if acao == 'executar_modulo':
                    modulo_escolhido = decisao_ia.get('modulo', '')
                    nome_exec = modulo_escolhido
                    if modulo_escolhido not in self.modulos_disponiveis:
                        nome_mapeado = self._mapear_categoria_para_modulo(modulo_escolhido)
                        if nome_mapeado:
                            self.logger.info(f"🔄 Mapeando '{modulo_escolhido}' → {nome_mapeado}")
                            nome_exec = nome_mapeado
                        else:
                            self.logger.warning(f"❓ Módulo desconhecido: {modulo_escolhido}")
                            continue

                    # Verificação adicional: evitar executar o mesmo módulo consecutivamente
                    if contexto.modulos_executados and contexto.modulos_executados[-1] == nome_exec:
                        self.logger.warning(f"🔄 IA tentou executar {nome_exec} consecutivamente. Pulando para evitar loop.")
                        continue

                    # Novo: Decidir se executar em paralelo ou sequencial (Fase 3)
                    if self._deve_executar_em_paralelo(nome_exec, contexto):
                        self.logger.info(f"⚡ Executando {nome_exec} em paralelo")
                        tarefa = self.executor.submit(self._executar_modulo_paralelo, nome_exec, contexto, decisao_ia)
                        tarefas_paralelas.append({
                            'tarefa': tarefa,
                            'modulo': nome_exec,
                            'decisao': decisao_ia,
                            'inicio': time.time()
                        })
                    else:
                        resultado_modulo = self._executar_modulo(nome_exec, contexto, decisao_ia)
                        self._atualizar_contexto_com_resultado(contexto, nome_exec, resultado_modulo)
                        contexto.pontuacao_risco = self._calcular_pontuacao_risco(contexto)

            except RuntimeError as e:
                falhas_consecutivas += 1
                self.logger.error(f"❌ ERRO DE IA: {str(e)} (falhas consecutivas: {falhas_consecutivas}/5)")
                if falhas_consecutivas >= 5:
                    contexto.finalizado = True
                    contexto.motivo_finalizacao = f"IA falhou 5 vezes consecutivas: {str(e)}"
                    break
                self.logger.info("⏳ Aguardando 30s antes de tentar novamente...")
                time.sleep(30)
                continue
            except Exception as e:
                self.logger.error(f"❌ Erro na iteração {iteracao}: {str(e)}")
                contexto.finalizado = True
                contexto.motivo_finalizacao = f"Erro na iteração {iteracao}: {str(e)}"
                break

            # Novo: Pequena pausa para permitir processamento de eventos (Fase 3)
            time.sleep(0.5)

        # Novo: Aguardar conclusão de todas as tarefas paralelas (Fase 3)
        if tarefas_paralelas:
            self.logger.info(f"⏳ Aguardando conclusão de {len(tarefas_paralelas)} tarefas paralelas...")
            for tarefa_info in tarefas_paralelas:
                try:
                    tarefa_info['tarefa'].result(timeout=60)  # Timeout de 60s por tarefa
                except Exception as e:
                    self.logger.warning(f"⚠️ Erro ao aguardar tarefa paralela {tarefa_info['modulo']}: {e}")

        if iteracao >= self.max_iteracoes:
            contexto.finalizado = True
            contexto.motivo_finalizacao = f"Limite máximo de iterações atingido ({self.max_iteracoes})"
            self.logger.warning(f"⚠️ {contexto.motivo_finalizacao}")

        return {'iteracoes_executadas': iteracao, 'contexto_final': contexto}

    def _processar_eventos_pendentes(self, contexto: ContextoExecucao):
        """Processa eventos pendentes no contexto (Fase 3)"""
        try:
            eventos_recentes = self.event_manager.obter_eventos_recentes(5)
            if eventos_recentes:
                self.logger.info(f"📋 Processando {len(eventos_recentes)} eventos recentes")
                
                # Filtrar eventos de alta prioridade
                eventos_prioritarios = [e for e in eventos_recentes if e.prioridade == "alta"]
                if eventos_prioritarios:
                    self.logger.info(f"🚨 {len(eventos_prioritarios)} eventos de alta prioridade detectados")
                    
                    # Adicionar ao contexto para decisão da IA
                    contexto.eventos.extend(eventos_prioritarios)
        except Exception as e:
            self.logger.warning(f"Erro ao processar eventos pendentes: {e}")

    def _verificar_tarefas_paralelas(self, tarefas_paralelas: List[Dict], contexto: ContextoExecucao) -> int:
        """Verifica conclusão de tarefas paralelas e atualiza contexto (Fase 3)"""
        concluidas = 0
        tarefas_restantes = []
        
        # Verificar se tarefas_paralelas é uma lista válida
        if not isinstance(tarefas_paralelas, list):
            self.logger.warning("⚠️ tarefas_paralelas não é uma lista válida, inicializando como lista vazia")
            return 0
            
        for tarefa_info in tarefas_paralelas:
            if tarefa_info['tarefa'].done():
                try:
                    resultado = tarefa_info['tarefa'].result()
                    nome_modulo = tarefa_info['modulo']
                    self._atualizar_contexto_com_resultado(contexto, nome_modulo, resultado)
                    contexto.pontuacao_risco = self._calcular_pontuacao_risco(contexto)
                    concluidas += 1
                    self.logger.info(f"✅ Tarefa paralela {nome_modulo} concluída")
                except Exception as e:
                    self.logger.error(f"❌ Erro na tarefa paralela {tarefa_info['modulo']}: {e}")
            else:
                tarefas_restantes.append(tarefa_info)
        
        # Atualizar lista de tarefas pendentes
        tarefas_paralelas.clear()
        tarefas_paralelas.extend(tarefas_restantes)
        
        return concluidas

    def _deve_executar_em_paralelo(self, nome_modulo: str, contexto: ContextoExecucao) -> bool:
        """Decide se um módulo deve ser executado em paralelo (Fase 3)"""
        # Módulos que podem ser executados em paralelo
        modulos_paralelos = [
            'scanner_portas_python',
            'enumerador_subdominios_python', 
            'detector_tecnologias_python',
            'scanner_diretorios_python',
            'buscador_exploits_python'
        ]
        
        # Não executar em paralelo se já há muitas tarefas
        if len([t for t in self.executor._threads if t.is_alive()]) >= 3:
            return False
            
        # Verificar se o módulo suporta paralelização
        return nome_modulo in modulos_paralelos

    def _executar_modulo_paralelo(self, nome_modulo: str, contexto: ContextoExecucao, decisao_ia: Dict[str, Any]) -> Dict[str, Any]:
        """Executa módulo em thread separada (Fase 3)"""
        try:
            self.logger.info(f"⚡ Executando {nome_modulo} em paralelo")
            resultado = self._executar_modulo(nome_modulo, contexto, decisao_ia)
            return resultado
        except Exception as e:
            self.logger.error(f"❌ Erro na execução paralela de {nome_modulo}: {e}")
            return {'sucesso': False, 'erro': str(e), 'tempo_execucao': 0}

    def _consultar_ia_proximos_passos(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Consulta IA com contexto seguro e retorna decisão em JSON."""
        # Debug para verificar estrutura do contexto
        self.logger.warning("DEBUG _consultar_ia_proximos_passos - Estrutura contexto:")
        
        # Verificar tipo do contexto.ips_descobertos
        self.logger.warning(f"contexto.ips_descobertos tipo: {type(contexto.ips_descobertos)}")
        if isinstance(contexto.ips_descobertos, list):
            self.logger.warning(f"  - tamanho lista: {len(contexto.ips_descobertos)}")
        else:
            self.logger.warning(f"  - valor direto: {contexto.ips_descobertos}")
        
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
        # Debug para verificar estrutura do contexto
        self.logger.warning("DEBUG _montar_contexto_completo - Estrutura contexto:")
        
        # Verificar tipo e conteúdo das principais propriedades
        try:
            self.logger.warning(f"contexto.ips_descobertos tipo: {type(contexto.ips_descobertos)} valor: {contexto.ips_descobertos}")
            if isinstance(contexto.ips_descobertos, list):
                self.logger.warning(f"  - ips_descobertos tamanho: {len(contexto.ips_descobertos)}")
            
            self.logger.warning(f"contexto.portas_abertas tipo: {type(contexto.portas_abertas)}")
            if isinstance(contexto.portas_abertas, dict):
                self.logger.warning(f"  - portas_abertas chaves: {list(contexto.portas_abertas.keys())}")
            
            self.logger.warning(f"contexto.servicos_detectados tipo: {type(contexto.servicos_detectados)}")
            if isinstance(contexto.servicos_detectados, dict):
                self.logger.warning(f"  - servicos_detectados chaves: {list(contexto.servicos_detectados.keys())}")
                
            self.logger.warning(f"contexto.resultados_por_modulo tipo: {type(contexto.resultados_por_modulo)}")
            if isinstance(contexto.resultados_por_modulo, dict):
                self.logger.warning(f"  - resultados_por_modulo chaves: {list(contexto.resultados_por_modulo.keys())}")
        except Exception as e:
            self.logger.error(f"Erro ao fazer debug do contexto: {e}")
        
        # Criação do contexto com proteção contra tipos inválidos
        ips_descobertos_safe = contexto.ips_descobertos if isinstance(contexto.ips_descobertos, list) else []
        portas_abertas_safe = contexto.portas_abertas if isinstance(contexto.portas_abertas, dict) else {}
        servicos_detectados_safe = contexto.servicos_detectados if isinstance(contexto.servicos_detectados, dict) else {}
        vulnerabilidades_safe = contexto.vulnerabilidades_encontradas if isinstance(contexto.vulnerabilidades_encontradas, list) else []
        modulos_executados_safe = contexto.modulos_executados if isinstance(contexto.modulos_executados, list) else []
        resultados_por_modulo_safe = contexto.resultados_por_modulo if isinstance(contexto.resultados_por_modulo, dict) else {}
        
        try:
            ultimos_resultados = {
                modulo: resultado
                for modulo, resultado in list(resultados_por_modulo_safe.items())[-3:]
            }
        except Exception as e:
            self.logger.error(f"Erro ao obter últimos resultados: {e}")
            ultimos_resultados = {}
            
        return {
            'alvo_original': contexto.alvo_original,
            'timestamp_inicio': contexto.timestamp_inicio,
            'tempo_decorrido': self._calcular_tempo_decorrido(contexto),
            'pontuacao_risco': contexto.pontuacao_risco,
            'ips_descobertos': ips_descobertos_safe,
            'portas_abertas': portas_abertas_safe,
            'servicos_detectados': servicos_detectados_safe,
            'vulnerabilidades_encontradas': vulnerabilidades_safe,
            'modulos_executados': modulos_executados_safe,
            'ultimos_resultados': ultimos_resultados
        }

    def _gerar_prompt_contexto_completo_seguro(self, contexto_seguro: Dict[str, Any], contexto_original: ContextoExecucao) -> str:
        # Logs para debug
        self.logger.warning("DEBUG _gerar_prompt_contexto_completo_seguro - Contexto seguro:")
        self.logger.warning(f"contexto_seguro['ips_descobertos'] tipo: {type(contexto_seguro.get('ips_descobertos'))}")
        
        # Garantir que ips_descobertos é uma lista antes de usar join
        ips_descobertos = contexto_seguro.get('ips_descobertos', [])
        if not isinstance(ips_descobertos, list):
            self.logger.warning(f"⚠️ ips_descobertos no contexto_seguro não é uma lista: {type(ips_descobertos)}")
            ips_descobertos = []
        
        prompt = f"""
ALVO ORIGINAL: {contexto_seguro.get('alvo_original', '[ANONIMIZADO]')}
TEMPO DECORRIDO: {contexto_seguro.get('tempo_decorrido', 'N/A')}
PONTUAÇÃO DE RISCO ATUAL: {contexto_seguro.get('pontuacao_risco', 0)}/100

IPS DESCOBERTOS: {', '.join(ips_descobertos)}

PORTAS ABERTAS POR HOST:
"""
        for ip, portas in contexto_seguro.get('portas_abertas', {}).items():
            if isinstance(portas, list):
                prompt += f"  {ip}: {', '.join(map(str, portas))}\n"
            else:
                self.logger.warning(f"⚠️ portas para IP {ip} não é uma lista: {type(portas)}")
                prompt += f"  {ip}: Formato desconhecido\n"

        servicos_detectados = contexto_seguro.get('servicos_detectados', {})
        
        # Contar total de serviços detectados com verificações ultra-robustas de tipo
        self.logger.debug("Iniciando contagem segura de serviços detectados")
        total_servicos = 0
        
        # Primeiro, verificar se servicos_detectados é um dicionário
        if not isinstance(servicos_detectados, dict):
            self.logger.warning(f"⚠️ servicos_detectados não é um dicionário: {type(servicos_detectados)}")
            prompt += f"\nSERVIÇOS DETECTADOS: Formato inválido\n"
            prompt += f"  Tipo encontrado: {type(servicos_detectados).__name__}\n"
        else:
            # Se for um dicionário vazio
            if not servicos_detectados:
                prompt += f"\nSERVIÇOS DETECTADOS: 0\n"
                prompt += f"  Nenhum serviço encontrado\n"
            else:
                # Iterar com tratamento seguro para cada entrada
                for ip, s in servicos_detectados.items():
                    try:
                        if s is None:
                            # Não adiciona nada
                            self.logger.debug(f"Serviços para {ip} é None - ignorando na contagem")
                            continue
                        
                        if isinstance(s, dict):
                            if not s:  # Dicionário vazio
                                self.logger.debug(f"Dicionário vazio para {ip}")
                                # Não incrementa o contador
                            else:
                                total_servicos += len(s)
                                self.logger.debug(f"Contados {len(s)} serviços para {ip} (dict)")
                        elif isinstance(s, list):
                            # Contar apenas itens válidos na lista
                            valid_items = [item for item in s if item is not None]
                            total_servicos += len(valid_items)
                            self.logger.debug(f"Contados {len(valid_items)} serviços para {ip} (list)")
                        elif isinstance(s, int):
                            if s > 0:  # Não contar números negativos ou zero
                                total_servicos += s
                                self.logger.debug(f"Adicionado contador {s} para {ip} (int)")
                        elif isinstance(s, str):
                            # Para strings, contar como 1 serviço se não estiver vazia
                            if s.strip():
                                total_servicos += 1
                                self.logger.debug(f"Contado 1 serviço para {ip} (string)")
                        else:
                            # Para qualquer outro tipo, contar como 1 por segurança
                            self.logger.warning(f"Tipo não esperado em servicos_detectados[{ip}]: {type(s).__name__}")
                            total_servicos += 1
                    except Exception as e:
                        self.logger.warning(f"Erro ao contar serviço para {ip}: {str(e)}")
                        # Continuar para o próximo item sem falhar
                
                # Adicionar ao prompt
                prompt += f"\nSERVIÇOS DETECTADOS: {total_servicos}\n"
                
                # Processar cada entrada com verificações ultra-robustas
                for ip, servicos in servicos_detectados.items():
                    try:
                        # Validação extremamente defensiva
                        if servicos is None:
                            prompt += f"  {ip}: 0 serviços (None)\n"
                            continue
                            
                        if isinstance(servicos, dict):
                            # Validar se é um dicionário vazio
                            if not servicos:
                                prompt += f"  {ip}: 0 serviços (dict vazio)\n"
                            else:
                                # Tentar extrair informações úteis se possível
                                if 'tecnologias' in servicos:
                                    # Caso especial para detector_tecnologias_python
                                    techs = servicos['tecnologias']
                                    if isinstance(techs, dict):
                                        tech_count = len(techs)
                                        tech_list = list(techs.keys())
                                        prompt += f"  {ip}: {tech_count} tecnologias"
                                        if tech_list:
                                            prompt += f" ({', '.join(tech_list[:3])}"
                                            if len(tech_list) > 3:
                                                prompt += f" e mais {len(tech_list)-3})"
                                            else:
                                                prompt += ")"
                                        prompt += "\n"
                                    else:
                                        prompt += f"  {ip}: tecnologias (formato não-dict)\n"
                                else:
                                    prompt += f"  {ip}: {len(servicos) if hasattr(servicos, '__len__') else '1'} serviços\n"
                        elif isinstance(servicos, list):
                            # Contar apenas itens válidos na lista
                            valid_items = [item for item in servicos if item is not None]
                            prompt += f"  {ip}: {len(valid_items)} serviços (lista)\n"
                        elif isinstance(servicos, int):
                            prompt += f"  {ip}: {servicos} serviços (contador)\n"
                        elif isinstance(servicos, str):
                            prompt += f"  {ip}: 1 serviço ({servicos[:20]}...)\n"
                        else:
                            # Qualquer outro tipo
                            prompt += f"  {ip}: Formato desconhecido ({type(servicos).__name__})\n"
                    except Exception as e:
                        self.logger.warning(f"Erro ao formatar serviços para {ip}: {e}")
                        prompt += f"  {ip}: Erro ao processar ({str(e)[:30]}...)\n"

        vulnerabilidades = contexto_seguro.get('vulnerabilidades_encontradas', [])
        
        # Garantir que vulnerabilidades é uma lista
        if not isinstance(vulnerabilidades, list):
            self.logger.warning(f"⚠️ vulnerabilidades no contexto_seguro não é uma lista: {type(vulnerabilidades)}")
            vulnerabilidades = []
            
        prompt += f"\nVULNERABILIDADES ENCONTRADAS: {len(vulnerabilidades)}\n"
        if vulnerabilidades:
            # Pegar as 3 últimas vulnerabilidades de forma segura
            for i in range(max(0, len(vulnerabilidades) - 3), len(vulnerabilidades)):
                vuln = vulnerabilidades[i]
                if isinstance(vuln, dict):
                    tipo = vuln.get('tipo', 'N/A')
                    descricao = vuln.get('descricao', 'N/A')
                    # Truncar descrição de forma segura
                    if isinstance(descricao, str):
                        descricao = descricao[:100]
                    prompt += f"  - {tipo}: {descricao}...\n"
                else:
                    prompt += f"  - Vulnerabilidade em formato inválido: {type(vuln).__name__}\n"

        prompt += f"\nRESUMO DOS ÚLTIMOS RESULTADOS:\n"
        
        # Garantir que modulos_executados é uma lista
        modulos_executados = []
        if isinstance(contexto_original.modulos_executados, list):
            # Pegar os 3 últimos módulos de forma segura
            modulos_executados = contexto_original.modulos_executados[-3:]
        else:
            self.logger.warning(f"⚠️ modulos_executados não é uma lista: {type(contexto_original.modulos_executados)}")
            
        # Garantir que resultados_por_modulo é um dicionário
        resultados_por_modulo = {}
        if isinstance(contexto_original.resultados_por_modulo, dict):
            resultados_por_modulo = contexto_original.resultados_por_modulo
        else:
            self.logger.warning(f"⚠️ resultados_por_modulo não é um dicionário: {type(contexto_original.resultados_por_modulo)}")
            
        for modulo in modulos_executados:
            resultado = resultados_por_modulo.get(modulo, {})
            # Verificar se resultado é um dicionário
            if not isinstance(resultado, dict):
                self.logger.warning(f"⚠️ resultado para {modulo} não é um dicionário: {type(resultado)}")
                prompt += f"  ⚠️ {modulo}: formato de resultado desconhecido\n"
                continue
                
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
        """
        Resolve os alvos para execução baseado na decisão da IA e no contexto atual.
        Inclui várias verificações e fallbacks para garantir que sempre retorna uma lista válida.
        """
        # Verificação inicial para garantir que alvos_ia é uma lista
        if not isinstance(alvos_ia, list):
            self.logger.warning(f"⚠️ alvos_ia não é uma lista, inicializando como lista vazia (tipo: {type(alvos_ia)})")
            alvos_ia = []
            
        # Verificação inicial para garantir que ips_descobertos é uma lista
        if not isinstance(contexto.ips_descobertos, list):
            self.logger.warning(f"⚠️ contexto.ips_descobertos não é uma lista, inicializando como lista vazia (tipo: {type(contexto.ips_descobertos)})")
            contexto.ips_descobertos = []
        
        # Usar o alvo original em caso de WEB scan se não houver IPs
        if (not contexto.ips_descobertos or len(contexto.ips_descobertos) == 0) and contexto.alvo_original:
            if isinstance(contexto.alvo_original, str) and contexto.alvo_original.startswith('http'):
                self.logger.info(f"🌐 Usando alvo WEB original como fallback: {contexto.alvo_original}")
                return [contexto.alvo_original]
            else:
                self.logger.info(f"🌐 Usando alvo original como fallback: {contexto.alvo_original}")
                return [str(contexto.alvo_original)]
            
        if not alvos_ia:
            if contexto.ips_descobertos:
                return contexto.ips_descobertos
            elif contexto.alvo_original:
                self.logger.warning(f"⚠️ Nenhum alvo especificado pela IA, usando alvo original: {contexto.alvo_original}")
                return [str(contexto.alvo_original)]
            else:
                self.logger.warning("⚠️ Nenhum alvo disponível para execução")
                return []
            
        alvos_reais: List[str] = []
        for alvo_ia in alvos_ia:
            if not isinstance(alvo_ia, str):
                self.logger.warning(f"⚠️ Alvo IA não é uma string: {type(alvo_ia)}, ignorando")
                continue
                
            if alvo_ia == "use_alvos_descobertos":
                if contexto.ips_descobertos:
                    alvos_reais.extend(contexto.ips_descobertos)
                elif contexto.alvo_original:
                    alvos_reais.append(str(contexto.alvo_original))
            elif alvo_ia.startswith("[") and alvo_ia.endswith("]"):
                self.logger.warning(f"Alvo anonimizado detectado: {alvo_ia}, usando todos os IPs descobertos")
                if contexto.ips_descobertos:
                    alvos_reais.extend(contexto.ips_descobertos)
                elif contexto.alvo_original:
                    alvos_reais.append(str(contexto.alvo_original))
            else:
                self.logger.info(f"Usando alvo específico da IA: {alvo_ia}")
                alvos_reais.append(alvo_ia)
                
        alvos_unicos: List[str] = []
        for a in alvos_reais:
            if a not in alvos_unicos:
                alvos_unicos.append(a)
                
        if not alvos_unicos:
            # Sem alvos disponíveis - usar o alvo original se disponível
            if contexto.alvo_original:
                self.logger.warning(f"⚠️ Nenhum alvo válido resolvido, usando alvo original: {contexto.alvo_original}")
                return [str(contexto.alvo_original)]
            else:
                self.logger.warning("⚠️ Nenhum alvo válido disponível para execução")
                return []
            
        self.logger.info(f"🎯 Alvos resolvidos: {len(alvos_unicos)} IPs/URLs")
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
        """Executa scanner de portas Python puro com tratamento robusto de tipos"""
        try:
            tipo_scan = parametros.get('tipo_scan', 'rapido')  # rapido, completo, ou personalizado
            portas_personalizadas = parametros.get('portas', None)

            try:
                # Executar o scan apropriado
                if tipo_scan == 'rapido':
                    resultado = modulo.scan_rapido(alvo)
                elif tipo_scan == 'completo':
                    resultado = modulo.scan_completo(alvo)
                elif tipo_scan == 'personalizado' and portas_personalizadas:
                    resultado = modulo.scan_personalizado(alvo, portas_personalizadas)
                else:
                    resultado = modulo.scan_rapido(alvo)
                    
                # Verificar se resultado é um dicionário
                if not isinstance(resultado, dict):
                    self.logger.warning(f"⚠️ Resultado do scanner de portas não é um dicionário: {type(resultado)}")
                    resultado = {'erro': f'Formato de resultado inválido: {type(resultado)}'}
                
                # Extrair portas_abertas de forma segura
                portas_abertas = {}
                if 'portas_abertas' in resultado:
                    portas_dados = resultado['portas_abertas']
                    if isinstance(portas_dados, dict):
                        portas_abertas = portas_dados
                    elif isinstance(portas_dados, list):
                        # Se for uma lista simples, associar ao alvo atual
                        portas_abertas = {alvo: portas_dados}
                    else:
                        self.logger.warning(f"⚠️ portas_abertas em formato inválido: {type(portas_dados)}")
                
                # Criar estrutura servicos_detectados robusta
                servicos_detectados = {}
                if 'servicos' in resultado:
                    servicos = resultado['servicos']
                    if isinstance(servicos, dict):
                        servicos_detectados = servicos
                    else:
                        self.logger.warning(f"⚠️ servicos em formato inválido: {type(servicos)}")
                        # Tentar normalizar
                        if isinstance(servicos, list):
                            # Converter lista para dicionário
                            servicos_detectados = {alvo: {f"servico_{i}": s for i, s in enumerate(servicos) if s}}
                        elif servicos is None:
                            servicos_detectados = {alvo: {}}
                        else:
                            servicos_detectados = {alvo: {'info': str(servicos)}}
                
                # Se não tiver serviços mas tiver portas abertas, criar serviços baseado nas portas
                if not servicos_detectados and portas_abertas:
                    for host, portas in portas_abertas.items():
                        if isinstance(portas, list):
                            servicos_detectados[host] = {
                                f"porta_{porta}": {"porta": porta, "servico": "desconhecido"} 
                                for porta in portas if porta
                            }
                
                # Resposta completa e padronizada
                resposta = {
                    'sucesso': 'erro' not in resultado,
                    'dados': resultado,
                    'tipo_scan': tipo_scan,
                    'timestamp': datetime.now().isoformat(),
                    'portas_abertas': portas_abertas,
                    'servicos_detectados': servicos_detectados  # Formato explícito e padronizado
                }
                
                return resposta
            except Exception as e:
                self.logger.error(f"Erro específico no scan: {str(e)}")
                import traceback
                self.logger.error(f"Traceback: {traceback.format_exc()}")
                
                # Resposta de erro com estrutura padronizada
                return {
                    'sucesso': False,
                    'erro': f'Erro específico no scanner de portas: {str(e)}',
                    'timestamp': datetime.now().isoformat(),
                    'servicos_detectados': {alvo: {}},  # Garante estrutura válida mesmo em caso de erro
                    'portas_abertas': {}
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
            # Verificação especial para quando não há alvos disponíveis
            if alvo == "use_alvos_descobertos" or (alvo.startswith("[") and alvo.endswith("]")):
                self.logger.warning("⚠️ Não há alvos disponíveis para detector_tecnologias_python")
                return {
                    'sucesso': False,
                    'erro': "Não há alvos disponíveis para detector_tecnologias_python",
                    'dados': {},
                    'modo_deteccao': 'completo',
                    'timestamp': datetime.now().isoformat()
                }
                
            url = f"http://{alvo}" if not alvo.startswith(('http://', 'https://')) else alvo
            
            self.logger.info(f"   Executando detector_tecnologias_python em {url}")
            
            try:
                resultado_bruto = modulo.executar_deteccao(url)
                
                # Verificar e sanitizar o resultado
                if not isinstance(resultado_bruto, dict):
                    self.logger.warning(f"Resultado de detector_tecnologias_python não é um dicionário: {type(resultado_bruto)}")
                    resultado_bruto = {
                        'sucesso': False,
                        'erro': f"Formato de resultado inválido: {type(resultado_bruto)}",
                        'alvo': url
                    }
                
                # Verificar e sanitizar campo 'tecnologias'
                if 'tecnologias' in resultado_bruto and not isinstance(resultado_bruto['tecnologias'], dict):
                    self.logger.warning(f"Campo 'tecnologias' não é um dicionário: {type(resultado_bruto['tecnologias'])}")
                    resultado_bruto['tecnologias'] = {'erro': 'formato inválido'}
                
                # Construir resposta padronizada com validação extrema de tipos
                self.logger.debug(f"Construindo resposta para detector_tecnologias_python com validação robusta de tipos")
                
                # Garantir que temos uma estrutura válida em resultados brutos
                if not isinstance(resultado_bruto, dict):
                    self.logger.warning(f"⚠️ resultado_bruto não é um dicionário: {type(resultado_bruto)} - normalizando")
                    resultado_bruto = {
                        'sucesso': False,
                        'erro': f"Formato de resultado inválido: {type(resultado_bruto)}",
                        'alvo': url,
                        'timestamp': datetime.now().isoformat()
                    }
                
                # Verificar tecnologias de forma robusta
                tecnologias = {}
                if 'tecnologias' in resultado_bruto:
                    tech_data = resultado_bruto['tecnologias']
                    if isinstance(tech_data, dict):
                        tecnologias = tech_data
                    else:
                        self.logger.warning(f"⚠️ tecnologias não é um dicionário: {type(tech_data)}")
                        # Tentar normalizar dados não-dicionário
                        if isinstance(tech_data, list):
                            tecnologias = {f"item_{i}": item for i, item in enumerate(tech_data) if item is not None}
                        elif isinstance(tech_data, str):
                            tecnologias = {"valor": tech_data}
                        elif isinstance(tech_data, int):
                            tecnologias = {"contador": tech_data}
                        elif tech_data is None:
                            tecnologias = {}
                        else:
                            tecnologias = {"valor_tipo_desconhecido": str(tech_data)}
                
                # Construir estrutura normalizada e defensiva
                resposta = {
                    'sucesso': resultado_bruto.get('sucesso', True),
                    'dados': resultado_bruto,
                    'timestamp': datetime.now().isoformat(),
                }
                
                # Garantir estrutura válida de servicos_detectados
                servicos_detectados = {}
                
                # Se temos tecnologias detectadas
                if tecnologias:
                    # Usar o URL como chave para os serviços
                    servicos_detectados = {
                        url: {'tecnologias': tecnologias}
                    }
                else:
                    # Se não temos tecnologias, mas temos algum erro
                    if 'erro' in resultado_bruto:
                        servicos_detectados = {
                            url: {'info': f"Nenhuma tecnologia detectada: {resultado_bruto['erro'][:50]}"}
                        }
                    else:
                        # Se não temos tecnologias nem erro, indicar que nada foi encontrado
                        servicos_detectados = {
                            url: {'info': "Nenhuma tecnologia detectada"}
                        }
                
                # Adicionar estrutura à resposta
                resposta['servicos_detectados'] = servicos_detectados
                
                self.logger.debug(f"Resposta do detector_tecnologias_python estruturada com sucesso")
                return resposta
            except Exception as e:
                self.logger.error(f"Erro ao executar detector_tecnologias_python: {str(e)}")
                import traceback
                self.logger.error(f"Traceback: {traceback.format_exc()}")
                return {
                    'sucesso': False,
                    'erro': f"Erro no detector de tecnologias: {str(e)}",
                    'dados': {'alvo': url, 'erro': str(e)},
                    'timestamp': datetime.now().isoformat()
                }
        except Exception as e:
            self.logger.error(f"Erro geral no detector de tecnologias: {str(e)}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            return {
                'sucesso': False, 
                'erro': f'Erro no detector de tecnologias: {str(e)}',
                'timestamp': datetime.now().isoformat(),
                'dados': {'erro': str(e)}
            }

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

            # Validar que vulnerabilidades_encontradas é uma lista
            if not isinstance(contexto.vulnerabilidades_encontradas, list):
                self.logger.warning("⚠️ contexto.vulnerabilidades_encontradas não é uma lista, inicializando como lista vazia")
                contexto.vulnerabilidades_encontradas = []

            # Fator 1: Vulnerabilidades encontradas (peso alto - 40 pontos max)
            num_vulnerabilidades = len(contexto.vulnerabilidades_encontradas)
            if num_vulnerabilidades > 0:
                # Cada vulnerabilidade crítica adiciona 20 pontos, média 10, baixa 5
                for vuln in contexto.vulnerabilidades_encontradas:
                    if not isinstance(vuln, dict):
                        continue
                    severidade = vuln.get('severidade', 'media').lower()
                    if severidade == 'critica' or severidade == 'alta':
                        pontuacao += 20
                    elif severidade == 'media':
                        pontuacao += 10
                    else:
                        pontuacao += 5
                # Limitar a 40 pontos para vulnerabilidades
                pontuacao = min(pontuacao, 40)

            # Validar que portas_abertas é um dicionário
            if not isinstance(contexto.portas_abertas, dict):
                self.logger.warning("⚠️ contexto.portas_abertas não é um dicionário, inicializando como dicionário vazio")
                contexto.portas_abertas = {}

            # Fator 2: Portas abertas (peso médio - 25 pontos max)
            total_portas_abertas = 0
            try:
                total_portas_abertas = sum(len(portas) if isinstance(portas, list) else 0 
                                         for portas in contexto.portas_abertas.values())
            except Exception as e:
                self.logger.warning(f"Erro ao calcular total de portas abertas: {str(e)}")
                
            if total_portas_abertas > 0:
                # Portas perigosas têm peso maior
                portas_perigosas = 0
                for ip, portas in contexto.portas_abertas.items():
                    if not isinstance(portas, list):
                        continue
                    for porta in portas:
                        if porta in [21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 993, 995, 3389]:
                            portas_perigosas += 1

                # Cada porta perigosa = 5 pontos, outras = 2 pontos
                pontuacao += (portas_perigosas * 5) + ((total_portas_abertas - portas_perigosas) * 2)
                # Limitar a 25 pontos para portas
                pontuacao = min(pontuacao, 65)  # 40 (vulns) + 25 (portas)

            # Validar que servicos_detectados é um dicionário
            if not isinstance(contexto.servicos_detectados, dict):
                self.logger.warning("⚠️ contexto.servicos_detectados não é um dicionário, inicializando como dicionário vazio")
                contexto.servicos_detectados = {}

            # Fator 3: Serviços detectados (peso médio - 20 pontos max)
            total_servicos = 0
            try:
                # Contagem ultra-robusta para evitar chamar len() em tipos não iteráveis
                for ip, servicos in contexto.servicos_detectados.items():
                    if servicos is None:
                        # Se é None, não contar
                        continue
                    
                    if isinstance(servicos, dict):
                        # Para dicionários, contar cada chave como um serviço
                        # Mas também verificar valores internos que podem ser dicionários
                        for chave, valor in servicos.items():
                            if isinstance(valor, dict):
                                # Caso especial para detector_tecnologias_python
                                if chave == 'tecnologias' and isinstance(valor, dict):
                                    # Cada tecnologia detectada é um serviço
                                    total_servicos += len(valor)
                                else:
                                    # Para outros dicionários aninhados, contar como um serviço
                                    total_servicos += 1
                            elif valor is not None:
                                # Para outros valores não-None, contar como um serviço
                                total_servicos += 1
                    elif isinstance(servicos, list):
                        # Para listas, contar cada elemento não-None
                        for item in servicos:
                            if item is not None:
                                total_servicos += 1
                    elif isinstance(servicos, int):
                        # Se é um contador direto - NÃO tente chamar len() nele
                        if servicos > 0:
                            total_servicos += servicos
                    elif isinstance(servicos, str):
                        # Se é uma string, contar como 1
                        total_servicos += 1
                    else:
                        # Para qualquer outro tipo, usar como 1
                        total_servicos += 1
                        
                # Log de diagnóstico
                self.logger.debug(f"Total de serviços detectados contados: {total_servicos}")
            except Exception as e:
                self.logger.warning(f"Erro ao calcular total de serviços: {str(e)}")
                import traceback
                self.logger.debug(f"Traceback: {traceback.format_exc()}")
                
            if total_servicos > 0:
                # Serviços web têm peso maior
                servicos_web = 0
                for ip, servicos in contexto.servicos_detectados.items():
                    if not isinstance(servicos, dict):
                        # Tentar uma contagem aproximada para tipos não dicionário
                        if isinstance(servicos, str) and any(web in servicos.lower() for web in ['http', 'apache', 'nginx', 'iis', 'tomcat']):
                            servicos_web += 1
                        # Se for um inteiro, não tente tratar como um container
                        elif isinstance(servicos, int):
                            # Apenas considerar como um único serviço não-web
                            continue
                        else:
                            continue
                        
                    for key, servico in servicos.items():
                        # Verificações extensivas para diferentes formatos de dados
                        if isinstance(servico, dict):
                            # Formato padrão: dicionário com chave 'nome'
                            nome_servico = str(servico.get('nome', '')).lower()
                            # Procurar também em outras chaves comuns se 'nome' não existir
                            if not nome_servico:
                                for chave in ['servico', 'service', 'tipo', 'type', 'servidor', 'server']:
                                    if chave in servico:
                                        nome_servico += ' ' + str(servico.get(chave, '')).lower()
                        elif isinstance(servico, str):
                            # Se o serviço é uma string direta
                            nome_servico = servico.lower()
                        else:
                            # Para outros tipos, tentar converter para string
                            try:
                                nome_servico = str(servico).lower()
                            except:
                                nome_servico = ''
                                
                        # Verificar por indicadores de serviço web
                        if any(web in nome_servico for web in ['http', 'apache', 'nginx', 'iis', 'tomcat', 'web', 'html', 'ssl']):
                            servicos_web += 1

                # Cada serviço web = 4 pontos, outros = 2 pontos
                pontuacao += (servicos_web * 4) + ((total_servicos - servicos_web) * 2)
                # Limitar a 20 pontos para serviços
                pontuacao = min(pontuacao, 85)  # 40 + 25 + 20

            # Validar que ips_descobertos é uma lista
            if not isinstance(contexto.ips_descobertos, list):
                self.logger.warning("⚠️ contexto.ips_descobertos não é uma lista, inicializando como lista vazia")
                contexto.ips_descobertos = []

            # Fator 4: IPs descobertos (peso baixo - 10 pontos max)
            num_ips = len(contexto.ips_descobertos)
            if num_ips > 1:
                # Múltiplos IPs podem indicar rede maior = mais risco
                pontuacao += min(num_ips * 2, 10)
                pontuacao = min(pontuacao, 95)  # 40 + 25 + 20 + 10

            # Validar que modulos_executados é uma lista
            if not isinstance(contexto.modulos_executados, list):
                self.logger.warning("⚠️ contexto.modulos_executados não é uma lista, inicializando como lista vazia")
                contexto.modulos_executados = []

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
            import traceback
            self.logger.warning(f"Traceback: {traceback.format_exc()}")
            # Em caso de erro, retorna pontuação padrão
            return 50

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
        # Logs para debug
        self.logger.warning("DEBUG _finalizar_pentest - Verificando estruturas do contexto:")
        
        # Verificar estruturas críticas e garantir tipos corretos
        if not isinstance(contexto.ips_descobertos, list):
            self.logger.error(f"⚠️ contexto.ips_descobertos não é uma lista: {type(contexto.ips_descobertos)}")
            contexto.ips_descobertos = []
            
        if not isinstance(contexto.portas_abertas, dict):
            self.logger.error(f"⚠️ contexto.portas_abertas não é um dicionário: {type(contexto.portas_abertas)}")
            contexto.portas_abertas = {}
            
        if not isinstance(contexto.servicos_detectados, dict):
            self.logger.error(f"⚠️ contexto.servicos_detectados não é um dicionário: {type(contexto.servicos_detectados)}")
            contexto.servicos_detectados = {}
            
        if not isinstance(contexto.vulnerabilidades_encontradas, list):
            self.logger.error(f"⚠️ contexto.vulnerabilidades_encontradas não é uma lista: {type(contexto.vulnerabilidades_encontradas)}")
            contexto.vulnerabilidades_encontradas = []
            
        if not isinstance(contexto.modulos_executados, list):
            self.logger.error(f"⚠️ contexto.modulos_executados não é uma lista: {type(contexto.modulos_executados)}")
            contexto.modulos_executados = []
            
        if not isinstance(contexto.resultados_por_modulo, dict):
            self.logger.error(f"⚠️ contexto.resultados_por_modulo não é um dicionário: {type(contexto.resultados_por_modulo)}")
            contexto.resultados_por_modulo = {}
        
        timestamp_fim = datetime.now().isoformat()
        
        # Cálculos seguros para estatísticas
        try:
            ips_descobertos_count = len(contexto.ips_descobertos)
        except Exception as e:
            self.logger.error(f"Erro ao contar ips_descobertos: {e}")
            ips_descobertos_count = 0
            
        try:
            total_portas_abertas = sum(len(p) if isinstance(p, list) else 0 for p in contexto.portas_abertas.values())
        except Exception as e:
            self.logger.error(f"Erro ao calcular total_portas_abertas: {e}")
            total_portas_abertas = 0
            
        try:
            servicos_detectados_count = sum(len(s) if hasattr(s, '__len__') else 0 for s in contexto.servicos_detectados.values())
        except Exception as e:
            self.logger.error(f"Erro ao contar servicos_detectados: {e}")
            servicos_detectados_count = 0
            
        try:
            vulnerabilidades_count = len(contexto.vulnerabilidades_encontradas)
        except Exception as e:
            self.logger.error(f"Erro ao contar vulnerabilidades_encontradas: {e}")
            vulnerabilidades_count = 0
            
        try:
            modulos_count = len(contexto.modulos_executados)
        except Exception as e:
            self.logger.error(f"Erro ao contar modulos_executados: {e}")
            modulos_count = 0
        
        try:
            sucesso_geral = any(
                r.get('sucesso', False)
                for r in contexto.resultados_por_modulo.values()
                if isinstance(r, dict)
            )
        except Exception as e:
            self.logger.error(f"Erro ao calcular sucesso_geral: {e}")
            sucesso_geral = False
            
        resumo_final = {
            'alvo_original': contexto.alvo_original,
            'timestamp_inicio': contexto.timestamp_inicio,
            'timestamp_fim': timestamp_fim,
            'tempo_total': self._calcular_tempo_decorrido(contexto),
            'sucesso_geral': sucesso_geral,
            'estatisticas': {
                'ips_descobertos': ips_descobertos_count,
                'total_portas_abertas': total_portas_abertas,
                'servicos_detectados': servicos_detectados_count,
                'vulnerabilidades_encontradas': vulnerabilidades_count,
                'modulos_executados': modulos_count,
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
