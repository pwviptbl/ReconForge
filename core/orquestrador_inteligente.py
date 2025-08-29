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
            from modulos.varredura_feroxbuster import VarreduraFeroxbuster
            from modulos.varredura_nikto import VarreduraNikto
            from modulos.varredura_whatweb import VarreduraWhatWeb
            from modulos.varredura_nuclei import VarreduraNuclei

            # Descoberta
            from modulos.varredura_subfinder import VarreduraSubfinder
            from modulos.varredura_sublist3r import VarreduraSublist3r

            # Exploração
            from modulos.varredura_sqlmap import VarreduraSQLMap
            from modulos.varredura_searchsploit import VarreduraSearchSploit

            # Scanners
            from modulos.scanner_vulnerabilidades import ScannerVulnerabilidades
            from modulos.scanner_web_avancado import ScannerWebAvancado
            from modulos.varredura_scraper_auth import VarreduraScraperAuth
            from modulos.navegacao_web_ia import NavegadorWebIA

            # Testes
            from modulos.testador_vulnerabilidades_web import TestadorVulnerabilidadesWeb
            from modulos.testador_seguranca_api import TestadorSegurancaAPI
            from modulos.testador_seguranca_mobile_web import TestadorSegurancaMobileWeb

            self.modulos_disponiveis = {
                'feroxbuster_basico': VarreduraFeroxbuster(),
                'feroxbuster_recursivo': VarreduraFeroxbuster(),
                'nikto_scan': VarreduraNikto(),
                'whatweb_scan': VarreduraWhatWeb(),
                'nuclei_scan': VarreduraNuclei(),
                'subfinder_enum': VarreduraSubfinder(),
                'sublist3r_enum': VarreduraSublist3r(),
                'sqlmap_teste_url': VarreduraSQLMap(),
                'sqlmap_teste_formulario': VarreduraSQLMap(),
                'searchsploit_check': VarreduraSearchSploit(),
                'scanner_vulnerabilidades': ScannerVulnerabilidades(),
                'scanner_web_avancado': ScannerWebAvancado(),
                'scraper_auth': VarreduraScraperAuth(),
                'navegador_web': NavegadorWebIA(),

                'testador_vulnerabilidades_web': TestadorVulnerabilidadesWeb(),
                'testador_seguranca_api': TestadorSegurancaAPI(),
                'testador_seguranca_mobile_web': TestadorSegurancaMobileWeb(),

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
            if modo == 'web':
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
                'feroxbuster_basico', 'feroxbuster_recursivo', 'nikto_scan',
                'whatweb_scan', 'nuclei_scan', 'scraper_auth', 'navegador_web'
            ],
            'Descoberta de Subdomínios': ['subfinder_enum', 'sublist3r_enum'],
            'Exploração': ['sqlmap_teste_url', 'sqlmap_teste_formulario', 'searchsploit_check'],
            'Scanner de Vulnerabilidades': ['scanner_vulnerabilidades', 'scanner_web_avancado'],
            'Testes de Vulnerabilidades Web': ['testador_vulnerabilidades_web'],
            'Testes de Segurança de API': ['testador_seguranca_api'],
            'Testes de Segurança Mobile/Web': ['testador_seguranca_mobile_web'],
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
            'varredura web': 'feroxbuster_basico',
            'varredura de web': 'feroxbuster_basico',
            'web scanner': 'scanner_web_avancado',
            'scanner web': 'scanner_web_avancado',
            'web scan': 'feroxbuster_basico',
            'feroxbuster': 'feroxbuster_basico',
            'nikto': 'nikto_scan',
            'whatweb': 'whatweb_scan',
            'nuclei': 'nuclei_scan',
            'scraper': 'scraper_auth',
            'scraping': 'scraper_auth',
            'web scraping': 'navegador_web',
            'selenium': 'navegador_web',
            'navegador': 'navegador_web',
            'browser': 'navegador_web',
            'nmap': 'nmap_varredura_completa',
            'nmap completo': 'nmap_varredura_completa',
            'scan de vulnerabilidades': 'scanner_vulnerabilidades',
            'scanner de vulnerabilidades': 'scanner_vulnerabilidades',
            'sqlmap': 'sqlmap_teste_url',
            'subfinder': 'subfinder_enum',
            'sublist3r': 'sublist3r_enum',
            'teste vulnerabilidades web': 'testador_vulnerabilidades_web',
            'teste xss': 'testador_vulnerabilidades_web',
            'teste sql injection': 'testador_vulnerabilidades_web',
            'teste lfi': 'testador_vulnerabilidades_web',
            'teste command injection': 'testador_vulnerabilidades_web',
            'teste csrf': 'testador_vulnerabilidades_web',
            'teste open redirect': 'testador_vulnerabilidades_web',
            'teste api': 'testador_seguranca_api',
            'teste seguranca api': 'testador_seguranca_api',
            'teste autenticacao api': 'testador_seguranca_api',
            'teste injection api': 'testador_seguranca_api',
            'teste idor': 'testador_seguranca_api',
            'teste rate limiting': 'testador_seguranca_api',
            'teste cors': 'testador_seguranca_api',
            'teste graphql': 'testador_seguranca_api',
            'teste mobile': 'testador_seguranca_mobile_web',
            'teste pwa': 'testador_seguranca_mobile_web',
            'teste ssl': 'testador_seguranca_mobile_web',
            'teste certificado': 'testador_seguranca_mobile_web',
            'teste service worker': 'testador_seguranca_mobile_web',
            'teste manifest': 'testador_seguranca_mobile_web',
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

            if nome_modulo == 'navegador_web' and 'credenciais' not in parametros and getattr(self, 'credenciais_web', None):
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
                    elif nome_modulo == 'testador_vulnerabilidades_web':
                        resultado = self._executar_modulo_testador_vulnerabilidades_web(alvo, modulo, parametros)
                    elif nome_modulo == 'testador_seguranca_api':
                        resultado = self._executar_modulo_testador_seguranca_api(alvo, modulo, parametros)
                    elif nome_modulo == 'testador_seguranca_mobile_web':
                        resultado = self._executar_modulo_testador_seguranca_mobile_web(alvo, modulo, parametros)
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

    def _atualizar_contexto_com_resultado(self, contexto: ContextoExecucao, nome_modulo: str, resultado: Dict):
        try:
            contexto.modulos_executados.append(nome_modulo)
            contexto.resultados_por_modulo[nome_modulo] = resultado

            if resultado.get('sucesso'):
                # Serviços
                servicos = self._extrair_servicos_do_resultado(resultado)
                for ip, servicos_ip in servicos.items():
                    if ip not in contexto.servicos_detectados:
                        contexto.servicos_detectados[ip] = {}
                    contexto.servicos_detectados[ip].update(servicos_ip)

                # Vulnerabilidades
                vulnerabilidades = self._extrair_vulnerabilidades_do_resultado(resultado)
                contexto.vulnerabilidades_encontradas.extend(vulnerabilidades)

                # Portas novas
                novas_portas = self._extrair_portas_do_resultado(resultado)
                for ip, portas in novas_portas.items():
                    if ip in contexto.portas_abertas:
                        contexto.portas_abertas[ip] = list(set(contexto.portas_abertas[ip] + portas))
                    else:
                        contexto.portas_abertas[ip] = portas

            self.logger.info(f"   Contexto atualizado com resultados de {nome_modulo}")
        except Exception as e:
            self.logger.error(f"Erro ao atualizar contexto: {str(e)}")

    def _extrair_portas_abertas(self, resultado_scan: Dict) -> List[int]:
        portas: List[int] = []
        try:
            dados = resultado_scan.get('dados', {})
            if 'portas_abertas' in dados:
                portas = dados['portas_abertas']
            elif 'hosts' in dados:
                for host in dados['hosts']:
                    for porta in host.get('portas', []):
                        if porta.get('estado') == 'open':
                            portas.append(porta.get('numero'))
        except Exception as e:
            self.logger.warning(f"Erro ao extrair portas: {str(e)}")
        return portas

    def _extrair_servicos_do_resultado(self, resultado: Dict) -> Dict[str, Dict]:
        servicos: Dict[str, Dict] = {}
        try:
            for alvo, resultado_alvo in resultado.get('resultados_por_alvo', {}).items():
                dados = resultado_alvo.get('dados', {})
                if 'hosts' in dados:
                    for host in dados['hosts']:
                        ip = host.get('endereco', alvo)
                        if ip not in servicos:
                            servicos[ip] = {}
                        for porta in host.get('portas', []):
                            if porta.get('estado') == 'open':
                                porta_num = porta.get('numero')
                                servicos[ip][porta_num] = {
                                    'servico': porta.get('servico', 'unknown'),
                                    'produto': porta.get('produto', ''),
                                    'versao': porta.get('versao', ''),
                                    'protocolo': porta.get('protocolo', 'tcp')
                                }
        except Exception as e:
            self.logger.warning(f"Erro ao extrair serviços: {str(e)}")
        return servicos

    def _extrair_vulnerabilidades_do_resultado(self, resultado: Dict) -> List[Dict]:
        vulnerabilidades: List[Dict] = []
        try:
            for alvo, resultado_alvo in resultado.get('resultados_por_alvo', {}).items():
                dados = resultado_alvo.get('dados', {})

                if 'hosts' in dados:
                    for host in dados['hosts']:
                        ip = host.get('endereco', alvo)
                        for script in host.get('scripts', []):
                            if 'vuln' in script.get('id', '').lower():
                                vulnerabilidades.append({
                                    'ip': ip,
                                    'tipo': 'host',
                                    'script': script.get('id'),
                                    'descricao': script.get('saida', ''),
                                    'fonte': resultado.get('nome_modulo', 'unknown')
                                })
                        for porta in host.get('portas', []):
                            for script in porta.get('scripts', []):
                                if 'vuln' in script.get('id', '').lower():
                                    vulnerabilidades.append({
                                        'ip': ip,
                                        'porta': porta.get('numero'),
                                        'tipo': 'porta',
                                        'script': script.get('id'),
                                        'descricao': script.get('saida', ''),
                                        'fonte': resultado.get('nome_modulo', 'unknown')
                                    })

                # Outras ferramentas em 'dados'
                if 'vulnerabilidades' in dados:
                    for v in dados['vulnerabilidades']:
                        vulnerabilidades.append({
                            'ip': alvo,
                            'tipo': v.get('tipo', 'unknown'),
                            'descricao': v.get('descricao', ''),
                            'severidade': v.get('severidade', 'unknown'),
                            'fonte': resultado.get('nome_modulo', 'unknown')
                        })

            # Suporte scanner_web_avancado (formato direto)
            if resultado.get('nome_modulo') == 'scanner_web_avancado':
                dados_dir = resultado.get('dados', {})
                if 'vulnerabilidades' in dados_dir:
                    for v in dados_dir['vulnerabilidades']:
                        vulnerabilidades.append({
                            'ip': dados_dir.get('url_base', 'unknown').replace('http://', '').replace('https://', '').split('/')[0],
                            'tipo': 'web',
                            'titulo': v.get('titulo', 'Vulnerabilidade Web'),
                            'descricao': v.get('descricao', ''),
                            'criticidade': v.get('criticidade', 'BAIXA'),
                            'url': v.get('url', ''),
                            'fonte': 'scanner_web_avancado'
                        })

            # Suporte navegador_web (estudo com navegador)
            if resultado.get('nome_modulo') == 'navegador_web':
                dados_nav = resultado.get('dados', {})
                if 'vulnerabilidades' in dados_nav:
                    for v in dados_nav['vulnerabilidades']:
                        base = dados_nav.get('url_base', dados_nav.get('url', 'unknown'))
                        ip = base.replace('http://', '').replace('https://', '').split('/')[0]
                        vulnerabilidades.append({
                            'ip': ip,
                            'tipo': 'web',
                            'titulo': v.get('titulo', 'Vulnerabilidade Web'),
                            'descricao': v.get('descricao', ''),
                            'criticidade': v.get('criticidade', 'BAIXA'),
                            'url': v.get('url', dados_nav.get('url', '')),
                            'fonte': 'navegador_web'
                        })
        except Exception as e:
            self.logger.warning(f"Erro ao extrair vulnerabilidades: {str(e)}")
        return vulnerabilidades

    def _extrair_portas_do_resultado(self, resultado: Dict) -> Dict[str, List[int]]:
        portas: Dict[str, List[int]] = {}
        try:
            for alvo, resultado_alvo in resultado.get('resultados_por_alvo', {}).items():
                novas = self._extrair_portas_abertas(resultado_alvo)
                if novas:
                    portas[alvo] = novas
        except Exception as e:
            self.logger.warning(f"Erro ao extrair portas do resultado: {str(e)}")
        return portas

    def _calcular_pontuacao_risco(self, contexto: ContextoExecucao) -> int:
        try:
            pontuacao = 0
            total_portas = sum(len(portas) for portas in contexto.portas_abertas.values())
            pontuacao += min(total_portas * 2, 30)
            servicos_criticos = ['ssh', 'ftp', 'telnet', 'smb', 'rdp', 'mysql', 'postgresql']
            for ip, servicos in contexto.servicos_detectados.items():
                for porta, info in servicos.items():
                    servico = info.get('servico', '').lower()
                    if any(crit in servico for crit in servicos_criticos):
                        pontuacao += 10
            pontuacao += len(contexto.vulnerabilidades_encontradas) * 15
            servicos_web = 0
            for ip, portas in contexto.portas_abertas.items():
                servicos_web += len([p for p in portas if p in [80, 443, 8080, 8000, 8443]])
            pontuacao += servicos_web * 5
            return min(pontuacao, 100)
        except Exception:
            return 0

    def _calcular_tempo_decorrido(self, contexto: ContextoExecucao) -> str:
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
