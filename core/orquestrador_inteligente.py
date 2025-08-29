#!/usr/bin/env python3
"""
Orquestrador Inteligente com Loop Adaptativo
Implementa estratégia de loop inteligente onde a IA decide os próximos passos
baseada em todos os resultados acumulados anteriormente.

SEGURANÇA: IPs são anonimizados antes do envio para IA, preservando privacidade
sem comprometer a funcionalidade do sistema.

Fluxo:
1. Resolução DNS inicial
2. RustScan básico (todas as portas)
3. Loop inteligente:
   - IA analisa contexto acumulado (com IPs anonimizados)
   - Decide próximo módulo ou parar
   - Executa módulo escolhido (com IPs reais)
   - Acumula resultados
   - Repete até decisão de parar
4. Gera relatório final
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field

from utils.logger import obter_logger, log_manager
from utils.rede import extrair_ips_para_scan
from utils.resumo import gerar_resumo_scan_completo
from utils.anonimizador_ip import anonimizar_contexto_ia, criar_contexto_seguro_para_ia


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
        """Inicializa o orquestrador inteligente"""
        self.logger = logger_func('OrquestradorInteligente')
        self.resolver_dns = resolver_dns
        self.scanner_portas = scanner_portas
        self.scanner_nmap = scanner_nmap
        self.decisao_ia = decisao_ia
        
        # Verificar se Gemini está disponível
        if not self._verificar_gemini_obrigatorio():
            raise RuntimeError(" Sistema requer Gemini AI ativo. Configure a chave API no config/default.yaml")
        
        # Módulos disponíveis (carregados dinamicamente)
        self.modulos_disponiveis = {}
        self._carregar_modulos()
        
        # Configurações do loop
        self.max_iteracoes = 50
        self.min_intervalo_iteracao = 2
        
        self.logger.info("Orquestrador Inteligente inicializado")
        self.logger.info(f"Módulos disponíveis: {list(self.modulos_disponiveis.keys())}")

    def _verificar_gemini_obrigatorio(self) -> bool:
        """
        Verifica se Gemini está configurado e funcionando (OBRIGATÓRIO)
        Returns:
            bool: True se Gemini está ativo, False caso contrário
        """
        try:
            self.logger.info(" Verificando Gemini AI (OBRIGATÓRIO)...")
            
            # Tentar conectar
            if not self.decisao_ia.conectar_gemini():
                self.logger.error(" Falha ao conectar com Gemini AI")
                return False
            
            # Testar uma consulta simples
            teste_prompt = "Responda apenas: TESTE_OK"
            resposta = self.decisao_ia._executar_consulta_gemini(teste_prompt)
            
            if resposta and "TESTE_OK" in resposta:
                self.logger.info(" Gemini AI verificado e funcionando!")
                return True
            else:
                self.logger.error(" Gemini AI não respondeu corretamente ao teste")
                return False
                
        except Exception as e:
            self.logger.error(f" Erro na verificação do Gemini: {str(e)}")
            return False

    def _carregar_modulos(self):
        """Carrega dinamicamente todos os módulos disponíveis"""
        try:
            # Módulos de varredura web
            from modulos.varredura_feroxbuster import VarreduraFeroxbuster
            from modulos.varredura_nikto import VarreduraNikto
            from modulos.varredura_whatweb import VarreduraWhatWeb
            from modulos.varredura_nuclei import VarreduraNuclei
            
            # Módulos de descoberta
            from modulos.varredura_subfinder import VarreduraSubfinder
            from modulos.varredura_sublist3r import VarreduraSublist3r
            
            # Módulos de exploração
            from modulos.varredura_sqlmap import VarreduraSQLMap
            from modulos.varredura_searchsploit import VarreduraSearchSploit
            
            # Módulos de scanner
            from modulos.scanner_vulnerabilidades import ScannerVulnerabilidades
            from modulos.scanner_web_avancado import ScannerWebAvancado
            
            # Módulos especializados (ZAP e OpenVAS removidos)
            
            # Instanciar módulos
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
                
                # Módulos Nmap
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
            # Carregar módulos básicos
            self.modulos_disponiveis = {
                'nmap_varredura_basica': self.scanner_nmap,
                'nmap_varredura_completa': self.scanner_nmap,
                'nmap_varredura_vulnerabilidades': self.scanner_nmap,
            }

    def executar_pentest_inteligente(self, alvo: str) -> Dict[str, Any]:
        """
        Executa pentest com loop inteligente baseado em IA
        
        Args:
            alvo (str): Alvo (domínio ou IP) para analisar
            
        Returns:
            Dict[str, Any]: Resultados completos do pentest
        """
        self.logger.info(f" Iniciando pentest inteligente para {alvo}")
        
        # Iniciar sessão de histórico
        try:
            sessao_id = self.decisao_ia.historico.iniciar_sessao(alvo, "pentest_inteligente")
            self.logger.info(f" Sessão de histórico iniciada: {sessao_id}")
        except Exception as e:
            self.logger.warning(f"Erro ao iniciar sessão de histórico: {e}")
        
        # Inicializar contexto
        contexto = ContextoExecucao(
            alvo_original=alvo,
            timestamp_inicio=datetime.now().isoformat()
        )
        
        try:
            # Fase 1: Resolução DNS
            self.logger.info("=== FASE 1: Resolução DNS ===")
            resultado_dns = self._executar_resolucao_dns(alvo, contexto)
            
            if not resultado_dns.get('sucesso'):
                return self._finalizar_com_erro(contexto, f"Falha na resolução DNS: {resultado_dns.get('erro')}")
            
            # Fase 2: Scan inicial de portas (RustScan)
            self.logger.info("=== FASE 2: Scan Inicial de Portas ===")
            resultado_scan = self._executar_scan_inicial(contexto)
            
            if not resultado_scan.get('sucesso'):
                return self._finalizar_com_erro(contexto, f"Falha no scan inicial: {resultado_scan.get('erro')}")
            
            # Fase 3: Loop inteligente
            self.logger.info("=== FASE 3: Loop Inteligente ===")
            resultado_loop = self._executar_loop_inteligente(contexto)
            
            # Fase 4: Finalização
            self.logger.info("=== FASE 4: Finalização ===")
            resultado_final = self._finalizar_pentest(contexto)
            
            self.logger.info(" Pentest inteligente concluído com sucesso!")
            return resultado_final
            
        except Exception as e:
            self.logger.error(f"Erro crítico no pentest: {str(e)}")
            return self._finalizar_com_erro(contexto, f"Erro crítico: {str(e)}")

    def _executar_resolucao_dns(self, alvo: str, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Executa resolução DNS e atualiza contexto"""
        try:
            resultado_dns = self.resolver_dns.resolver_dns(alvo)
            
            if resultado_dns.get('sucesso'):
                # Extrair IPs descobertos
                ips_para_scan = extrair_ips_para_scan(resultado_dns)
                contexto.ips_descobertos = ips_para_scan
                
                # Armazenar resultado
                contexto.resultados_por_modulo['resolucao_dns'] = resultado_dns
                contexto.modulos_executados.append('resolucao_dns')
                
                self.logger.info(f"✓ DNS resolvido: {len(ips_para_scan)} IPs descobertos")
                
            return resultado_dns
            
        except Exception as e:
            self.logger.error(f"Erro na resolução DNS: {str(e)}")
            return {'sucesso': False, 'erro': f'Erro na resolução DNS: {str(e)}'}

    def _executar_scan_inicial(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Executa scan inicial de portas com RustScan"""
        try:
            if not contexto.ips_descobertos:
                return {'sucesso': False, 'erro': 'Nenhum IP disponível para scan'}
            
            resultados_scan = {}
            
            for ip in contexto.ips_descobertos:
                self.logger.info(f" Escaneando portas em {ip}")
                resultado_scan = self.scanner_portas.varredura_completa(ip)
                resultados_scan[ip] = resultado_scan
                
                if resultado_scan.get('sucesso'):
                    # Extrair portas abertas
                    portas_abertas = self._extrair_portas_abertas(resultado_scan)
                    contexto.portas_abertas[ip] = portas_abertas
                    
                    self.logger.info(f"✓ {len(portas_abertas)} portas abertas em {ip}")
                else:
                    self.logger.warning(f" Falha no scan de {ip}")
            
            # Armazenar resultados
            contexto.resultados_por_modulo['scan_inicial'] = resultados_scan
            contexto.modulos_executados.append('scan_inicial')
            
            # Calcular pontuação inicial de risco
            contexto.pontuacao_risco = self._calcular_pontuacao_risco(contexto)
            
            return {'sucesso': True, 'resultados': resultados_scan}
            
        except Exception as e:
            self.logger.error(f"Erro no scan inicial: {str(e)}")
            return {'sucesso': False, 'erro': f'Erro no scan inicial: {str(e)}'}

    def _executar_loop_inteligente(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Executa o loop inteligente principal"""
        iteracao = 0
        
        while not contexto.finalizado and iteracao < self.max_iteracoes:
            iteracao += 1
            self.logger.info(f" Iteração {iteracao} do loop inteligente")
            
            try:
                # IA analisa contexto atual e decide próximo passo
                decisao_ia = self._consultar_ia_proximos_passos(contexto)
                contexto.decisoes_ia.append(decisao_ia)
                
                acao = decisao_ia.get('acao', 'parar')
                self.logger.info(f" IA decidiu: {acao}")
                
                if acao == 'parar':
                    contexto.finalizado = True
                    contexto.motivo_finalizacao = decisao_ia.get('justificativa', 'IA decidiu parar')
                    self.logger.info(f" IA decidiu parar: {contexto.motivo_finalizacao}")
                    break
                
                elif acao == 'executar_modulo':
                    modulo_escolhido = decisao_ia.get('modulo', '')
                    
                    if modulo_escolhido in self.modulos_disponiveis:
                        # Executar módulo escolhido
                        resultado_modulo = self._executar_modulo(modulo_escolhido, contexto, decisao_ia)
                        
                        # Atualizar contexto com resultados
                        self._atualizar_contexto_com_resultado(contexto, modulo_escolhido, resultado_modulo)
                        
                        # Recalcular pontuação de risco
                        contexto.pontuacao_risco = self._calcular_pontuacao_risco(contexto)
                        
                    else:
                        # Mapear nomes de categoria para módulos específicos
                        modulo_mapeado = self._mapear_categoria_para_modulo(modulo_escolhido)
                        if modulo_mapeado:
                            self.logger.info(f" Mapeando '{modulo_escolhido}' → {modulo_mapeado}")
                            resultado_modulo = self._executar_modulo(modulo_mapeado, contexto, decisao_ia)
                            self._atualizar_contexto_com_resultado(contexto, modulo_mapeado, resultado_modulo)
                            contexto.pontuacao_risco = self._calcular_pontuacao_risco(contexto)
                        else:
                            self.logger.warning(f" Módulo desconhecido: {modulo_escolhido}")
                
                elif acao == 'parar':
                    contexto.finalizado = True
                    contexto.motivo_finalizacao = decisao_ia.get('justificativa', 'IA decidiu parar')
                    self.logger.info(f" IA decidiu parar: {contexto.motivo_finalizacao}")
                    break
                
                else:
                    self.logger.warning(f" Ação desconhecida da IA: {acao}")
                
            except RuntimeError as e:
                # Erro crítico da IA - sistema deve parar
                self.logger.error(f" ERRO CRÍTICO: {str(e)}")
                contexto.finalizado = True
                contexto.motivo_finalizacao = f"Erro crítico da IA: {str(e)}"
                break
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
        """Consulta IA para decidir próximos passos baseado no contexto atual (OBRIGATÓRIO)"""
        try:
            # Preparar contexto completo para análise
            contexto_completo = self._montar_contexto_completo(contexto)
            
            # Criar contexto seguro para IA (anonimizar IPs)
            contexto_seguro = criar_contexto_seguro_para_ia(contexto_completo)
            
            # Preparar prompt universal com contexto seguro
            prompt_contexto = self._gerar_prompt_contexto_completo_seguro(contexto_seguro, contexto)
            
            # Template de prompt universal
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
- Para alvos, use sempre "use_alvos_descobertos" - o sistema aplicará aos IPs reais
- Considere os resultados anteriores para não repetir análises desnecessárias
- Pare quando tiver informações suficientes ou não houver mais descobertas úteis
- Priorize módulos que podem revelar vulnerabilidades críticas
"""
            
            # Enviar para IA (OBRIGATÓRIO - sem fallback)
            self.logger.info("🔒 Consultando Gemini AI com contexto seguro...")
            resposta_ia = self.decisao_ia._executar_consulta_gemini(prompt_universal, "decisao_loop_seguro")
            
            if not resposta_ia:
                raise RuntimeError(" Gemini AI não retornou resposta válida")
            
            decisao = self._parsear_decisao_ia_loop(resposta_ia)
            if not decisao:
                raise RuntimeError(" Não foi possível parsear resposta da IA")
            
            self.logger.info(f"🧠 IA decidiu: {decisao.get('acao', 'N/A')}")
            
            # Log de segurança
            self.logger.info("🔒 Contexto enviado com IPs anonimizados - privacidade preservada")
            
            return decisao
            
        except Exception as e:
            self.logger.error(f"💥 ERRO CRÍTICO na consulta IA: {str(e)}")
            # SEM FALLBACK - sistema deve parar se IA falhar
            raise RuntimeError(f"Sistema requer IA funcional. Erro: {str(e)}")
    
    def _montar_contexto_completo(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Monta contexto completo para análise"""
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
                modulo: resultado for modulo, resultado in 
                list(contexto.resultados_por_modulo.items())[-3:]  # Últimos 3 resultados
            }
        }
    
    def _gerar_prompt_contexto_completo_seguro(self, contexto_seguro: Dict[str, Any], contexto_original: ContextoExecucao) -> str:
        """Gera prompt com contexto seguro para IA"""
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
            for vuln in vulnerabilidades[-3:]:  # Últimas 3
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
        
        # Adicionar aviso sobre anonimização
        prompt += f"\n📋 INFORMAÇÕES DE SEGURANÇA:\n"
        aviso = contexto_seguro.get('_aviso_anonimizacao', {})
        if aviso:
            prompt += f"  • {aviso.get('status', 'IPs anonimizados')}\n"
            prompt += f"  • {aviso.get('preservado', 'Estrutura mantida')}\n"
            prompt += f"  • Total anonimizado: {aviso.get('total_anonimizado', 0)}\n"
        
        return prompt

    def _listar_modulos_disponiveis(self) -> str:
        """Lista módulos disponíveis para o prompt"""
        categorias = {
            'Varredura Web': [
                'feroxbuster_basico', 'feroxbuster_recursivo', 'nikto_scan', 
                'whatweb_scan', 'nuclei_scan'
            ],
            'Descoberta de Subdomínios': [
                'subfinder_enum', 'sublist3r_enum'
            ],
            'Exploração': [
                'sqlmap_teste_url', 'sqlmap_teste_formulario', 'searchsploit_check'
            ],
            'Scanner de Vulnerabilidades': [
                'scanner_vulnerabilidades', 'scanner_web_avancado'
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
        """
        Mapeia categorias ou nomes genéricos da IA para módulos específicos disponíveis
        """
        nome_lower = nome_categoria.lower().strip()
        
        # Mapeamento direto de categorias para módulos preferenciais
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
            'nmap': 'nmap_varredura_completa',
            'nmap completo': 'nmap_varredura_completa',
            'scan de vulnerabilidades': 'scanner_vulnerabilidades',
            'scanner de vulnerabilidades': 'scanner_vulnerabilidades',
            'sqlmap': 'sqlmap_teste_url',
            'subfinder': 'subfinder_enum',
            'sublist3r': 'sublist3r_enum',
        }
        
        # Busca direta no mapeamento
        if nome_lower in mapeamento_categorias:
            modulo_mapeado = mapeamento_categorias[nome_lower]
            if modulo_mapeado in self.modulos_disponiveis:
                return modulo_mapeado
        
        # Se não encontrou, retorna None
        return None

    def _parsear_decisao_ia_loop(self, resposta_ia: str) -> Optional[Dict[str, Any]]:
        """Parseia decisão da IA para o loop"""
        try:
            # Extrair JSON da resposta
            resposta_limpa = resposta_ia.strip()
            inicio_json = resposta_limpa.find('{')
            fim_json = resposta_limpa.rfind('}') + 1
            
            if inicio_json >= 0 and fim_json > inicio_json:
                json_str = resposta_limpa[inicio_json:fim_json]
                decisao = json.loads(json_str)
                
                # Validar campos obrigatórios
                if 'acao' in decisao and 'justificativa' in decisao:
                    return decisao
            
            return None
            
        except json.JSONDecodeError as e:
            self.logger.warning(f"Erro ao parsear JSON da IA: {str(e)}")
            return None



    def _executar_modulo(self, nome_modulo: str, contexto: ContextoExecucao, decisao_ia: Dict) -> Dict[str, Any]:
        """Executa um módulo específico"""
        self.logger.info(f"⚡ Executando módulo: {nome_modulo}")
        
        try:
            modulo = self.modulos_disponiveis[nome_modulo]
            alvos_ia = decisao_ia.get('alvos', [])
            parametros = decisao_ia.get('parametros', {})
            
            # Processar alvos: converter alvos anonimizados ou especiais para reais
            alvos_reais = self._resolver_alvos_para_execucao(alvos_ia, contexto)
            
            resultados = {}
            
            for alvo in alvos_reais:
                try:
                    self.logger.info(f"   Executando {nome_modulo} em {alvo}")
                    
                    # Executar baseado no tipo de módulo
                    if nome_modulo.startswith('nmap_'):
                        resultado = self._executar_modulo_nmap(nome_modulo, alvo, modulo, parametros)
                    elif nome_modulo.startswith('feroxbuster_'):
                        resultado = self._executar_modulo_feroxbuster(nome_modulo, alvo, modulo, parametros)
                    elif nome_modulo.startswith('sqlmap_'):
                        resultado = self._executar_modulo_sqlmap(nome_modulo, alvo, modulo, parametros)
                    elif nome_modulo.startswith('scanner_'):
                        resultado = self._executar_modulo_scanner(nome_modulo, alvo, modulo, parametros)
                    else:
                        # Módulos genéricos
                        resultado = self._executar_modulo_generico(nome_modulo, alvo, modulo, parametros)
                    
                    resultados[alvo] = resultado
                    
                    if resultado.get('sucesso'):
                        self.logger.info(f"  ✅ {nome_modulo} executado com sucesso em {alvo}")
                    else:
                        self.logger.warning(f"  ⚠️ Falha em {nome_modulo} para {alvo}: {resultado.get('erro')}")
                
                except Exception as e:
                    self.logger.error(f"Erro ao executar {nome_modulo} em {alvo}: {str(e)}")
                    resultados[alvo] = {
                        'sucesso': False,
                        'erro': f'Erro na execução: {str(e)}',
                        'timestamp': datetime.now().isoformat()
                    }
            
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
            return {
                'nome_modulo': nome_modulo,
                'sucesso_geral': False,
                'erro': f'Erro crítico: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    def _resolver_alvos_para_execucao(self, alvos_ia: List[str], contexto: ContextoExecucao) -> List[str]:
        """
        Resolve alvos da IA para alvos reais de execução
        Args:
            alvos_ia (List[str]): Alvos indicados pela IA (podem ser anonimizados ou especiais)
            contexto (ContextoExecucao): Contexto com IPs reais
        Returns:
            List[str]: Lista de alvos reais para execução
        """
        if not alvos_ia:
            # Se IA não especificou alvos, usar IPs descobertos
            return contexto.ips_descobertos
        
        alvos_reais = []
        
        for alvo_ia in alvos_ia:
            if alvo_ia == "use_alvos_descobertos":
                # Comando especial para usar todos os IPs descobertos
                alvos_reais.extend(contexto.ips_descobertos)
            elif alvo_ia.startswith("[") and alvo_ia.endswith("]"):
                # IP foi removido/anonimizado - usar todos os IPs descobertos como fallback
                self.logger.warning(f"Alvo anonimizado detectado: {alvo_ia}, usando todos os IPs descobertos")
                alvos_reais.extend(contexto.ips_descobertos)
            else:
                # Tentar usar o alvo diretamente (pode ser IP anonimizado válido)
                # Neste caso, precisaríamos de um mapeamento reverso, mas para simplificar
                # vamos usar os IPs descobertos
                self.logger.info(f"Resolvendo alvo da IA: {alvo_ia} → usando IPs descobertos")
                alvos_reais.extend(contexto.ips_descobertos)
        
        # Remover duplicatas mantendo ordem
        alvos_unicos = []
        for alvo in alvos_reais:
            if alvo not in alvos_unicos:
                alvos_unicos.append(alvo)
        
        # Garantir que temos pelo menos um alvo
        if not alvos_unicos:
            alvos_unicos = contexto.ips_descobertos
        
        self.logger.info(f"🎯 Alvos resolvidos: {len(alvos_unicos)} IPs → {', '.join(alvos_unicos[:3])}{'...' if len(alvos_unicos) > 3 else ''}")
        
        return alvos_unicos

    def _executar_modulo_nmap(self, nome_modulo: str, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        """Executa módulos Nmap específicos"""
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
        else:
            return {'sucesso': False, 'erro': f'Método não encontrado para {nome_modulo}'}

    def _executar_modulo_feroxbuster(self, nome_modulo: str, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        """Executa módulos Feroxbuster"""
        # Construir URL se necessário
        if not alvo.startswith('http'):
            url = f"http://{alvo}"
        else:
            url = alvo
        
        if nome_modulo == 'feroxbuster_basico':
            return modulo.varredura_basica(url, **parametros)
        elif nome_modulo == 'feroxbuster_recursivo':
            return modulo.varredura_recursiva(url, **parametros)
        else:
            return {'sucesso': False, 'erro': f'Método não encontrado para {nome_modulo}'}

    def _executar_modulo_sqlmap(self, nome_modulo: str, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        """Executa módulos SQLMap"""
        if not alvo.startswith('http'):
            url = f"http://{alvo}"
        else:
            url = alvo
        
        if nome_modulo == 'sqlmap_teste_url':
            return modulo.testar_url(url, **parametros)
        elif nome_modulo == 'sqlmap_teste_formulario':
            return modulo.testar_formulario(url, **parametros)
        else:
            return {'sucesso': False, 'erro': f'Método não encontrado para {nome_modulo}'}

    def _executar_modulo_scanner(self, nome_modulo: str, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        """Executa módulos de scanner"""
        try:
            if nome_modulo == 'scanner_vulnerabilidades':
                # Obter portas abertas do contexto se disponível
                portas_abertas = parametros.get('portas_abertas', None)
                return modulo.scan_vulnerabilidades(alvo, portas_abertas)
            elif nome_modulo == 'scanner_web_avancado':
                # Construir URL se necessário
                if not alvo.startswith('http'):
                    url = f"http://{alvo}"
                else:
                    url = alvo

                # Executar o scanner
                resultado_scanner = modulo.scan_completo(url)

                # Verificar se o scanner retornou erro
                if 'erro' in resultado_scanner:
                    return {
                        'sucesso': False,
                        'erro': resultado_scanner['erro'],
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    # Scanner executado com sucesso
                    return {
                        'sucesso': True,
                        'dados': resultado_scanner,
                        'timestamp': datetime.now().isoformat()
                    }
            else:
                return {'sucesso': False, 'erro': f'Scanner não implementado: {nome_modulo}'}
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro no scanner: {str(e)}'}

    def _executar_modulo_generico(self, nome_modulo: str, alvo: str, modulo, parametros: Dict) -> Dict[str, Any]:
        """Executa módulos genéricos baseado em convenções"""
        try:
            # Tentar métodos padrão
            if hasattr(modulo, 'executar'):
                return modulo.executar(alvo, **parametros)
            elif hasattr(modulo, 'scan'):
                return modulo.scan(alvo, **parametros)
            elif hasattr(modulo, 'varredura'):
                return modulo.varredura(alvo, **parametros)
            elif hasattr(modulo, 'analise'):
                return modulo.analise(alvo, **parametros)
            else:
                return {'sucesso': False, 'erro': f'Método de execução não encontrado para {nome_modulo}'}
                
        except Exception as e:
            return {'sucesso': False, 'erro': f'Erro na execução genérica: {str(e)}'}

    def _atualizar_contexto_com_resultado(self, contexto: ContextoExecucao, nome_modulo: str, resultado: Dict):
        """Atualiza contexto com resultados do módulo executado"""
        try:
            # Adicionar módulo à lista de executados
            contexto.modulos_executados.append(nome_modulo)
            contexto.resultados_por_modulo[nome_modulo] = resultado
            
            # Extrair informações específicas baseado no tipo de resultado
            if resultado.get('sucesso'):
                
                # Extrair novos serviços descobertos
                servicos = self._extrair_servicos_do_resultado(resultado)
                for ip, servicos_ip in servicos.items():
                    if ip not in contexto.servicos_detectados:
                        contexto.servicos_detectados[ip] = {}
                    contexto.servicos_detectados[ip].update(servicos_ip)
                
                # Extrair vulnerabilidades
                vulnerabilidades = self._extrair_vulnerabilidades_do_resultado(resultado)
                contexto.vulnerabilidades_encontradas.extend(vulnerabilidades)
                
                # Extrair novas portas (se aplicável)
                novas_portas = self._extrair_portas_do_resultado(resultado)
                for ip, portas in novas_portas.items():
                    if ip in contexto.portas_abertas:
                        # Adicionar novas portas sem duplicatas
                        contexto.portas_abertas[ip] = list(set(contexto.portas_abertas[ip] + portas))
                    else:
                        contexto.portas_abertas[ip] = portas
            
            self.logger.info(f"   Contexto atualizado com resultados de {nome_modulo}")
            
        except Exception as e:
            self.logger.error(f"Erro ao atualizar contexto: {str(e)}")

    def _extrair_portas_abertas(self, resultado_scan: Dict) -> List[int]:
        """Extrai portas abertas de resultado de scan"""
        portas = []
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
        """Extrai serviços descobertos de um resultado"""
        servicos = {}
        try:
            for alvo, resultado_alvo in resultado.get('resultados_por_alvo', {}).items():
                dados = resultado_alvo.get('dados', {})
                
                # Nmap format
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
                
                # Outros formatos podem ser adicionados aqui
                
        except Exception as e:
            self.logger.warning(f"Erro ao extrair serviços: {str(e)}")
        
        return servicos

    def _extrair_vulnerabilidades_do_resultado(self, resultado: Dict) -> List[Dict]:
        """Extrai vulnerabilidades de um resultado"""
        vulnerabilidades = []
        try:
            for alvo, resultado_alvo in resultado.get('resultados_por_alvo', {}).items():
                dados = resultado_alvo.get('dados', {})

                # Scripts NSE de vulnerabilidades
                if 'hosts' in dados:
                    for host in dados['hosts']:
                        ip = host.get('endereco', alvo)

                        # Scripts de host
                        for script in host.get('scripts', []):
                            if 'vuln' in script.get('id', '').lower():
                                vulnerabilidades.append({
                                    'ip': ip,
                                    'tipo': 'host',
                                    'script': script.get('id'),
                                    'descricao': script.get('saida', ''),
                                    'fonte': resultado.get('nome_modulo', 'unknown')
                                })

                        # Scripts de portas
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

                # Outras ferramentas
                if 'vulnerabilidades' in dados:
                    for vuln in dados['vulnerabilidades']:
                        vulnerabilidades.append({
                            'ip': alvo,
                            'tipo': vuln.get('tipo', 'unknown'),
                            'descricao': vuln.get('descricao', ''),
                            'severidade': vuln.get('severidade', 'unknown'),
                            'fonte': resultado.get('nome_modulo', 'unknown')
                        })

            # Suporte específico para scanner_web_avancado
            if resultado.get('nome_modulo') == 'scanner_web_avancado':
                # Verificar se há dados diretos do scanner (formato antigo)
                dados_diretos = resultado.get('dados', {})
                if 'vulnerabilidades' in dados_diretos:
                    for vuln in dados_diretos['vulnerabilidades']:
                        vulnerabilidades.append({
                            'ip': dados_diretos.get('url_base', 'unknown').replace('http://', '').replace('https://', '').split('/')[0],
                            'tipo': 'web',
                            'titulo': vuln.get('titulo', 'Vulnerabilidade Web'),
                            'descricao': vuln.get('descricao', ''),
                            'criticidade': vuln.get('criticidade', 'BAIXA'),
                            'url': vuln.get('url', ''),
                            'fonte': 'scanner_web_avancado'
                        })

        except Exception as e:
            self.logger.warning(f"Erro ao extrair vulnerabilidades: {str(e)}")

        return vulnerabilidades

    def _extrair_portas_do_resultado(self, resultado: Dict) -> Dict[str, List[int]]:
        """Extrai novas portas descobertas"""
        portas = {}
        try:
            for alvo, resultado_alvo in resultado.get('resultados_por_alvo', {}).items():
                portas_alvo = self._extrair_portas_abertas(resultado_alvo)
                if portas_alvo:
                    portas[alvo] = portas_alvo
        except Exception as e:
            self.logger.warning(f"Erro ao extrair portas do resultado: {str(e)}")
        
        return portas

    def _calcular_pontuacao_risco(self, contexto: ContextoExecucao) -> int:
        """Calcula pontuação de risco baseada no contexto atual"""
        pontuacao = 0
        
        try:
            # Pontuação base por portas abertas
            total_portas = sum(len(portas) for portas in contexto.portas_abertas.values())
            pontuacao += min(total_portas * 2, 30)  # Máximo 30 pontos
            
            # Pontuação por serviços críticos
            servicos_criticos = ['ssh', 'ftp', 'telnet', 'smb', 'rdp', 'mysql', 'postgresql']
            for ip, servicos in contexto.servicos_detectados.items():
                for porta, info in servicos.items():
                    servico = info.get('servico', '').lower()
                    if any(critico in servico for critico in servicos_criticos):
                        pontuacao += 10
            
            # Pontuação por vulnerabilidades
            pontuacao += len(contexto.vulnerabilidades_encontradas) * 15
            
            # Pontuação por serviços web
            servicos_web = 0
            for ip, portas in contexto.portas_abertas.items():
                servicos_web += len([p for p in portas if p in [80, 443, 8080, 8000, 8443]])
            pontuacao += servicos_web * 5
            
            # Limitar a 100
            pontuacao = min(pontuacao, 100)
            
        except Exception as e:
            self.logger.warning(f"Erro ao calcular pontuação de risco: {str(e)}")
            pontuacao = 0
        
        return pontuacao

    def _calcular_tempo_decorrido(self, contexto: ContextoExecucao) -> str:
        """Calcula tempo decorrido desde o início"""
        try:
            inicio = datetime.fromisoformat(contexto.timestamp_inicio)
            agora = datetime.now()
            delta = agora - inicio
            
            minutos = int(delta.total_seconds() / 60)
            if minutos < 60:
                return f"{minutos} minutos"
            else:
                horas = minutos // 60
                min_restantes = minutos % 60
                return f"{horas}h{min_restantes}m"
                
        except Exception:
            return "N/A"

    def _finalizar_pentest(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Finaliza pentest e gera resultado consolidado"""
        timestamp_fim = datetime.now().isoformat()
        
        # Gerar resumo final
        resumo_final = {
            'alvo_original': contexto.alvo_original,
            'timestamp_inicio': contexto.timestamp_inicio,
            'timestamp_fim': timestamp_fim,
            'tempo_total': self._calcular_tempo_decorrido(contexto),
            'sucesso_geral': any(
                resultado.get('sucesso', False) 
                for resultado in contexto.resultados_por_modulo.values()
                if isinstance(resultado, dict)
            ),
            
            # Estatísticas gerais
            'estatisticas': {
                'ips_descobertos': len(contexto.ips_descobertos),
                'total_portas_abertas': sum(len(portas) for portas in contexto.portas_abertas.values()),
                'servicos_detectados': sum(len(servicos) for servicos in contexto.servicos_detectados.values()),
                'vulnerabilidades_encontradas': len(contexto.vulnerabilidades_encontradas),
                'modulos_executados': len(contexto.modulos_executados),
                'pontuacao_risco_final': contexto.pontuacao_risco
            },
            
            # Contexto completo
            'contexto_execucao': {
                'ips_descobertos': contexto.ips_descobertos,
                'portas_abertas': contexto.portas_abertas,
                'servicos_detectados': contexto.servicos_detectados,
                'vulnerabilidades_encontradas': contexto.vulnerabilidades_encontradas,
                'modulos_executados': contexto.modulos_executados,
                'motivo_finalizacao': contexto.motivo_finalizacao
            },
            
            # Resultados detalhados
            'resultados_por_modulo': contexto.resultados_por_modulo,
            'decisoes_ia': contexto.decisoes_ia,
            
            # Resumos e análises
            'resumo_dns': self._gerar_resumo_dns(contexto),
            'resumo_scan': self._gerar_resumo_scan_final(contexto),
            'analise_vulnerabilidades': self._gerar_analise_vulnerabilidades(contexto),
            'recomendacoes_finais': self._gerar_recomendacoes_finais(contexto)
        }
        
        # Log da sessão
        log_manager.log_sessao_pentest('pentest_inteligente', {
            'alvo': contexto.alvo_original,
            'ips_descobertos': len(contexto.ips_descobertos),
            'modulos_executados': len(contexto.modulos_executados),
            'vulnerabilidades': len(contexto.vulnerabilidades_encontradas),
            'pontuacao_risco': contexto.pontuacao_risco,
            'tempo_total_min': int((datetime.fromisoformat(timestamp_fim) - 
                                   datetime.fromisoformat(contexto.timestamp_inicio)).total_seconds() / 60)
        })
        
        self.logger.info(f" Estatísticas finais:")
        self.logger.info(f"  • IPs: {resumo_final['estatisticas']['ips_descobertos']}")
        self.logger.info(f"  • Portas: {resumo_final['estatisticas']['total_portas_abertas']}")
        self.logger.info(f"  • Serviços: {resumo_final['estatisticas']['servicos_detectados']}")
        self.logger.info(f"  • Vulnerabilidades: {resumo_final['estatisticas']['vulnerabilidades_encontradas']}")
        self.logger.info(f"  • Módulos: {resumo_final['estatisticas']['modulos_executados']}")
        self.logger.info(f"  • Risco: {resumo_final['estatisticas']['pontuacao_risco_final']}/100")
        
        # Finalizar sessão de histórico
        try:
            arquivo_historico = self.decisao_ia.historico.finalizar_sessao(resumo_final)
            if arquivo_historico:
                self.logger.info(f" Histórico salvo: {arquivo_historico}")
        except Exception as e:
            self.logger.warning(f"Erro ao finalizar sessão de histórico: {e}")
        
        return resumo_final

    def _gerar_resumo_dns(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Gera resumo da resolução DNS"""
        resultado_dns = contexto.resultados_por_modulo.get('resolucao_dns', {})
        
        if hasattr(self.resolver_dns, 'gerar_resumo'):
            return self.resolver_dns.gerar_resumo(resultado_dns)
        else:
            return {
                'ips_descobertos': len(contexto.ips_descobertos),
                'ips_list': contexto.ips_descobertos
            }

    def _gerar_resumo_scan_final(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Gera resumo final do scan"""
        return {
            'total_ips_scaneados': len(contexto.ips_descobertos),
            'hosts_ativos': len([ip for ip, portas in contexto.portas_abertas.items() if portas]),
            'total_portas_abertas': sum(len(portas) for portas in contexto.portas_abertas.values()),
            'hosts_com_portas_abertas': [
                {
                    'ip': ip,
                    'portas': portas,
                    'portas_abertas': len(portas)
                }
                for ip, portas in contexto.portas_abertas.items() if portas
            ],
            'portas_mais_comuns': self._calcular_portas_mais_comuns(contexto),
            'servicos_mais_comuns': self._calcular_servicos_mais_comuns(contexto)
        }

    def _calcular_portas_mais_comuns(self, contexto: ContextoExecucao) -> List[Dict]:
        """Calcula estatísticas de portas mais comuns"""
        contador_portas = {}
        
        for ip, portas in contexto.portas_abertas.items():
            for porta in portas:
                contador_portas[porta] = contador_portas.get(porta, 0) + 1
        
        portas_ordenadas = sorted(contador_portas.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {'porta': porta, 'ocorrencias': count}
            for porta, count in portas_ordenadas[:10]
        ]

    def _calcular_servicos_mais_comuns(self, contexto: ContextoExecucao) -> List[Dict]:
        """Calcula estatísticas de serviços mais comuns"""
        contador_servicos = {}
        
        for ip, servicos in contexto.servicos_detectados.items():
            for porta, info in servicos.items():
                servico = info.get('servico', 'unknown')
                contador_servicos[servico] = contador_servicos.get(servico, 0) + 1
        
        servicos_ordenados = sorted(contador_servicos.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {'servico': servico, 'ocorrencias': count}
            for servico, count in servicos_ordenados[:10]
        ]

    def _gerar_analise_vulnerabilidades(self, contexto: ContextoExecucao) -> Dict[str, Any]:
        """Gera análise das vulnerabilidades encontradas"""
        if not contexto.vulnerabilidades_encontradas:
            return {
                'total': 0,
                'por_criticidade': {},
                'por_tipo': {},
                'recomendacoes': ['Nenhuma vulnerabilidade específica encontrada']
            }
        
        # Classificar por criticidade (baseado em palavras-chave)
        criticidade = {'critica': 0, 'alta': 0, 'media': 0, 'baixa': 0}
        tipos = {}
        
        for vuln in contexto.vulnerabilidades_encontradas:
            descricao = vuln.get('descricao', '').lower()
            
            # Classificar criticidade
            if any(termo in descricao for termo in ['remote code execution', 'rce', 'sql injection']):
                criticidade['critica'] += 1
            elif any(termo in descricao for termo in ['xss', 'directory traversal', 'authentication']):
                criticidade['alta'] += 1
            elif any(termo in descricao for termo in ['information disclosure', 'ssl']):
                criticidade['media'] += 1
            else:
                criticidade['baixa'] += 1
            
            # Classificar por tipo
            tipo = vuln.get('script', vuln.get('tipo', 'unknown'))
            tipos[tipo] = tipos.get(tipo, 0) + 1
        
        return {
            'total': len(contexto.vulnerabilidades_encontradas),
            'por_criticidade': criticidade,
            'por_tipo': tipos,
            'detalhes': contexto.vulnerabilidades_encontradas[-5:],  # Últimas 5
            'recomendacoes': self._gerar_recomendacoes_vulnerabilidades(contexto.vulnerabilidades_encontradas)
        }

    def _gerar_recomendacoes_vulnerabilidades(self, vulnerabilidades: List[Dict]) -> List[str]:
        """Gera recomendações baseadas nas vulnerabilidades"""
        recomendacoes = []
        
        # Análise básica baseada em tipos comuns
        tipos_encontrados = [v.get('script', v.get('tipo', '')) for v in vulnerabilidades]
        
        if any('ssl' in tipo.lower() for tipo in tipos_encontrados):
            recomendacoes.append("Atualizar configurações SSL/TLS")
        
        if any('ftp' in tipo.lower() for tipo in tipos_encontrados):
            recomendacoes.append("Revisar configurações de FTP")
        
        if any('ssh' in tipo.lower() for tipo in tipos_encontrados):
            recomendacoes.append("Hardening do SSH")
        
        if any('http' in tipo.lower() for tipo in tipos_encontrados):
            recomendacoes.append("Revisar configurações de servidor web")
        
        if not recomendacoes:
            recomendacoes.append("Investigar vulnerabilidades específicas encontradas")
        
        return recomendacoes

    def _gerar_recomendacoes_finais(self, contexto: ContextoExecucao) -> List[str]:
        """Gera recomendações finais baseadas em todo o contexto"""
        recomendacoes = []
        
        # Baseado na pontuação de risco
        if contexto.pontuacao_risco >= 70:
            recomendacoes.append("🔴 RISCO ALTO: Ação imediata necessária")
            recomendacoes.append("Investigar e corrigir vulnerabilidades críticas")
            recomendacoes.append("Implementar monitoramento contínuo")
        elif contexto.pontuacao_risco >= 40:
            recomendacoes.append("🟡 RISCO MÉDIO: Revisão necessária")
            recomendacoes.append("Planejar correções de vulnerabilidades")
            recomendacoes.append("Revisar configurações de segurança")
        else:
            recomendacoes.append("🟢 RISCO BAIXO: Monitoramento regular")
            recomendacoes.append("Manter boas práticas de segurança")
        
        # Baseado em vulnerabilidades
        if len(contexto.vulnerabilidades_encontradas) > 0:
            recomendacoes.append(f"Corrigir {len(contexto.vulnerabilidades_encontradas)} vulnerabilidades identificadas")
        
        # Baseado em serviços
        total_servicos = sum(len(s) for s in contexto.servicos_detectados.values())
        if total_servicos > 10:
            recomendacoes.append("Revisar necessidade de todos os serviços expostos")
        
        # Recomendações gerais
        recomendacoes.extend([
            "Implementar firewall com regras restritivas",
            "Manter sistemas atualizados",
            "Implementar autenticação forte",
            "Realizar auditorias regulares de segurança"
        ])
        
        return recomendacoes[:8]  # Máximo 8 recomendações

    def _finalizar_com_erro(self, contexto: ContextoExecucao, erro: str) -> Dict[str, Any]:
        """Finaliza execução com erro"""
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
    # Teste básico do orquestrador inteligente
    from utils.logger import obter_logger
    
    logger = obter_logger('OrquestradorInteligenteCLI')
    logger.info("🧪 Teste do Orquestrador Inteligente")
    
    # Mock de módulos para teste
    class MockModulo:
        def resolver_dns(self, alvo):
            return {'sucesso': True, 'ips': ['192.168.1.100']}
        
        def varredura_completa(self, ip):
            return {'sucesso': True, 'dados': {'portas_abertas': [22, 80, 443]}}
        
        def varredura_basica(self, ip):
            return {'sucesso': True, 'dados': {'portas': [{'numero': 80, 'estado': 'open'}]}}
    
    mock = MockModulo()
    
    # Conectar ao Gemini se disponível
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
    
    orquestrador = OrquestradorInteligente(
        resolver_dns=mock,
        scanner_portas=mock,
        scanner_nmap=mock,
        decisao_ia=decisao_ia
    )
    
    logger.info("✓ Orquestrador Inteligente inicializado com sucesso!")
    logger.info(" Pronto para execução com loop adaptativo!")
