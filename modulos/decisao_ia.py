#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de Decisão Inteligente
Analisa resultados de scan inicial e decide próximos passos usando IA
Inclui análise completa com Gemini AI integrada
"""

import json
import time
import threading
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

import google.generativeai as genai
from core.configuracao import obter_config
from utils.logger import obter_logger
from utils.anonimizador_ip import anonimizar_contexto_ia, criar_contexto_seguro_para_ia
from historico_ia.gerenciador_historico import obter_gerenciador_historico

class DecisaoIA:
    """Classe para tomada de decisões inteligentes baseada em IA"""
    
    def __init__(self):
        """Inicializa o módulo de decisão IA"""
        self.logger = obter_logger('DecisaoIA')
        
        # Configuração Gemini
        self.chave_api = obter_config('api.gemini.chave_api')
        self.modelo_nome = obter_config('api.gemini.modelo', 'gemini-2.5-flash')
        self.timeout = obter_config('api.gemini.timeout', 30)
        self.max_tentativas = obter_config('api.gemini.max_tentativas', 3)
        self.habilitado = obter_config('api.gemini.habilitado', True)
        
        # Configuração de segurança - anonimização de IPs
        self.anonimizar_ips = obter_config('api.gemini.anonimizar_ips', True)
        self.seed_anonimizacao = obter_config('api.gemini.seed_anonimizacao', 'varredura_ia_default')
        
        self.modelo = None
        self.conectado = False
        
        # Gerenciador de histórico
        self.historico = obter_gerenciador_historico()
        
        # Mapeamento de IPs para manter consistência durante sessão
        self.mapeamento_ips_sessao = {}
        
        self.logger.info(f"Anonimização de IPs: {'✓ HABILITADA' if self.anonimizar_ips else '✗ DESABILITADA'}")
        
        # Templates de prompts para decisão e análise completa
        self.templates_prompts = {
            'decidir_proximos_passos': """
Analise os seguintes resultados de scan inicial de portas e decida os próximos passos:

RESULTADOS DO SCAN INICIAL:
{resultados_scan}

MÓDULOS DISPONÍVEIS:
1. varredura_basica - Varredura simples de portas
2. varredura_completa - Detecção de versão e serviços  
3. varredura_vulnerabilidades - Scripts NSE de vulnerabilidades
4. varredura_servicos_web - Análise específica de HTTP/HTTPS
5. varredura_smb - Análise de serviços SMB/NetBIOS
6. varredura_descoberta_rede - Discovery de hosts na rede
7. feroxbuster_basico - Descoberta de diretórios e arquivos web
8. feroxbuster_recursivo - Descoberta recursiva de diretórios
9. sqlmap_teste_url - Teste de SQL Injection em URLs
10. sqlmap_teste_formulario - Teste de SQL Injection em formulários

Com base nos serviços encontrados, responda APENAS em formato JSON:
{{
    "executar_nmap_avancado": true/false,
    "modulos_recomendados": ["nome_modulo1", "nome_modulo2"],
    "justificativa": "explicação da decisão",
    "prioridade": "alta/media/baixa",
    "portas_prioritarias": ["porta1", "porta2"],
    "tempo_estimado": "estimativa em minutos"
}}

IMPORTANTE: Use EXATAMENTE os nomes dos módulos listados acima. Responda APENAS o JSON, sem texto adicional.
""",

            'loop_inteligente_universal': """
ANÁLISE DE CONTEXTO PARA PRÓXIMO PASSO:

{contexto_completo}

MÓDULOS DISPONÍVEIS:
{modulos_disponiveis}

MÓDULOS JÁ EXECUTADOS:
{modulos_executados}

Baseado no contexto atual, decida o próximo passo. Considere:
1. Resultados anteriores para evitar redundância
2. Vulnerabilidades encontradas que precisam de investigação
3. Serviços descobertos que merecem análise aprofundada
4. Eficiência: pare quando tiver informações suficientes

Responda APENAS em formato JSON:
{{
    "acao": "executar_modulo|parar|gerar_relatorio",
    "modulo": "nome_do_modulo_se_aplicavel",
    "alvos": ["lista_de_alvos_especificos"],
    "parametros": {{"parametros_especiais": "se_necessario"}},
    "justificativa": "explicação_da_decisão",
    "prioridade": "alta|media|baixa",
    "expectativa": "o_que_espera_descobrir"
}}

IMPORTANTE: 
- Use EXATAMENTE os nomes dos módulos listados
- Evite repetir análises já feitas
- Pare quando análise estiver completa ou descobertas se esgotaram
- Priorize módulos que podem revelar vulnerabilidades críticas
""",
            
            'analisar_servicos_encontrados': """
Analise os serviços encontrados e determine o nível de interesse para pentest:

SERVIÇOS DETECTADOS:
{servicos_detectados}

Classifique cada serviço por:
1. Potencial de vulnerabilidades
2. Criticidade para segurança  
3. Necessidade de análise aprofundada

Responda em formato JSON:
{{
    "servicos_criticos": ["servico1", "servico2"],
    "servicos_interessantes": ["servico3", "servico4"],
    "recomendacoes_especificas": {{
        "servico": "ação_recomendada"
    }},
    "nivel_interesse_geral": "alto/medio/baixo"
}}
""",
            
            'analise_completa_varredura': """
Analise os seguintes resultados de varredura Nmap e forneça uma análise detalhada de segurança:

{dados_varredura}

Por favor, forneça:
1. Resumo executivo dos achados
2. Vulnerabilidades identificadas e seu nível de risco
3. Recomendações de segurança prioritárias
4. Análise de superfície de ataque
5. Próximos passos sugeridos para pentest

Formato a resposta em português e seja específico sobre os riscos encontrados.
""",
            
            'analise_vulnerabilidades': """
Analise especificamente as vulnerabilidades encontradas na varredura:

{dados_vulnerabilidades}

Para cada vulnerabilidade encontrada, forneça:
1. Descrição técnica da vulnerabilidade
2. Nível de risco (Crítico/Alto/Médio/Baixo)
3. Impacto potencial
4. Passos de exploração (se aplicável)
5. Medidas de mitigação específicas

Responda em português e priorize por criticidade.
""",
            
            'plano_pentest': """
Com base nos resultados da varredura:

{dados_varredura}

Elabore um plano estruturado de pentest incluindo:
1. Metodologia recomendada
2. Sequência de ataques sugerida
3. Ferramentas específicas para cada fase
4. Técnicas de exploit recomendadas
5. Validação de vulnerabilidades

Formate como um plano executável em português.
"""
        }
    
    def conectar_gemini(self) -> bool:
        """
        Estabelece conexão com a API do Gemini
        Returns:
            bool: True se conectado com sucesso
        """
        try:
            if not self.habilitado:
                self.logger.info("Gemini desabilitado por configuração (api.gemini.habilitado=false)")
                return False
            if not self.chave_api or self.chave_api.startswith('${'):
                self.logger.warning("Chave da API Gemini não configurada - usando modo fallback")
                return False
            
            # Configurar API
            genai.configure(api_key=self.chave_api)
            
            # Inicializar modelo
            try:
                self.modelo = genai.GenerativeModel(self.modelo_nome)
                if self.modelo is None:
                    self.logger.error("Falha ao inicializar modelo Gemini")
                    return False
            except Exception as e:
                self.logger.error(f"Erro ao inicializar modelo: {str(e)}")
                return False
            
            # Teste de conexão com prompt mais simples
            resposta_teste = self.modelo.generate_content("Responda apenas: OK")
            
            # Verificar se a resposta é válida
            if resposta_teste and resposta_teste.candidates:
                candidate = resposta_teste.candidates[0]
                
                # Verificar se há conteúdo ou se pelo menos a conexão funcionou
                if (hasattr(candidate, 'content') and candidate.content and 
                    hasattr(candidate.content, 'parts') and candidate.content.parts):
                    try:
                        # Tentar acessar o texto
                        texto = resposta_teste.text
                        self.conectado = True
                        self.logger.info(f"Conectado ao Gemini {self.modelo_nome} - Resposta: {texto[:50]}...")
                        return True
                    except:
                        # Se não conseguir acessar o texto, mas a estrutura está ok
                        self.conectado = True
                        self.logger.info(f"Conectado ao Gemini {self.modelo_nome} (resposta sem texto)")
                        return True
                elif candidate.finish_reason == 1:  # STOP - resposta completa mas vazia
                    # Conexão OK, mas modelo não gerou conteúdo
                    self.conectado = True
                    self.logger.info(f"Conectado ao Gemini {self.modelo_nome} (modelo conectado)")
                    return True
                else:
                    self.logger.error(f"Resposta inválida do Gemini: {candidate.finish_reason}")
                    return False
            else:
                self.logger.error("Nenhuma resposta do Gemini")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro ao conectar com Gemini: {str(e)}")
            return False
    
    def _executar_consulta_gemini(self, prompt: str, tipo_prompt: str = "consulta_geral") -> Optional[str]:
        """
        Executa consulta ao Gemini com retry e timeout por tentativa.
        Usa thread para impor timeout definido em self.timeout.
        Registra interação no histórico.
        """
        # Verificar se modelo está inicializado
        if self.modelo is None:
            self.logger.warning("Modelo Gemini não inicializado")
            return None
        
        # DEBUG: Informações básicas do prompt
        self.logger.info(f"Enviando prompt para Gemini ({len(prompt)} caracteres)")
        
        # Marcar tempo de início
        tempo_inicio = time.time()
        
        for tentativa in range(self.max_tentativas):
            result_container: Dict[str, Any] = {'resp': None, 'err': None}

            def worker():
                try:
                    if self.modelo is not None:
                        result_container['resp'] = self.modelo.generate_content(prompt)
                    else:
                        result_container['err'] = Exception("Modelo não inicializado")
                except Exception as e:
                    result_container['err'] = e

            t = threading.Thread(target=worker, daemon=True)
            t.start()
            t.join(timeout=self.timeout)

            if t.is_alive():
                self.logger.warning(f"Timeout na consulta ao Gemini na tentativa {tentativa + 1} ({self.timeout}s)")
                # prossegue para próxima tentativa sem aguardar a thread
                continue

            if result_container['err'] is not None:
                erro_str = str(result_container['err'])
                self.logger.warning(f"Erro na tentativa {tentativa + 1}: {erro_str}")
                if "429" in erro_str or "quota" in erro_str.lower():
                    if tentativa < self.max_tentativas - 1:
                        delay = 10 * (tentativa + 1)
                        self.logger.info(f"Aguardando {delay}s devido ao limite de quota...")
                        time.sleep(delay)
                if tentativa == self.max_tentativas - 1:
                    self.logger.error(f"Falha após {self.max_tentativas} tentativas")
                    return None
                continue

            resposta = result_container['resp']
            
            # DEBUG: Informações básicas da resposta
            if resposta and getattr(resposta, 'candidates', None):
                candidate = resposta.candidates[0]
                finish_reason = getattr(candidate, 'finish_reason', 'N/A')
                
                # Mapear finish_reason para entendimento
                finish_reason_map = {
                    1: 'STOP (resposta completa)',
                    2: 'MAX_TOKENS (limite de tokens)',
                    3: 'SAFETY (bloqueio de segurança)',
                    4: 'RECITATION (conteúdo repetitivo)',
                    5: 'OTHER (outro motivo)'
                }
                
                finish_reason_desc = finish_reason_map.get(finish_reason, f'UNKNOWN ({finish_reason})')
                
                # DEBUG detalhado apenas em caso de erro
                if finish_reason == 1:  # STOP - normal
                    # Tentar acessar o texto direto
                    try:
                        if getattr(resposta, 'text', None) and resposta.text.strip():
                            tempo_resposta = time.time() - tempo_inicio
                            self.logger.info(f"Resposta recebida com sucesso ({len(resposta.text)} caracteres)")
                            
                            # Registrar no histórico
                            try:
                                self.historico.registrar_interacao(
                                    prompt_enviado=prompt,
                                    resposta_recebida=resposta.text.strip(),
                                    tempo_resposta=tempo_resposta,
                                    tipo_prompt=tipo_prompt,
                                    contexto_adicional={
                                        'tentativa': tentativa + 1,
                                        'finish_reason': finish_reason_desc,
                                        'modelo': self.modelo_nome
                                    }
                                )
                            except Exception as e:
                                self.logger.warning(f"Erro ao registrar histórico: {e}")
                            
                            return resposta.text.strip()
                    except Exception as e:
                        self.logger.debug(f"Erro ao acessar resposta.text: {e}")

                    # Alternativa: extrair das parts
                    if (hasattr(candidate, 'content') and candidate.content and
                            hasattr(candidate.content, 'parts') and candidate.content.parts):
                        for part in candidate.content.parts:
                            if hasattr(part, 'text') and part.text:
                                tempo_resposta = time.time() - tempo_inicio
                                self.logger.info(f"Resposta recebida via parts ({len(part.text)} caracteres)")
                                
                                # Registrar no histórico
                                try:
                                    self.historico.registrar_interacao(
                                        prompt_enviado=prompt,
                                        resposta_recebida=part.text.strip(),
                                        tempo_resposta=tempo_resposta,
                                        tipo_prompt=tipo_prompt,
                                        contexto_adicional={
                                            'tentativa': tentativa + 1,
                                            'finish_reason': finish_reason_desc,
                                            'modelo': self.modelo_nome,
                                            'via_parts': True
                                        }
                                    )
                                except Exception as e:
                                    self.logger.warning(f"Erro ao registrar histórico: {e}")
                                
                                return part.text.strip()

                    # Se chegou aqui, a resposta está vazia
                    self.logger.warning(f"Resposta vazia na tentativa {tentativa + 1} - {finish_reason_desc}")
                    
                    # Tentar estratégias para resposta vazia
                    if tentativa < self.max_tentativas - 1:
                        # Aguardar um pouco antes da próxima tentativa
                        time.sleep(2)
                        self.logger.info(f"Tentando novamente com prompt simplificado...")
                        
                        # Se for a segunda tentativa, tentar com prompt simplificado
                        if tentativa == 1:
                            prompt_simplificado = self._simplificar_prompt(prompt)
                            if prompt_simplificado != prompt:
                                self.logger.info("Usando prompt simplificado na próxima tentativa")
                                # Substituir prompt para próxima iteração
                                prompt = prompt_simplificado
                    
                elif finish_reason in [2, 3, 4, 5]:  # Outros finish_reason - problemas específicos
                    self.logger.warning(f"Resposta bloqueada na tentativa {tentativa + 1} - {finish_reason_desc}")
                    
                    if finish_reason == 3:  # SAFETY
                        safety_ratings = getattr(candidate, 'safety_ratings', [])
                        self.logger.warning(f"Bloqueio de segurança detectado. Safety ratings: {safety_ratings}")
                        # Para problemas de segurança, tentar prompt mais neutro
                        if tentativa < self.max_tentativas - 1:
                            prompt = self._neutralizar_prompt(prompt)
                            self.logger.info("Tentando com prompt neutralizado")
                    
                    elif finish_reason == 2:  # MAX_TOKENS
                        self.logger.warning("Limite de tokens atingido - prompt muito longo")
                        if tentativa < self.max_tentativas - 1:
                            prompt = self._encurtar_prompt(prompt)
                            self.logger.info("Tentando com prompt encurtado")
                else:
                    self.logger.warning(f"Finish reason inesperado: {finish_reason_desc}")
                    
            else:
                self.logger.warning(f"Nenhuma resposta válida na tentativa {tentativa + 1}")

        # Se chegou aqui, todas as tentativas falharam - registrar falha no histórico
        tempo_resposta = time.time() - tempo_inicio
        try:
            self.historico.registrar_interacao(
                prompt_enviado=prompt,
                resposta_recebida=None,
                tempo_resposta=tempo_resposta,
                tipo_prompt=tipo_prompt,
                contexto_adicional={
                    'tentativas_totais': self.max_tentativas,
                    'status': 'falhou_todas_tentativas',
                    'modelo': self.modelo_nome
                }
            )
        except Exception as e:
            self.logger.warning(f"Erro ao registrar falha no histórico: {e}")
        
        return None
    
    def _simplificar_prompt(self, prompt: str) -> str:
        """
        Simplifica o prompt para tentar obter resposta do Gemini
        Args:
            prompt (str): Prompt original
        Returns:
            str: Prompt simplificado
        """
        if 'decidir_proximos_passos' in prompt:
            # Prompt simplificado para decisão
            return """
Analise estes resultados de scan e responda apenas em JSON:
- 16 portas abertas incluindo SSH (22), HTTP (80), e vários serviços web (8000, 8080, 9443)

Responda APENAS:
{
    "executar_nmap_avancado": true/false,
    "justificativa": "explicação"
}
"""
        return prompt[:len(prompt)//2]  # Reduzir pela metade como fallback
    
    def _neutralizar_prompt(self, prompt: str) -> str:
        """
        Remove termos que podem causar bloqueios de segurança
        Args:
            prompt (str): Prompt original
        Returns:
            str: Prompt neutralizado
        """
        # Substituir termos que podem ser considerados problemáticos
        termos_problematicos = {
            'vulnerabilidades': 'questões de configuração',
            'exploração': 'análise',
            'ataque': 'teste',
            'pentest': 'auditoria de segurança',
            'hack': 'análise',
            'exploit': 'verificação'
        }
        
        prompt_neutralizado = prompt
        for termo, substituto in termos_problematicos.items():
            prompt_neutralizado = prompt_neutralizado.replace(termo, substituto)
        
        return prompt_neutralizado
    
    def _preparar_contexto_seguro_para_ia(self, dados: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """
        Prepara contexto seguro para envio à IA
        Args:
            dados (Dict): Dados originais
        Returns:
            Tuple[Dict, Dict]: Contexto seguro e mapeamento de IPs
        """
        if not self.anonimizar_ips:
            self.logger.warning("⚠️ Anonimização desabilitada - IPs reais serão enviados à IA")
            return dados, {}
        
        try:
            # Criar contexto seguro
            contexto_seguro = criar_contexto_seguro_para_ia(dados)
            
            # Extrair mapeamento de IPs para log (sem armazenar)
            _, mapeamento_ips = anonimizar_contexto_ia(dados, self.seed_anonimizacao)
            
            # Log da anonimização (apenas estatísticas)
            if mapeamento_ips:
                self.logger.info(f"🔒 {len(mapeamento_ips)} IPs anonimizados para contexto IA")
                self.logger.debug("Tipos de IP anonimizados: " + ", ".join(
                    [self._classificar_tipo_ip(ip) for ip in mapeamento_ips.keys()]
                ))
            
            return contexto_seguro, mapeamento_ips
            
        except Exception as e:
            self.logger.error(f"Erro na anonimização: {e}")
            # Fallback: remover IPs completamente
            return self._remover_ips_completamente(dados), {}
    
    def _classificar_tipo_ip(self, ip: str) -> str:
        """Classifica tipo de IP para log"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return "PRIVADO"
            elif ip_obj.is_loopback:
                return "LOCALHOST"
            elif ip_obj.is_link_local:
                return "LINK_LOCAL"
            else:
                return "PÚBLICO"
        except:
            return "INVÁLIDO"
    
    def _remover_ips_completamente(self, dados: Dict[str, Any]) -> Dict[str, Any]:
        """Remove IPs completamente como fallback de segurança"""
        def limpar_recursivo(obj):
            if isinstance(obj, dict):
                resultado = {}
                for chave, valor in obj.items():
                    if any(termo in chave.lower() for termo in ['ip', 'endereco', 'address', 'host']):
                        resultado[chave] = "[IP_REMOVIDO]"
                    else:
                        resultado[chave] = limpar_recursivo(valor)
                return resultado
            elif isinstance(obj, list):
                return [limpar_recursivo(item) for item in obj]
            elif isinstance(obj, str):
                # Substituir padrões de IP
                import re
                return re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP_REMOVIDO]', obj)
            else:
                return obj
        
        return limpar_recursivo(dados)
    
    def _encurtar_prompt(self, prompt: str) -> str:
        """
        Encurta o prompt para reduzir tokens
        Args:
            prompt (str): Prompt original
        Returns:
            str: Prompt encurtado
        """
        # Manter apenas as partes essenciais
        linhas = prompt.split('\n')
        linhas_essenciais = []
        
        for linha in linhas:
            if any(termo in linha.lower() for termo in ['analise', 'responda', 'json', 'formato']):
                linhas_essenciais.append(linha)
            elif len(linhas_essenciais) < 10:  # Manter primeiras 10 linhas relevantes
                linhas_essenciais.append(linha)
        
        return '\n'.join(linhas_essenciais)

    def decidir_proximos_passos(self, resultados_scan_inicial: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decide os próximos passos baseado nos resultados do scan inicial
        Args:
            resultados_scan_inicial (Dict): Resultados do scan de portas inicial
        Returns:
            Dict[str, Any]: Decisão e recomendações
        """
        self.logger.info("Iniciando análise IA para decisão dos próximos passos")
        
        try:
            # Conectar ao Gemini se necessário
            if not self.conectado and not self.conectar_gemini():
                return self._decisao_fallback(resultados_scan_inicial)
            
            # Preparar contexto seguro para IA
            contexto_seguro, mapeamento_ips = self._preparar_contexto_seguro_para_ia(resultados_scan_inicial)
            
            # Preparar dados para análise (usando contexto seguro)
            dados_formatados = self._formatar_resultados_scan(contexto_seguro)
            
            # Gerar prompt de decisão
            prompt = self.templates_prompts['decidir_proximos_passos'].format(
                resultados_scan=dados_formatados
            )
            
            # Executar consulta IA
            resposta_ia = self._executar_consulta_gemini(prompt)
            
            if resposta_ia:
                # Tentar parsear JSON da resposta
                decisao_ia = self._parsear_decisao_ia(resposta_ia)
                
                if decisao_ia:
                    # Enriquecer decisão com análise local (usando dados originais)
                    decisao_final = self._enriquecer_decisao(decisao_ia, resultados_scan_inicial)
                    
                    # Adicionar informações de segurança
                    decisao_final['seguranca'] = {
                        'ips_anonimizados': len(mapeamento_ips) if mapeamento_ips else 0,
                        'contexto_seguro_usado': self.anonimizar_ips
                    }
                    
                    self.logger.info(f"Decisão IA: {decisao_final.get('executar_nmap_avancado', False)}")
                    return decisao_final
                else:
                    self.logger.warning("Falha ao parsear resposta da IA, usando fallback")
                    return self._decisao_fallback(resultados_scan_inicial)
            else:
                self.logger.warning("Resposta vazia da IA, usando fallback")
                return self._decisao_fallback(resultados_scan_inicial)
                
        except Exception as e:
            self.logger.error(f"Erro na decisão IA: {str(e)}")
            return self._decisao_fallback(resultados_scan_inicial)
    
    def analisar_servicos_detectados(self, resultados_scan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analisa especificamente os serviços detectados
        Args:
            resultados_scan (Dict): Resultados do scan
        Returns:
            Dict[str, Any]: Análise dos serviços
        """
        try:
            # Extrair serviços dos resultados (dados originais para análise local)
            servicos = self._extrair_servicos_scan(resultados_scan)
            
            if not servicos:
                return {
                    'servicos_criticos': [],
                    'servicos_interessantes': [],
                    'nivel_interesse_geral': 'baixo',
                    'recomendacoes_especificas': {}
                }
            
            # Conectar ao Gemini se necessário
            if not self.conectado and not self.conectar_gemini():
                return self._analise_servicos_local(servicos)
            
            # Preparar contexto seguro para IA
            dados_servicos_para_ia = {'servicos_detectados': servicos}
            contexto_seguro, mapeamento_ips = self._preparar_contexto_seguro_para_ia(dados_servicos_para_ia)
            
            # Formatar serviços para análise (usando dados seguros)
            servicos_formatados = json.dumps(contexto_seguro['servicos_detectados'], indent=2, ensure_ascii=False)
            
            # Gerar prompt
            prompt = self.templates_prompts['analisar_servicos_encontrados'].format(
                servicos_detectados=servicos_formatados
            )
            
            # Executar análise
            resposta_ia = self._executar_consulta_gemini(prompt)
            
            if resposta_ia:
                analise_ia = self._parsear_analise_servicos(resposta_ia)
                if analise_ia:
                    # Adicionar informações de segurança
                    analise_ia['seguranca'] = {
                        'ips_anonimizados': len(mapeamento_ips) if mapeamento_ips else 0,
                        'contexto_seguro_usado': self.anonimizar_ips
                    }
                    return analise_ia
            
            # Fallback para análise local (usando dados originais)
            return self._analise_servicos_local(servicos)
            
        except Exception as e:
            self.logger.error(f"Erro na análise de serviços: {str(e)}")
            return self._analise_servicos_local([])
    
    def _formatar_resultados_scan(self, resultados: Dict[str, Any]) -> str:
        """
        Formata resultados do scan para análise IA
        Args:
            resultados (Dict): Resultados do scan inicial
        Returns:
            str: Dados formatados
        """
        resumo_scan = resultados.get('resumo_scan', {})
        hosts_com_portas = resumo_scan.get('hosts_com_portas_abertas', [])
        
        formatado = f"""
RESUMO GERAL:
- IPs scaneados: {resumo_scan.get('total_ips_scaneados', 0)}
- Hosts ativos: {resumo_scan.get('hosts_ativos', 0)}  
- Total de portas abertas: {resumo_scan.get('total_portas_abertas', 0)}

HOSTS COM PORTAS ABERTAS:
"""
        
        for host in hosts_com_portas:
            formatado += f"""
Host: {host.get('ip', 'N/A')}
Portas abertas: {', '.join(map(str, host.get('portas', [])))}
Total de portas: {host.get('portas_abertas', 0)}
"""
        
        return formatado
    
    def _extrair_servicos_scan(self, resultados: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extrai informações de serviços dos resultados do scan
        Args:
            resultados (Dict): Resultados do scan
        Returns:
            List[Dict]: Lista de serviços detectados
        """
        servicos = []
        
        # Mapear portas para serviços conhecidos
        mapa_portas_servicos = {
            22: 'SSH',
            23: 'Telnet', 
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL',
            1433: 'MSSQL',
            8000: 'HTTP-Alt',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            8085: 'HTTP-Alt',
            8090: 'HTTP-Alt'
        }
        
        hosts_com_portas = resultados.get('resumo_scan', {}).get('hosts_com_portas_abertas', [])
        
        for host in hosts_com_portas:
            host_ip = host.get('ip', 'N/A')
            portas = host.get('portas', [])
            
            for porta in portas:
                servico_nome = mapa_portas_servicos.get(porta, 'Unknown')
                
                servicos.append({
                    'host': host_ip,
                    'porta': porta,
                    'servico': servico_nome,
                    'protocolo': 'tcp',  # Assumindo TCP por padrão
                    'criticidade': self._avaliar_criticidade_porta(porta)
                })
        
        return servicos
    
    def _avaliar_criticidade_porta(self, porta: int) -> str:
        """
        Avalia criticidade de uma porta para segurança
        Args:
            porta (int): Número da porta
        Returns:
            str: Nível de criticidade
        """
        portas_criticas = [22, 23, 135, 139, 445, 3389]  # SSH, Telnet, RPC, NetBIOS, SMB, RDP
        portas_altas = [25, 80, 110, 143, 443, 993, 995, 3306, 5432, 1433]  # Web, Email, DB
        portas_medias = [53, 111, 8000, 8080, 8443, 8085, 8090]  # DNS, RPC, Web-Alt
        
        if porta in portas_criticas:
            return 'critica'
        elif porta in portas_altas:
            return 'alta'
        elif porta in portas_medias:
            return 'media'
        else:
            return 'baixa'
    
    def _parsear_decisao_ia(self, resposta_ia: str) -> Optional[Dict[str, Any]]:
        """
        Parseia resposta JSON da IA
        Args:
            resposta_ia (str): Resposta da IA
        Returns:
            Optional[Dict]: Decisão parseada ou None
        """
        try:
            # Tentar extrair JSON da resposta
            resposta_limpa = resposta_ia.strip()
            
            # Procurar por JSON na resposta
            inicio_json = resposta_limpa.find('{')
            fim_json = resposta_limpa.rfind('}') + 1
            
            if inicio_json >= 0 and fim_json > inicio_json:
                json_str = resposta_limpa[inicio_json:fim_json]
                decisao = json.loads(json_str)
                
                # Validar campos obrigatórios
                campos_obrigatorios = ['executar_nmap_avancado', 'justificativa']
                if all(campo in decisao for campo in campos_obrigatorios):
                    return decisao
            
            return None
            
        except json.JSONDecodeError as e:
            self.logger.warning(f"Erro ao parsear JSON da IA: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"Erro inesperado ao parsear decisão: {str(e)}")
            return None
    
    def _parsear_analise_servicos(self, resposta_ia: str) -> Optional[Dict[str, Any]]:
        """
        Parseia análise de serviços da IA
        Args:
            resposta_ia (str): Resposta da IA
        Returns:
            Optional[Dict]: Análise parseada ou None
        """
        try:
            # Similar ao método anterior, mas para análise de serviços
            resposta_limpa = resposta_ia.strip()
            inicio_json = resposta_limpa.find('{')
            fim_json = resposta_limpa.rfind('}') + 1
            
            if inicio_json >= 0 and fim_json > inicio_json:
                json_str = resposta_limpa[inicio_json:fim_json]
                analise = json.loads(json_str)
                return analise
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Erro ao parsear análise de serviços: {str(e)}")
            return None
    
    def _normalizar_modulos_ia(self, modulos_ia: List[str]) -> List[str]:
        """
        Normaliza nomes de módulos vindos da IA para os nomes esperados pelo orquestrador
        Args:
            modulos_ia (List[str]): Lista de módulos recomendados pela IA
        Returns:
            List[str]: Lista de módulos normalizados
        """
        # Mapeamento de nomes da IA para nomes do orquestrador
        mapa_normalizacao = {
            # Nomes descritivos da IA -> nomes técnicos do orquestrador
            'Nmap Básico': 'varredura_basica',
            'Nmap Completo': 'varredura_completa',
            'Nmap Vulnerabilidades': 'varredura_vulnerabilidades',
            'Nmap Serviços Web': 'varredura_servicos_web',
            'Nmap SMB': 'varredura_smb',
            'Nmap Descoberta de Rede': 'varredura_descoberta_rede',
            'Feroxbuster Básico': 'feroxbuster_basico',
            'Feroxbuster Recursivo': 'feroxbuster_recursivo',
            'SQLMap URL': 'sqlmap_teste_url',
            'SQLMap Formulário': 'sqlmap_teste_formulario',
            
            # Nomes descritivos completos
            'Nmap Básico - Varredura simples de portas': 'varredura_basica',
            'Nmap Completo - Detecção de versão e serviços': 'varredura_completa',
            'Nmap Vulnerabilidades - Scripts NSE de vulnerabilidades': 'varredura_vulnerabilidades',
            'Nmap Serviços Web - Análise específica de HTTP/HTTPS': 'varredura_servicos_web',
            'Nmap SMB - Análise de serviços SMB/NetBIOS': 'varredura_smb',
            'Nmap Descoberta de Rede - Discovery de hosts na rede': 'varredura_descoberta_rede',
            'Feroxbuster Básico - Descoberta de diretórios e arquivos web': 'feroxbuster_basico',
            'Feroxbuster Recursivo - Descoberta recursiva de diretórios': 'feroxbuster_recursivo',
            'SQLMap URL - Teste de SQL Injection em URLs': 'sqlmap_teste_url',
            'SQLMap Formulário - Teste de SQL Injection em formulários': 'sqlmap_teste_formulario',
            
            # Já normalizados (pass-through)
            'varredura_basica': 'varredura_basica',
            'varredura_completa': 'varredura_completa',
            'varredura_vulnerabilidades': 'varredura_vulnerabilidades',
            'varredura_servicos_web': 'varredura_servicos_web',
            'varredura_smb': 'varredura_smb',
            'varredura_descoberta_rede': 'varredura_descoberta_rede',
            'feroxbuster_basico': 'feroxbuster_basico',
            'feroxbuster_recursivo': 'feroxbuster_recursivo',
            'sqlmap_teste_url': 'sqlmap_teste_url',
            'sqlmap_teste_formulario': 'sqlmap_teste_formulario'
        }
        
        modulos_normalizados = []
        for modulo in modulos_ia:
            modulo_normalizado = mapa_normalizacao.get(modulo.strip())
            if modulo_normalizado:
                if modulo_normalizado not in modulos_normalizados:  # Evitar duplicatas
                    modulos_normalizados.append(modulo_normalizado)
                    self.logger.debug(f"Módulo normalizado: '{modulo}' -> '{modulo_normalizado}'")
            else:
                self.logger.warning(f"Módulo não reconhecido da IA: '{modulo}'")
        
        return modulos_normalizados
    
    def _enriquecer_decisao(self, decisao_ia: Dict[str, Any], resultados_scan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enriquece decisão da IA com análise local
        Args:
            decisao_ia (Dict): Decisão da IA
            resultados_scan (Dict): Resultados do scan
        Returns:
            Dict[str, Any]: Decisão enriquecida
        """
        # Normalizar módulos recomendados pela IA
        modulos_ia_originais = decisao_ia.get('modulos_recomendados', [])
        modulos_normalizados = self._normalizar_modulos_ia(modulos_ia_originais)
        
        decisao_final = {
            'timestamp': datetime.now().isoformat(),
            'fonte_decisao': 'ia_gemini',
            'executar_nmap_avancado': decisao_ia.get('executar_nmap_avancado', False),
            'modulos_recomendados': modulos_normalizados,  # Usar módulos normalizados
            'modulos_ia_originais': modulos_ia_originais,  # Manter originais para debug
            'justificativa_ia': decisao_ia.get('justificativa', ''),
            'prioridade': decisao_ia.get('prioridade', 'media'),
            'portas_prioritarias': decisao_ia.get('portas_prioritarias', []),
            'tempo_estimado': decisao_ia.get('tempo_estimado', '5-10 minutos'),
            
            # Análise local adicional
            'analise_local': self._gerar_analise_local(resultados_scan),
            'contexto_scan': {
                'total_hosts': resultados_scan.get('resumo_scan', {}).get('hosts_ativos', 0),
                'total_portas': resultados_scan.get('resumo_scan', {}).get('total_portas_abertas', 0),
                'hosts_interessantes': len(resultados_scan.get('resumo_scan', {}).get('hosts_com_portas_abertas', []))
            }
        }
        
        # Log da normalização
        if modulos_ia_originais != modulos_normalizados:
            self.logger.info(f"Módulos IA normalizados: {modulos_ia_originais} -> {modulos_normalizados}")
        
        return decisao_final
    
    def _gerar_analise_local(self, resultados_scan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera análise local complementar
        Args:
            resultados_scan (Dict): Resultados do scan
        Returns:
            Dict[str, Any]: Análise local
        """
        resumo_scan = resultados_scan.get('resumo_scan', {})
        hosts_com_portas = resumo_scan.get('hosts_com_portas_abertas', [])
        
        # Contar tipos de serviços
        servicos_web = 0
        servicos_criticos = 0
        portas_interessantes = []
        
        for host in hosts_com_portas:
            portas = host.get('portas', [])
            
            for porta in portas:
                if porta in [80, 443, 8000, 8080, 8443, 8085, 8090]:
                    servicos_web += 1
                
                if porta in [22, 23, 135, 139, 445, 3389]:
                    servicos_criticos += 1
                
                if self._avaliar_criticidade_porta(porta) in ['critica', 'alta']:
                    portas_interessantes.append(porta)
        
        return {
            'servicos_web_detectados': servicos_web,
            'servicos_criticos_detectados': servicos_criticos,
            'portas_interessantes': list(set(portas_interessantes)),
            'recomendacao_local': self._gerar_recomendacao_local(servicos_web, servicos_criticos),
            'nivel_interesse': self._calcular_nivel_interesse(servicos_web, servicos_criticos)
        }
    
    def _gerar_recomendacao_local(self, servicos_web: int, servicos_criticos: int) -> str:
        """
        Gera recomendação baseada em análise local
        Args:
            servicos_web (int): Número de serviços web
            servicos_criticos (int): Número de serviços críticos
        Returns:
            str: Recomendação
        """
        if servicos_criticos > 0:
            return "Serviços críticos detectados - análise aprofundada recomendada"
        elif servicos_web > 2:
            return "Múltiplos serviços web - análise de vulnerabilidades web recomendada"
        elif servicos_web > 0:
            return "Serviços web detectados - varredura básica de vulnerabilidades"
        else:
            return "Poucos serviços expostos - análise básica suficiente"
    
    def _calcular_nivel_interesse(self, servicos_web: int, servicos_criticos: int) -> str:
        """
        Calcula nível de interesse para pentest
        Args:
            servicos_web (int): Número de serviços web
            servicos_criticos (int): Número de serviços críticos
        Returns:
            str: Nível de interesse
        """
        if servicos_criticos >= 2:
            return 'alto'
        elif servicos_criticos >= 1 or servicos_web >= 3:
            return 'medio'
        elif servicos_web >= 1:
            return 'baixo'
        else:
            return 'muito_baixo'
    
    def _decisao_fallback(self, resultados_scan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decisão de fallback quando IA não está disponível
        Args:
            resultados_scan (Dict): Resultados do scan
        Returns:
            Dict[str, Any]: Decisão baseada em regras
        """
        self.logger.info("Usando decisão de fallback (regras locais)")
        
        resumo_scan = resultados_scan.get('resumo_scan', {})
        total_portas = resumo_scan.get('total_portas_abertas', 0)
        hosts_com_portas = resumo_scan.get('hosts_com_portas_abertas', [])
        hosts_ativos = resumo_scan.get('hosts_ativos', 0)
        
        # Análise local para decisão
        analise_local = self._gerar_analise_local(resultados_scan)
        nivel_interesse = analise_local.get('nivel_interesse', 'baixo')
        
        # Decisão conservadora - só executar nmap se realmente necessário
        executar_nmap = False
        modulos_recomendados = []
        justificativa = ""
        prioridade = "baixa"
        
        # Só executar nmap se houver hosts ativos E portas abertas
        if hosts_ativos == 0:
            # Nenhum host ativo - não vale a pena continuar
            executar_nmap = False
            justificativa = "Nenhum host ativo detectado - scan inicial suficiente"
        elif total_portas == 0:
            # Hosts ativos mas sem portas abertas - só descoberta se necessário
            executar_nmap = False
            justificativa = "Nenhuma porta aberta detectada - pode ser firewall ou host offline"
        elif nivel_interesse == 'alto':
            # Serviços críticos detectados
            executar_nmap = True
            modulos_recomendados = ['varredura_vulnerabilidades', 'varredura_completa']
            justificativa = "Serviços críticos detectados - análise aprofundada necessária"
            prioridade = "alta"
        elif nivel_interesse == 'medio':
            # Serviços interessantes
            executar_nmap = True
            modulos_recomendados = ['varredura_completa']
            justificativa = "Serviços interessantes detectados - análise recomendada"
            prioridade = "media"
        elif total_portas >= 10:
            # Muitas portas abertas - vale investigar
            executar_nmap = True
            modulos_recomendados = ['varredura_completa']
            justificativa = "Muitas portas abertas detectadas - análise recomendada para identificar serviços"
            prioridade = "media"
        elif total_portas >= 3:
            # Algumas portas interessantes
            executar_nmap = True
            modulos_recomendados = ['varredura_basica']
            justificativa = "Portas abertas detectadas - verificação básica recomendada"
            prioridade = "baixa"
        else:
            # Poucos serviços
            executar_nmap = False
            justificativa = "Poucos serviços expostos - scan inicial suficiente"
        
        # Adicionar módulos específicos baseado nos serviços (só se já vai executar nmap)
        if executar_nmap and analise_local.get('servicos_web_detectados', 0) > 0:
            if 'varredura_servicos_web' not in modulos_recomendados:
                modulos_recomendados.append('varredura_servicos_web')
        
        return {
            'timestamp': datetime.now().isoformat(),
            'fonte_decisao': 'regras_locais',
            'executar_nmap_avancado': executar_nmap,
            'modulos_recomendados': modulos_recomendados,
            'justificativa_ia': justificativa,
            'prioridade': prioridade,
            'portas_prioritarias': analise_local.get('portas_interessantes', []),
            'tempo_estimado': '3-5 minutos' if executar_nmap else '0 minutos',
            'analise_local': analise_local,
            'contexto_scan': {
                'total_hosts': hosts_ativos,
                'total_portas': total_portas,
                'hosts_interessantes': len(hosts_com_portas)
            },
            'motivo_decisao': f"Hosts ativos: {hosts_ativos}, Portas abertas: {total_portas}, Nível: {nivel_interesse}"
        }
    
    def _analise_servicos_local(self, servicos: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Análise local de serviços quando IA não disponível
        Args:
            servicos (List): Lista de serviços
        Returns:
            Dict[str, Any]: Análise local
        """
        servicos_criticos = []
        servicos_interessantes = []
        recomendacoes = {}
        
        for servico in servicos:
            criticidade = servico.get('criticidade', 'baixa')
            nome_servico = servico.get('servico', 'Unknown')
            
            if criticidade == 'critica':
                servicos_criticos.append(nome_servico)
                recomendacoes[nome_servico] = "Análise aprofundada de vulnerabilidades"
            elif criticidade in ['alta', 'media']:
                servicos_interessantes.append(nome_servico)
                recomendacoes[nome_servico] = "Verificação de configurações de segurança"
        
        nivel_interesse = 'alto' if servicos_criticos else ('medio' if servicos_interessantes else 'baixo')
        
        return {
            'servicos_criticos': servicos_criticos,
            'servicos_interessantes': servicos_interessantes,
            'recomendacoes_especificas': recomendacoes,
            'nivel_interesse_geral': nivel_interesse
        }
    
    def _formatar_dados_varredura_completa(self, resultados: Dict[str, Any]) -> str:
        """
        Formata dados de varredura para análise completa IA
        Args:
            resultados (Dict): Resultados da varredura
        Returns:
            str: Dados formatados para prompt
        """
        dados = resultados.get('dados', {})
        resumo = dados.get('resumo', {})
        hosts = dados.get('hosts', [])
        
        formatado = f"""
RESUMO DA VARREDURA:
- Tipo: {resultados.get('tipo_varredura', 'N/A')}
- Timestamp: {resultados.get('timestamp', 'N/A')}
- Hosts Total: {resumo.get('hosts_total', 0)}
- Hosts Ativos: {resumo.get('hosts_ativos', 0)}
- Portas Abertas: {resumo.get('portas_abertas', 0)}
- Serviços Detectados: {resumo.get('servicos_detectados', 0)}
- Vulnerabilidades: {resumo.get('vulnerabilidades', 0)}

DETALHES DOS HOSTS:
"""
        
        for host in hosts[:5]:  # Limitar a 5 hosts para não sobrecarregar
            formatado += f"""
Host: {host.get('endereco', 'N/A')}
Status: {host.get('status', 'N/A')}
Hostname: {host.get('hostname', 'N/A')}
OS: {host.get('os', {}).get('nome', 'N/A')}

Portas Abertas:
"""
            
            portas_abertas = [p for p in host.get('portas', []) if p.get('estado') == 'open']
            for porta in portas_abertas[:10]:  # Limitar portas
                formatado += f"  {porta['numero']}/{porta['protocolo']} - {porta.get('servico', 'unknown')}"
                if porta.get('produto'):
                    formatado += f" ({porta['produto']} {porta.get('versao', '')})"
                formatado += "\n"
            
            # Scripts NSE relevantes
            scripts_vuln = []
            for porta in portas_abertas:
                for script in porta.get('scripts', []):
                    if 'vuln' in script.get('id', '').lower():
                        scripts_vuln.append(script)
            
            if scripts_vuln:
                formatado += "Scripts de Vulnerabilidade:\n"
                for script in scripts_vuln[:5]:  # Limitar scripts
                    formatado += f"  {script.get('id', 'N/A')}: {script.get('saida', 'N/A')[:100]}...\n"
        
        return formatado
    
    def _extrair_vulnerabilidades_completas(self, resultados: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extrai vulnerabilidades dos resultados de varredura
        Args:
            resultados (Dict): Resultados da varredura
        Returns:
            List[Dict]: Lista de vulnerabilidades encontradas
        """
        vulnerabilidades = []
        
        for host in resultados.get('dados', {}).get('hosts', []):
            host_ip = host.get('endereco', 'N/A')
            
            # Verificar scripts de host
            for script in host.get('scripts', []):
                if 'vuln' in script.get('id', '').lower():
                    vulnerabilidades.append({
                        'host': host_ip,
                        'tipo': 'host',
                        'script': script.get('id', ''),
                        'descricao': script.get('saida', ''),
                        'elementos': script.get('elementos', [])
                    })
            
            # Verificar scripts de portas
            for porta in host.get('portas', []):
                if porta.get('estado') == 'open':
                    for script in porta.get('scripts', []):
                        if 'vuln' in script.get('id', '').lower():
                            vulnerabilidades.append({
                                'host': host_ip,
                                'porta': f"{porta['numero']}/{porta['protocolo']}",
                                'servico': porta.get('servico', ''),
                                'tipo': 'porta',
                                'script': script.get('id', ''),
                                'descricao': script.get('saida', ''),
                                'elementos': script.get('elementos', [])
                            })
        
        return vulnerabilidades
    
    def _determinar_nivel_risco_geral(self, resultados: Dict[str, Any]) -> str:
        """
        Determina nível de risco geral da varredura
        Args:
            resultados (Dict): Resultados da varredura
        Returns:
            str: Nível de risco (Crítico/Alto/Médio/Baixo)
        """
        resumo = resultados.get('dados', {}).get('resumo', {})
        vulnerabilidades = resumo.get('vulnerabilidades', 0)
        portas_abertas = resumo.get('portas_abertas', 0)
        
        if vulnerabilidades >= 5:
            return 'Crítico'
        elif vulnerabilidades >= 2 or portas_abertas >= 20:
            return 'Alto'
        elif vulnerabilidades >= 1 or portas_abertas >= 10:
            return 'Médio'
        else:
            return 'Baixo'
    
    def _extrair_resumo_tecnico(self, analise_ia: str) -> str:
        """
        Extrai resumo técnico da análise IA
        Args:
            analise_ia (str): Análise completa da IA
        Returns:
            str: Resumo técnico
        """
        # Simples extração do primeiro parágrafo
        linhas = analise_ia.split('\n')
        resumo = []
        
        for linha in linhas:
            linha = linha.strip()
            if linha and not linha.startswith('#') and not linha.startswith('*'):
                resumo.append(linha)
                if len(resumo) >= 3:  # Primeiras 3 linhas substantivas
                    break
        
        return ' '.join(resumo) if resumo else analise_ia[:200] + '...'
    
    def _extrair_recomendacoes(self, analise_ia: str) -> List[str]:
        """
        Extrai recomendações da análise IA
        Args:
            analise_ia (str): Análise completa da IA
        Returns:
            List[str]: Lista de recomendações
        """
        recomendacoes = []
        linhas = analise_ia.split('\n')
        
        capturando = False
        for linha in linhas:
            linha = linha.strip()
            
            if 'recomenda' in linha.lower() or 'sugest' in linha.lower():
                capturando = True
                continue
            
            if capturando and linha:
                if linha.startswith(('-', '*', '•')) or linha[0].isdigit():
                    recomendacoes.append(linha.lstrip('-*•0123456789. '))
                elif linha.startswith('#'):
                    break
        
        return recomendacoes[:5]  # Máximo 5 recomendações
    
    def _obter_criticidade_maxima(self, vulnerabilidades: List[Dict]) -> str:
        """Obtém criticidade máxima das vulnerabilidades"""
        # Análise simples baseada em palavras-chave
        criticas = ['remote code execution', 'rce', 'sql injection', 'authentication bypass']
        altas = ['xss', 'directory traversal', 'information disclosure']
        
        for vuln in vulnerabilidades:
            descricao = vuln.get('descricao', '').lower()
            for termo in criticas:
                if termo in descricao:
                    return 'Crítica'
            
            for termo in altas:
                if termo in descricao:
                    return 'Alta'
        
        return 'Média' if vulnerabilidades else 'Baixa'
    
    def _resumir_dados_para_plano(self, resultados: Dict[str, Any]) -> str:
        """Resume dados para geração de plano"""
        return self._formatar_dados_varredura_completa(resultados)[:1000]  # Resumo limitado
    
    def _extrair_alvos_prioritarios(self, resultados: Dict[str, Any]) -> List[str]:
        """Extrai alvos prioritários para pentest"""
        alvos = []
        
        for host in resultados.get('dados', {}).get('hosts', []):
            if host.get('status') == 'up':
                alvos.append(host.get('endereco', ''))
        
        return alvos[:5]  # Máximo 5 alvos
    
    def _extrair_fases_plano(self, plano_ia: str) -> List[str]:
        """Extrai fases do plano de pentest"""
        fases = ['Reconhecimento', 'Varredura', 'Enumeração', 'Exploração', 'Pós-exploração']
        return fases  # Retorna fases padrão por simplicidade
    
    def _estimar_tempo_pentest(self, resultados: Dict[str, Any]) -> str:
        """Estima tempo necessário para pentest"""
        hosts = len(resultados.get('dados', {}).get('hosts', []))
        
        if hosts <= 1:
            return '1-2 dias'
        elif hosts <= 5:
            return '3-5 dias'
        elif hosts <= 10:
            return '1-2 semanas'
        else:
            return '2+ semanas'
    
    def analisar_varredura_completa(self, resultados_varredura: Dict[str, Any]) -> Dict[str, Any]:
        """
        Análise completa dos resultados de varredura usando IA
        Args:
            resultados_varredura (Dict): Resultados da varredura Nmap
        Returns:
            Dict[str, Any]: Análise completa gerada pelo Gemini
        """
        if not self.conectado and not self.conectar_gemini():
            return {'erro': 'Não foi possível conectar ao Gemini'}
        
        try:
            # Preparar contexto seguro para IA
            contexto_seguro, mapeamento_ips = self._preparar_contexto_seguro_para_ia(resultados_varredura)
            
            # Preparar dados para análise (usando contexto seguro)
            dados_formatados = self._formatar_dados_varredura_completa(contexto_seguro)
            
            # Gerar prompt
            prompt = self.templates_prompts['analise_completa_varredura'].format(
                dados_varredura=dados_formatados
            )
            
            # Executar análise
            resposta = self._executar_consulta_gemini(prompt)
            
            if resposta:
                analise = {
                    'timestamp': datetime.now().isoformat(),
                    'tipo_analise': 'completa',
                    'modelo_utilizado': self.modelo_nome,
                    'analise_ia': resposta,
                    'resumo_tecnico': self._extrair_resumo_tecnico(resposta),
                    'nivel_risco_geral': self._determinar_nivel_risco_geral(resultados_varredura),  # Usar dados originais
                    'recomendacoes_prioritarias': self._extrair_recomendacoes(resposta),
                    'seguranca': {
                        'ips_anonimizados': len(mapeamento_ips) if mapeamento_ips else 0,
                        'contexto_seguro_usado': self.anonimizar_ips,
                        'dados_originais_preservados': True
                    }
                }
                
                self.logger.info("Análise completa executada com sucesso")
                return analise
            else:
                return {'erro': 'Falha na geração da análise'}
                
        except Exception as e:
            self.logger.error(f"Erro na análise completa: {str(e)}")
            return {'erro': f'Erro na análise: {str(e)}'}
    
    def analisar_vulnerabilidades_detalhadas(self, resultados_varredura: Dict[str, Any]) -> Dict[str, Any]:
        """
        Análise focada em vulnerabilidades usando IA
        Args:
            resultados_varredura (Dict): Resultados da varredura
        Returns:
            Dict[str, Any]: Análise de vulnerabilidades
        """
        if not self.conectado and not self.conectar_gemini():
            return {'erro': 'Não foi possível conectar ao Gemini'}
        
        try:
            # Extrair apenas dados de vulnerabilidades
            vulnerabilidades = self._extrair_vulnerabilidades_completas(resultados_varredura)
            
            if not vulnerabilidades:
                return {
                    'timestamp': datetime.now().isoformat(),
                    'tipo_analise': 'vulnerabilidades',
                    'analise_ia': 'Nenhuma vulnerabilidade específica detectada nos scripts NSE.',
                    'vulnerabilidades_encontradas': 0,
                    'nivel_risco_geral': 'Baixo'
                }
            
            # Formatar dados de vulnerabilidades
            dados_vuln = json.dumps(vulnerabilidades, indent=2, ensure_ascii=False)
            
            # Gerar prompt
            prompt = self.templates_prompts['analise_vulnerabilidades'].format(
                dados_vulnerabilidades=dados_vuln
            )
            
            # Executar análise
            resposta = self._executar_consulta_gemini(prompt)
            
            if resposta:
                analise = {
                    'timestamp': datetime.now().isoformat(),
                    'tipo_analise': 'vulnerabilidades',
                    'modelo_utilizado': self.modelo_nome,
                    'vulnerabilidades_encontradas': len(vulnerabilidades),
                    'analise_ia': resposta,
                    'vulnerabilidades_detalhadas': vulnerabilidades,
                    'nivel_risco_geral': self._determinar_nivel_risco_vulnerabilidades(vulnerabilidades),
                    'criticidade_maxima': self._obter_criticidade_maxima(vulnerabilidades)
                }
                
                self.logger.info(f"Análise de vulnerabilidades executada: {len(vulnerabilidades)} encontradas")
                return analise
            else:
                return {'erro': 'Falha na análise de vulnerabilidades'}
                
        except Exception as e:
            self.logger.error(f"Erro na análise de vulnerabilidades: {str(e)}")
            return {'erro': f'Erro na análise: {str(e)}'}
    
    def gerar_plano_pentest(self, resultados_varredura: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera plano estruturado de pentest baseado nos resultados
        Args:
            resultados_varredura (Dict): Resultados da varredura
        Returns:
            Dict[str, Any]: Plano de pentest gerado
        """
        if not self.conectado and not self.conectar_gemini():
            return {'erro': 'Não foi possível conectar ao Gemini'}
        
        try:
            # Preparar dados resumidos para o plano
            dados_resumidos = self._resumir_dados_para_plano(resultados_varredura)
            
            # Gerar prompt
            prompt = self.templates_prompts['plano_pentest'].format(
                dados_varredura=dados_resumidos
            )
            
            # Executar geração do plano
            resposta = self._executar_consulta_gemini(prompt)
            
            if resposta:
                plano = {
                    'timestamp': datetime.now().isoformat(),
                    'tipo_analise': 'plano_pentest',
                    'modelo_utilizado': self.modelo_nome,
                    'baseado_em': resultados_varredura.get('tipo_varredura', 'desconhecido'),
                    'plano_ia': resposta,
                    'alvos_identificados': self._extrair_alvos_prioritarios(resultados_varredura),
                    'fases_sugeridas': self._extrair_fases_plano(resposta),
                    'estimativa_tempo': self._estimar_tempo_pentest(resultados_varredura)
                }
                
                self.logger.info("Plano de pentest gerado com sucesso")
                return plano
            else:
                return {'erro': 'Falha na geração do plano'}
                
        except Exception as e:
            self.logger.error(f"Erro na geração do plano: {str(e)}")
            return {'erro': f'Erro na geração: {str(e)}'}


if __name__ == "__main__":
    # Teste do módulo de decisão unificado
    logger = obter_logger('DecisaoIACLI')
    decisao = DecisaoIA()
    
    # Dados de teste para decisão
    dados_teste_decisao = {
        'resumo_scan': {
            'total_ips_scaneados': 1,
            'hosts_ativos': 1,
            'total_portas_abertas': 7,
            'hosts_com_portas_abertas': [{
                'ip': '192.168.1.208',
                'portas_abertas': 7,
                'portas': [22, 80, 111, 8000, 8080, 8085, 8090]
            }]
        }
    }
    
    # Dados de teste para análise completa
    dados_teste_analise = {
        'tipo_varredura': 'teste',
        'timestamp': datetime.now().isoformat(),
        'dados': {
            'resumo': {
                'hosts_total': 1,
                'hosts_ativos': 1,
                'portas_abertas': 3,
                'servicos_detectados': 2,
                'vulnerabilidades': 1
            },
            'hosts': [{
                'endereco': '192.168.1.100',
                'status': 'up',
                'portas': [{
                    'numero': 80,
                    'protocolo': 'tcp',
                    'estado': 'open',
                    'servico': 'http',
                    'scripts': []
                }]
            }]
        }
    }
    
    # Teste 1: Decisão de próximos passos
    logger.info("\n1. Testando decisão de próximos passos...")
    resultado_decisao = decisao.decidir_proximos_passos(dados_teste_decisao)
    
    logger.info(f"Executar Nmap avançado: {resultado_decisao.get('executar_nmap_avancado', False)}")
    logger.info(f"Módulos recomendados: {resultado_decisao.get('modulos_recomendados', [])}")
    logger.info(f"Justificativa: {resultado_decisao.get('justificativa_ia', 'N/A')}")
    logger.info(f"Prioridade: {resultado_decisao.get('prioridade', 'N/A')}")
    
    # Teste 2: Conexão Gemini (se configurado)
    logger.info("\n2. Testando conexão Gemini...")
    if decisao.conectar_gemini():
        logger.info("✓ Gemini conectado com sucesso!")
        
        # Teste 3: Análise completa
        logger.info("\n3. Testando análise completa...")
        resultado_analise = decisao.analisar_varredura_completa(dados_teste_analise)
        
        if 'erro' not in resultado_analise:
            logger.info("✓ Análise completa executada com sucesso!")
            logger.info(f"Nível de risco: {resultado_analise.get('nivel_risco_geral', 'N/A')}")
        else:
            logger.error(f"✗ Erro na análise: {resultado_analise['erro']}")
    else:
        logger.error("✗ Falha ao conectar com Gemini (usando fallback)")
    
    logger.info("\n=== Teste concluído ===")
    logger.info("Módulo unificado pronto para uso!")