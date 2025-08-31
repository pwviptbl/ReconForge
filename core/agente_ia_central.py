#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agente IA Centralizado - Fase 2
Implementa um agente autônomo usando Gemini e aprendizado de máquina
para decisões inteligentes e adaptáveis
"""

import json
import re
import time
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field

# Importações para Gemini
try:
    import google.generativeai as genai
    GEMINI_DISPONIVEL = True
except ImportError:
    GEMINI_DISPONIVEL = False

# Importação do sistema de aprendizado de máquina
from historico_ia.gerenciador_historico import obter_aprendizado_maquina


@dataclass
class EstadoAgente:
    """Estado atual do agente IA"""
    contexto_atual: Dict[str, Any] = field(default_factory=dict)
    decisoes_anteriores: List[Dict] = field(default_factory=list)
    modulos_executados: List[str] = field(default_factory=list)
    pontuacao_risco: int = 0
    iteracao_atual: int = 0
    finalizado: bool = False


class AgenteIACentral:
    """Agente IA centralizado usando Gemini para decisões autônomas"""

    def __init__(self, config_ia: Dict[str, Any], logger_func=None):
        self.logger = logger_func if logger_func else print
        self.config = config_ia
        self.estado = EstadoAgente()
        
        # Inicializar sistema de aprendizado de máquina
        try:
            self.ml = obter_aprendizado_maquina()
            self.ml_disponivel = True
            self.log("✅ Sistema de aprendizado de máquina inicializado")
            
            # Carregar modelos existentes ou treinar novos se necessário
            self._inicializar_ml()
        except Exception as e:
            self.ml_disponivel = False
            self.log(f"⚠️ Sistema de aprendizado de máquina não disponível: {e}")

        # Verificar se temos chave API do Gemini
        if not self.config.get('chave_api'):
            raise ValueError("❌ Agente IA Central requer chave API do Gemini. Configure em config/default.yaml")

        # Inicializar conexão com Gemini
        self._inicializar_gemini()

        self.log("✅ Agente IA Central inicializado com Gemini e Aprendizado de Máquina")
    
    def log(self, mensagem: str):
        """Método auxiliar para log uniforme"""
        if callable(self.logger):
            self.logger(mensagem)
        else:
            print(mensagem)

    def _inicializar_ml(self):
        """Inicializa o sistema de aprendizado de máquina"""
        if not self.ml_disponivel:
            return
        
        try:
            # Tentar carregar modelos existentes
            resultado_carregamento = self.ml.carregar_modelos_salvos()
            
            if not resultado_carregamento or 'erro' in resultado_carregamento:
                self.log("⚠️ Nenhum modelo encontrado. Carregando dados para treinamento...")
                
                # Processar dados
                df = self.ml.carregar_e_processar_dados()
                
                if df is not None and not df.empty:
                    self.log(f"✅ Dados carregados com sucesso: {len(df)} registros")
                    
                    # Treinar modelos
                    self.log("🧠 Treinando modelos de aprendizado de máquina...")
                    resultados = self.ml.treinar_modelos()
                    
                    if resultados:
                        self.log("✅ Modelos treinados com sucesso")
                    else:
                        self.log("⚠️ Não foi possível treinar os modelos")
            else:
                self.log(f"✅ Modelos carregados: {', '.join(k for k, v in resultado_carregamento.items() if v == 'carregado')}")
                
            # Analisar tendências
            try:
                tendencias = self.ml.analisar_tendencias()
                if tendencias and 'erro' not in tendencias:
                    self.log(f"📊 Análise de tendências: Taxa de sucesso {tendencias.get('tendencia_sucesso', {}).get('taxa_atual', 0)}%")
            except:
                pass
                
        except Exception as e:
            self.log(f"⚠️ Erro ao inicializar sistema ML: {e}")
            self.ml_disponivel = False
    
    def _inicializar_gemini(self):
        """Inicializa a conexão com Gemini"""
        if not GEMINI_DISPONIVEL:
            raise ImportError("❌ google-generativeai não está instalado. Instale com: pip install google-generativeai")

        try:
            genai.configure(api_key=self.config['chave_api'])
            self.modelo = genai.GenerativeModel(
                model_name=self.config.get('modelo_principal', 'gemini-2.5-flash'),
                generation_config={
                    'temperature': self.config.get('temperatura', 0.3),
                    'max_output_tokens': self.config.get('contexto_max_tokens', 4000),
                }
            )

            # Teste de conexão
            teste_response = self.modelo.generate_content("Responda apenas: OK")
            if not teste_response or not hasattr(teste_response, 'text'):
                raise ConnectionError("❌ Falha na resposta de teste do Gemini")

        except Exception as e:
            raise ConnectionError(f"❌ Erro ao conectar com Gemini: {e}")

    def _consultar_gemini(self, prompt: str) -> str:
        """Consulta o Gemini com o prompt fornecido"""
        try:
            response = self.modelo.generate_content(prompt)
            if response and hasattr(response, 'text'):
                return response.text.strip()
            else:
                raise ValueError("Resposta inválida do Gemini")
        except Exception as e:
            if callable(self.logger):
                self.logger(f"❌ Erro na consulta Gemini: {e}")
            else:
                print(f"❌ Erro na consulta Gemini: {e}")
            raise

    def tomar_decisao(self, contexto_atual: Dict[str, Any], modulos_disponiveis: List[str]) -> Dict[str, Any]:
        """
        Toma decisão autônoma baseada no contexto usando Gemini e aprendizado de máquina
        Fase 2: Combina decisões de IA com recomendações de ML
        """
        self.estado.contexto_atual = contexto_atual
        self.estado.iteracao_atual += 1
        
        # Obter recomendações do sistema ML (se disponível)
        recomendacao_ml = self._obter_recomendacao_ml(contexto_atual, modulos_disponiveis)
        
        # Incluir recomendações de ML no contexto para o Gemini
        prompt = self._criar_prompt_decisao(contexto_atual, modulos_disponiveis, recomendacao_ml)

        try:
            # Consultar Gemini
            inicio = time.time()
            resposta_gemini = self._consultar_gemini(prompt)
            tempo_resposta = time.time() - inicio

            # Parse da resposta
            decisao = self._parse_resposta_gemini(resposta_gemini)
            
            # Adicionar metadados do ML
            if recomendacao_ml:
                decisao['metadados_ml'] = {
                    'recomendacao_usada': decisao.get('modulo') in recomendacao_ml.get('modulos_sugeridos', []),
                    'confianca_ml': recomendacao_ml.get('confianca', 'baixa')
                }

            # Registrar decisão
            self.estado.decisoes_anteriores.append(decisao)
            self.log(f"🧠 Agente híbrido decidiu: {decisao.get('acao')} - {decisao.get('modulo', '')}")
            
            # Feedback para o sistema de ML (para aprendizado contínuo)
            self._registrar_feedback_ml(decisao, contexto_atual, tempo_resposta)

            return decisao

        except Exception as e:
            # Em caso de erro, usar recomendações de ML ou decisão padrão
            self.log(f"❌ Erro na decisão IA: {e}. Tentando usar recomendação ML.")
            
            if recomendacao_ml and 'modulos_sugeridos' in recomendacao_ml and recomendacao_ml['modulos_sugeridos']:
                modulo_sugerido = recomendacao_ml['modulos_sugeridos'][0]
                return {
                    'acao': 'executar_modulo',
                    'modulo': modulo_sugerido,
                    'justificativa': 'Decisão baseada em aprendizado de máquina (fallback)',
                    'prioridade': 'media',
                    'expectativa': 'Seguindo padrão histórico de sucesso',
                    'origem': 'ml_fallback'
                }
            else:
                return self._decisao_padrao()
    
    def _obter_recomendacao_ml(self, contexto: Dict[str, Any], modulos_disponiveis: List[str]) -> Dict[str, Any]:
        """
        Obtém recomendações do sistema de aprendizado de máquina
        """
        if not self.ml_disponivel:
            return {}
        
        try:
            # Filtrar módulos que já foram executados
            modulos_executados = contexto.get('modulos_executados', [])
            modulos_disponiveis_filtrados = [m for m in modulos_disponiveis if m not in modulos_executados]
            
            if not modulos_disponiveis_filtrados:
                return {'sugestao': 'parar', 'motivo': 'Todos os módulos já foram executados'}
            
            # Pedir sugestão ao sistema ML
            sugestao = self.ml.sugerir_modulos(contexto)
            
            # Verificar se as sugestões estão na lista de módulos disponíveis
            if sugestao and 'modulos_sugeridos' in sugestao:
                sugestao['modulos_sugeridos'] = [
                    m for m in sugestao['modulos_sugeridos'] 
                    if m in modulos_disponiveis_filtrados
                ]
            
            # Checar se o sistema ML detecta anomalias no padrão atual
            try:
                # Converter contexto para formato compatível
                dados_contexto = {
                    'num_modulos': len(contexto.get('modulos_executados', [])),
                    'ips_descobertos': len(contexto.get('ips_descobertos', [])),
                    'total_portas': sum(len(portas) for portas in contexto.get('portas_abertas', {}).values()),
                    'vulnerabilidades': len(contexto.get('vulnerabilidades_encontradas', [])),
                }
                
                anomalia = self.ml.detectar_anomalias(dados_contexto)
                if anomalia and 'anomalia_detectada' in anomalia:
                    sugestao['anomalia'] = anomalia
            except:
                pass
            
            return sugestao
        except Exception as e:
            self.log(f"⚠️ Erro ao obter recomendação ML: {e}")
            return {}

    def _criar_prompt_decisao(self, contexto: Dict[str, Any], modulos_disponiveis: List[str], 
                         recomendacao_ml: Dict[str, Any] = None) -> str:
        """Cria o prompt para consulta ao Gemini, incluindo recomendações de ML"""
        # Usar o contexto passado em vez do estado interno para evitar dessincronização
        modulos_executados = contexto.get('modulos_executados', [])
        pontuacao_risco = contexto.get('pontuacao_risco', 0)
        iteracao_atual = self.estado.iteracao_atual
        
        # Seção de recomendações ML (se disponível)
        secao_ml = ""
        if recomendacao_ml and 'modulos_sugeridos' in recomendacao_ml and recomendacao_ml['modulos_sugeridos']:
            modulos_sugeridos = recomendacao_ml['modulos_sugeridos']
            confianca = recomendacao_ml.get('confianca', 'média')
            
            secao_ml = f"""
RECOMENDAÇÕES DE APRENDIZADO DE MÁQUINA:
- Confiança da recomendação: {confianca}
- Módulos recomendados com base em padrões históricos: {', '.join(modulos_sugeridos)}
"""
            
            # Adicionar informações de anomalias se disponíveis
            if 'anomalia' in recomendacao_ml and recomendacao_ml['anomalia'].get('anomalia_detectada', False):
                secao_ml += f"- ALERTA: Padrão anômalo detectado na varredura atual. {recomendacao_ml['anomalia'].get('recomendacao', '')}\n"
        
        return f"""Você é um agente de segurança cibernética autônomo especializado em pentesting.
Sua missão é coordenar varreduras de vulnerabilidades de forma inteligente e segura.
Você trabalha em conjunto com um sistema de aprendizado de máquina que analisa padrões históricos.

CONTEXTO ATUAL:
- Iteração: {iteracao_atual}
- Pontuação de risco: {pontuacao_risco}/100
- Módulos já executados: {', '.join(modulos_executados) or 'Nenhum'}
- IPs descobertos: {contexto.get('ips_descobertos', [])}
- Portas abertas: {contexto.get('portas_abertas', {})}
- Serviços detectados: {len(contexto.get('servicos_detectados', {}))}
- Vulnerabilidades encontradas: {len(contexto.get('vulnerabilidades_encontradas', []))}
{secao_ml}
MÓDULOS DISPONÍVEIS:
{', '.join(modulos_disponiveis)}

INSTRUÇÕES IMPORTANTES:
1. Sempre priorize a segurança e anonimização
2. Evite ações destrutivas ou invasivas sem justificativa clara
3. Use apenas módulos disponíveis na lista acima
4. Pare quando análise estiver completa ou risco for muito alto
5. Mantenha decisões consistentes e bem documentadas
6. EVITE REPETIR MÓDULOS JÁ EXECUTADOS - escolha sempre módulos diferentes
7. Se já executou vários módulos de Nmap, passe para outros tipos de análise
8. CONSIDERE AS RECOMENDAÇÕES DE ML - elas são baseadas em padrões históricos de sucesso

Decida o próximo passo e responda APENAS em formato JSON:
{{
    "acao": "executar_modulo|parar",
    "modulo": "nome_do_modulo_se_aplicavel",
    "justificativa": "explicação_da_decisão",
    "prioridade": "alta|media|baixa",
    "expectativa": "o_que_espera_descobrir",
    "considera_ml": "sim|parcial|nao"
}}

EXEMPLOS:
- Para iniciar descoberta: {{"acao": "executar_modulo", "modulo": "scanner_portas_python", "justificativa": "Iniciar descoberta básica de portas", "prioridade": "alta", "expectativa": "Descobrir portas abertas", "considera_ml": "sim"}}
- Para análise web: {{"acao": "executar_modulo", "modulo": "scanner_web_avancado", "justificativa": "Analisar vulnerabilidades web nas portas descobertas", "prioridade": "alta", "expectativa": "Encontrar vulnerabilidades web", "considera_ml": "parcial"}}
- Para parar: {{"acao": "parar", "justificativa": "Análise abrangente concluída", "prioridade": "baixa", "expectativa": "Nenhuma", "considera_ml": "sim"}}
"""

    def _parse_resposta_gemini(self, resposta: str) -> Dict[str, Any]:
        """Parse da resposta do Gemini para formato padronizado"""
        try:
            # Tentar encontrar JSON na resposta
            json_match = re.search(r'\{.*\}', resposta, re.DOTALL)
            if json_match:
                resposta_json = json_match.group()
                return json.loads(resposta_json)
            else:
                # Se não encontrar JSON, tentar extrair informações
                return self._extrair_decisao_texto(resposta)

        except json.JSONDecodeError:
            # Se JSON inválido, tentar extrair do texto
            return self._extrair_decisao_texto(resposta)

    def _extrair_decisao_texto(self, resposta: str) -> Dict[str, Any]:
        """Extrai decisão de resposta textual quando JSON falha"""
        resposta_lower = resposta.lower()

        # Verificar se deve parar
        if 'parar' in resposta_lower or 'conclu' in resposta_lower or 'final' in resposta_lower:
            return {
                'acao': 'parar',
                'justificativa': 'Decisão baseada na resposta do Gemini',
                'prioridade': 'baixa'
            }

        # Lista de módulos por prioridade (evitando repetições de Nmap)
        modulos_prioridade = [
            'scanner_vulnerabilidades',  # Prioridade alta para vulnerabilidades
            'nuclei_scan',               # Scanner de vulnerabilidades
            'scanner_web_avancado',      # Análise web
            'detector_tecnologias_python', # Detecção de tecnologias
            'scanner_diretorios_python',   # Scanner de diretórios
            'buscador_exploits_python',    # Busca de exploits
            'analisador_vulnerabilidades_web_python', # Análise web específica
            'enumerador_subdominios_python', # Enumeração de subdomínios
            'scraper_auth',               # Web scraping com auth
            'navegador_web',              # Navegação web
            'navegador_web_gemini',       # Navegação com Gemini
            'sqlmap_teste_url',           # Teste SQL injection
            'sqlmap_teste_formulario'     # Teste SQL em formulários
        ]

        # Verificar se algum módulo prioritário é mencionado
        for modulo in modulos_prioridade:
            if modulo.lower().replace('_', ' ') in resposta_lower or modulo in resposta_lower:
                return {
                    'acao': 'executar_modulo',
                    'modulo': modulo,
                    'justificativa': 'Decisão baseada na resposta do Gemini',
                    'prioridade': 'alta' if modulo in ['scanner_vulnerabilidades', 'nuclei_scan'] else 'media'
                }

        # Se nada específico for encontrado, usar decisão padrão de parar
        return self._decisao_padrao()
        return self._decisao_padrao()

    def _decisao_padrao(self) -> Dict[str, Any]:
        """Decisão padrão quando tudo falha"""
        return {
            'acao': 'parar',
            'justificativa': 'Decisão padrão - erro na IA',
            'prioridade': 'baixa'
        }

    def atualizar_estado(self, resultado_modulo: Dict[str, Any]):
        """Atualiza estado interno com resultado de módulo"""
        modulo = resultado_modulo.get('modulo', '')
        if modulo and modulo not in self.estado.modulos_executados:
            self.estado.modulos_executados.append(modulo)
            if callable(self.logger):
                self.logger(f"Agente IA Central: módulo {modulo} registrado como executado")
            else:
                print(f"Agente IA Central: módulo {modulo} registrado como executado")

        # Atualizar pontuação de risco baseada no resultado
        vulnerabilidades = resultado_modulo.get('vulnerabilidades', [])
        if vulnerabilidades:
            self.estado.pontuacao_risco += len(vulnerabilidades) * 10

        # Aumentar risco se o módulo foi bem-sucedido (mais informações = mais risco potencial)
        if resultado_modulo.get('sucesso', False):
            self.estado.pontuacao_risco += 5

        self.estado.pontuacao_risco = min(self.estado.pontuacao_risco, 100)

        if callable(self.logger):
            self.logger(f"Agente IA Central: pontuação de risco atualizada para {self.estado.pontuacao_risco}")
        else:
            print(f"Agente IA Central: pontuação de risco atualizada para {self.estado.pontuacao_risco}")

    def _registrar_feedback_ml(self, decisao: Dict[str, Any], contexto: Dict[str, Any], tempo_resposta: float):
        """
        Registra feedback para o sistema de ML
        Este feedback será usado para melhorar as recomendações futuras
        """
        if not self.ml_disponivel:
            return
        
        try:
            # Converter decisão e contexto para formato adequado para feedback
            feedback = {
                'decisao': decisao.get('acao'),
                'modulo_escolhido': decisao.get('modulo', ''),
                'modulos_executados_anteriormente': contexto.get('modulos_executados', []),
                'total_modulos_executados': len(contexto.get('modulos_executados', [])),
                'portas_encontradas': sum(len(portas) for portas in contexto.get('portas_abertas', {}).values()),
                'vulnerabilidades_encontradas': len(contexto.get('vulnerabilidades_encontradas', [])),
                'iteracao': self.estado.iteracao_atual,
                'tempo_decisao': tempo_resposta
            }
            
            # Aqui podemos implementar a lógica de feedback para melhorar o modelo
            # Por exemplo, armazenar os padrões de decisão para retreinar o modelo
            # periodicamente ou em tempo real
            
            # No futuro, podemos adicionar uma API no sistema ML para receber feedback
            pass
            
        except Exception as e:
            self.log(f"⚠️ Erro ao registrar feedback para ML: {e}")
    
    def finalizar(self):
        """Finaliza o agente"""
        self.estado.finalizado = True
        
        # Se tiver ML disponível, salvar análises ou treinar modelos finais
        if self.ml_disponivel:
            try:
                # Analisar tendências finais
                tendencias = self.ml.analisar_tendencias()
                if tendencias and 'erro' not in tendencias:
                    self.log(f"📊 Análise final de tendências: {tendencias.get('modulos_mais_utilizados', {})}")
            except:
                pass
        
        self.log("Agente IA Central finalizado")
