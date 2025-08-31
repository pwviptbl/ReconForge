#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agente IA Centralizado - Fase 1
Implementa um agente autônomo usando Gemini para decisões inteligentes
"""

import json
import re
from typing import Dict, Any, List
from dataclasses import dataclass, field

# Importações para Gemini
try:
    import google.generativeai as genai
    GEMINI_DISPONIVEL = True
except ImportError:
    GEMINI_DISPONIVEL = False


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

        # Verificar se temos chave API do Gemini
        if not self.config.get('chave_api'):
            raise ValueError("❌ Agente IA Central requer chave API do Gemini. Configure em config/default.yaml")

        # Inicializar conexão com Gemini
        self._inicializar_gemini()

        if callable(self.logger):
            self.logger("✅ Agente IA Central inicializado com Gemini")
        else:
            print("✅ Agente IA Central inicializado com Gemini")

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
        """Toma decisão autônoma baseada no contexto usando Gemini"""
        self.estado.contexto_atual = contexto_atual
        self.estado.iteracao_atual += 1

        # Criar prompt para o Gemini
        prompt = self._criar_prompt_decisao(contexto_atual, modulos_disponiveis)

        try:
            # Consultar Gemini
            resposta_gemini = self._consultar_gemini(prompt)

            # Parse da resposta
            decisao = self._parse_resposta_gemini(resposta_gemini)

            # Registrar decisão
            self.estado.decisoes_anteriores.append(decisao)
            if callable(self.logger):
                self.logger(f"🧠 Gemini decidiu: {decisao.get('acao')}")
            else:
                print(f"🧠 Gemini decidiu: {decisao.get('acao')}")

            return decisao

        except Exception as e:
            # Em caso de erro, retornar decisão padrão
            if callable(self.logger):
                self.logger(f"❌ Erro na decisão IA: {e}. Usando decisão padrão.")
            else:
                print(f"❌ Erro na decisão IA: {e}. Usando decisão padrão.")

            return self._decisao_padrao()

    def _criar_prompt_decisao(self, contexto: Dict[str, Any], modulos_disponiveis: List[str]) -> str:
        """Cria o prompt para consulta ao Gemini"""
        return f"""Você é um agente de segurança cibernética autônomo especializado em pentesting.
Sua missão é coordenar varreduras de vulnerabilidades de forma inteligente e segura.

CONTEXTO ATUAL:
- Iteração: {self.estado.iteracao_atual}
- Pontuação de risco: {self.estado.pontuacao_risco}/100
- Módulos já executados: {', '.join(self.estado.modulos_executados) or 'Nenhum'}
- IPs descobertos: {contexto.get('ips_descobertos', [])}
- Portas abertas: {contexto.get('portas_abertas', {})}
- Serviços detectados: {len(contexto.get('servicos_detectados', {}))}
- Vulnerabilidades encontradas: {len(contexto.get('vulnerabilidades_encontradas', []))}

MÓDULOS DISPONÍVEIS:
{', '.join(modulos_disponiveis)}

INSTRUÇÕES IMPORTANTES:
1. Sempre priorize a segurança e anonimização
2. Evite ações destrutivas ou invasivas sem justificativa clara
3. Use apenas módulos disponíveis na lista acima
4. Pare quando análise estiver completa ou risco for muito alto
5. Mantenha decisões consistentes e bem documentadas

Decida o próximo passo e responda APENAS em formato JSON:
{{
    "acao": "executar_modulo|parar",
    "modulo": "nome_do_modulo_se_aplicavel",
    "justificativa": "explicação_da_decisão",
    "prioridade": "alta|media|baixa",
    "expectativa": "o_que_espera_descobrir"
}}

EXEMPLOS:
- Para iniciar descoberta: {{"acao": "executar_modulo", "modulo": "scanner_portas_python", "justificativa": "Iniciar descoberta básica de portas", "prioridade": "alta", "expectativa": "Descobrir portas abertas"}}
- Para parar: {{"acao": "parar", "justificativa": "Análise abrangente concluída", "prioridade": "baixa", "expectativa": "Nenhuma"}}
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
        if 'parar' in resposta_lower or 'conclu' in resposta_lower:
            return {
                'acao': 'parar',
                'justificativa': 'Decisão baseada na resposta do Gemini',
                'prioridade': 'baixa'
            }

        # Tentar encontrar módulo mencionado
        modulos_conhecidos = ['scanner_portas_python', 'scanner_vulnerabilidades', 'nuclei_scan', 'scanner_web_avancado']
        for modulo in modulos_conhecidos:
            if modulo in resposta_lower:
                return {
                    'acao': 'executar_modulo',
                    'modulo': modulo,
                    'justificativa': 'Decisão baseada na resposta do Gemini',
                    'prioridade': 'media'
                }

        # Decisão padrão
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
        if modulo:
            self.estado.modulos_executados.append(modulo)

        # Atualizar pontuação de risco (lógica simples)
        if resultado_modulo.get('vulnerabilidades'):
            self.estado.pontuacao_risco += len(resultado_modulo['vulnerabilidades']) * 10

        self.estado.pontuacao_risco = min(self.estado.pontuacao_risco, 100)

    def finalizar(self):
        """Finaliza o agente"""
        self.estado.finalizado = True
        if callable(self.logger):
            self.logger("Agente IA Central finalizado")
        else:
            print("Agente IA Central finalizado")
