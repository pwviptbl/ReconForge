"""
Agente de IA para tomada de decisões no loop de pentest
"""

import json
import time
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

from .config import get_config
from utils.logger import get_logger


class AIAgent:
    """Agente de IA para decisões no pentest"""
    
    def __init__(self):
        self.logger = get_logger('AIAgent')
        self.model = None
        self.connected = False
        self.last_prompt = None  # Para capturar o último prompt
        
        # Configurações
        self.api_key = get_config('ai.gemini.api_key')
        
        # Verificar variável de ambiente se não estiver configurada
        if not self.api_key or self.api_key == "YOUR_GEMINI_API_KEY_HERE":
            self.api_key = os.getenv('GEMINI_API_KEY')
        
        self.model_name = get_config('ai.gemini.model', 'gemini-2.0-flash-exp')
        self.timeout = get_config('ai.gemini.timeout', 30)
        self.max_retries = get_config('ai.gemini.max_retries', 3)
        
        # Conectar se configurado
        if self.api_key and self.api_key != "YOUR_GEMINI_API_KEY_HERE":
            self._connect()
        else:
            self.logger.warning("⚠️ Chave API do Gemini não configurada - usando fallback")
            self.logger.info("💡 Configure em config/default.yaml ou variável GEMINI_API_KEY")
    
    def _connect(self) -> bool:
        """Conecta com a API do Gemini"""
        if not GEMINI_AVAILABLE:
            self.logger.error("❌ google-generativeai não instalado")
            return False
        
        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(self.model_name)
            
            # Teste de conexão
            response = self.model.generate_content("Responda apenas: OK")
            
            if response and response.text:
                self.connected = True
                self.logger.info(f"✅ Conectado ao Gemini {self.model_name}")
                return True
            else:
                self.logger.error("❌ Teste de conexão falhou")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Erro ao conectar: {e}")
            return False
    
    def decide_next_action(self, context: Dict[str, Any], available_plugins: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Decide a próxima ação baseada no contexto atual
        
        Args:
            context: Contexto atual da varredura
            available_plugins: Lista de dicionários com informações dos plugins disponíveis
            
        Returns:
            Dict com a decisão da IA
        """
        if not self.connected:
            return self._fallback_decision(context, available_plugins)
        
        prompt = self._create_decision_prompt(context, available_plugins)
        self.last_prompt = prompt  # Salvar prompt para histórico
        
        try:
            response = self._query_gemini(prompt)
            if response:
                decision = self._parse_decision(response)
                if decision:
                    self.logger.info(f"🤖 IA decidiu: {decision.get('action', 'unknown')}")
                    return decision
        except Exception as e:
            self.logger.warning(f"⚠️ Erro na consulta IA: {e}")
        
        # Fallback
        return self._fallback_decision(context, available_plugins)
    
    def get_last_prompt(self) -> str:
        """Retorna o último prompt enviado à IA"""
        return self.last_prompt or "N/A"
    
    def _create_decision_prompt(self, context: Dict[str, Any], plugins: List[Dict[str, Any]]) -> str:
        """Cria prompt para decisão da IA"""
        
        # Resumir contexto
        target = context.get('target', 'unknown')
        iteration = context.get('current_iteration', 0)
        max_iterations = context.get('max_iterations', 20)
        discoveries = context.get('discoveries', {})
        vulnerabilities = context.get('vulnerabilities', [])
        plugin_states = context.get('plugin_states', {})

        # Formatar informações para o prompt
        plugin_states_summary = "\n".join([f"- {name}: {status}" for name, status in plugin_states.items()]) if plugin_states else "Nenhum plugin executado ainda."

        available_plugins_details = "\n".join([
            f"- {p.get('name')} ({p.get('category', 'N/A')}): {p.get('description', 'Sem descrição.')}"
            for p in plugins
        ]) if plugins else "Nenhum"
        
        # Estatísticas
        open_ports = len(discoveries.get('open_ports', []))
        services = len(discoveries.get('services', []))
        hosts = len(discoveries.get('hosts', []))
        
        return f"""Você é um especialista em pentesting. Analise o contexto atual e decida o próximo passo.

CONTEXTO ATUAL:
- Alvo: {target}
- Iteração: {iteration}/{max_iterations}
- Hosts descobertos: {hosts}
- Portas abertas: {open_ports}
- Serviços identificados: {services}
- Vulnerabilidades encontradas: {len(vulnerabilities)}

ESTADO DOS PLUGINS EXECUTADOS:
{plugin_states_summary}

PLUGINS DISPONÍVEIS PARA PRÓXIMA AÇÃO:
{available_plugins_details}

DESCOBERTAS ATUAIS (resumo):
{json.dumps(discoveries, indent=2, default=str)[:500]}...

VULNERABILIDADES (resumo):
{json.dumps(vulnerabilities, indent=2, default=str)[:300]}...

Baseado neste contexto, decida o próximo passo. Considere:
1. O estado dos plugins já executados. Se um plugin essencial falhou, avalie se vale a pena tentar outro similar ou mudar de tática.
2. A descrição dos plugins disponíveis para escolher o mais adequado ao momento da análise.
3. Priorizar plugins que podem revelar novas informações com base no que já foi descoberto.
4. Parar a análise se julgar que não há mais progresso a ser feito ou se o objetivo foi atingido.

Responda APENAS em formato JSON:
{{
    "action": "execute_plugin|stop",
    "plugin": "nome_do_plugin_se_aplicavel",
    "reasoning": "explicação concisa da sua decisão estratégica",
    "priority": "high|medium|low",
    "expected_findings": "o que você espera descobrir com esta ação"
}}

IMPORTANTE: Use EXATAMENTE os nomes dos plugins listados em "PLUGINS DISPONÍVEIS".
"""
    
    def _query_gemini(self, prompt: str) -> Optional[str]:
        """Consulta o Gemini com retry"""
        for attempt in range(self.max_retries):
            try:
                response = self.model.generate_content(prompt)
                if response and response.text:
                    return response.text.strip()
            except Exception as e:
                self.logger.warning(f"Tentativa {attempt + 1} falhou: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)  # Backoff exponencial
        
        return None
    
    def _parse_decision(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse da resposta JSON da IA"""
        try:
            # Procurar JSON na resposta
            start = response.find('{')
            end = response.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = response[start:end]
                decision = json.loads(json_str)
                
                # Validar campos obrigatórios
                if 'action' in decision and 'reasoning' in decision:
                    return decision
            
            return None
            
        except json.JSONDecodeError:
            self.logger.warning("Erro ao parsear JSON da resposta IA")
            return None
    
    def _fallback_decision(self, context: Dict[str, Any], plugins: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Decisão de fallback quando IA não está disponível"""
        if not self.api_key:
            self.logger.warning("⚠️ IA não configurada - usando lógica simples")
            self.logger.info("💡 Para usar IA real: configure GEMINI_API_KEY ou config/default.yaml")
        else:
            self.logger.info("💡 Usando lógica de fallback (erro na IA)")
        
        # Estratégia simples: priorizar por categoria
        priority_order = [
            'network',      # Descoberta inicial
            'web',          # Análise web
            'vulnerability' # Detecção de vulnerabilidades
        ]
        
        # Encontrar próximo plugin por prioridade
        for category in priority_order:
            for plugin_info in plugins:
                if plugin_info.get('category') == category:
                    return {
                        'action': 'execute_plugin',
                        'plugin': plugin_info['name'],
                        'reasoning': f'Executando próximo plugin da categoria {category}',
                        'priority': 'medium',
                        'expected_findings': 'Descobertas baseadas na categoria do plugin'
                    }

        # Se não encontrou por categoria, pegar o primeiro disponível
        if plugins:
            return {
                'action': 'execute_plugin',
                'plugin': plugins[0]['name'],
                'reasoning': 'Executando o próximo plugin disponível',
                'priority': 'low',
                'expected_findings': 'Nenhuma'
            }
        
        # Se não há plugins disponíveis, parar
        return {
            'action': 'stop',
            'reasoning': 'Todos os plugins foram executados ou não há plugins adequados',
            'priority': 'low',
            'expected_findings': 'Nenhuma'
        }
    
    def is_connected(self) -> bool:
        """Verifica se a IA está conectada"""
        return self.connected
