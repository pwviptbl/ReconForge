"""
Sistema simples de log de conversas com IA
Salva prompts e respostas em formato texto legível
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any


class SimpleAILogger:
    """Logger simples para conversas com IA"""
    
    def __init__(self, history_dir: str = "history"):
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(exist_ok=True)
        self.current_session_file = None
        self.session_id = None
        
    def start_session(self, target: str) -> str:
        """Inicia uma nova sessão de log"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_id = f"conversation_{target.replace('.', '_')}_{timestamp}"
        
        self.current_session_file = self.history_dir / f"{self.session_id}.txt"
        
        # Cabeçalho do arquivo
        with open(self.current_session_file, 'w', encoding='utf-8') as f:
            f.write(f"""
=================================================================
                    VARREDURA IA - LOG DE CONVERSAS
=================================================================
Sessão: {self.session_id}
Alvo: {target}
Início: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}
=================================================================

""")
        
        return self.session_id
    
    def log_interaction(self, iteration: int, prompt: str, response: Dict[str, Any], 
                       response_time: float, context_summary: str = ""):
        """Registra uma interação com a IA"""
        if not self.current_session_file:
            return
            
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Extrair informações da resposta
        action = response.get('action', 'unknown')
        plugin = response.get('plugin', 'N/A')
        reasoning = response.get('reasoning', 'N/A')
        
        with open(self.current_session_file, 'a', encoding='utf-8') as f:
            f.write(f"""
--- ITERAÇÃO {iteration} ({timestamp}) ---

CONTEXTO ATUAL:
{context_summary}

PROMPT ENVIADO:
{prompt}

RESPOSTA DA IA (tempo: {response_time:.2f}s):
• Ação: {action}
• Plugin: {plugin}
• Raciocínio: {reasoning}

""")
    
    def log_plugin_execution(self, plugin_name: str, execution_time: float, 
                           success: bool, discoveries: str = "", error: str = ""):
        """Registra execução de plugin"""
        if not self.current_session_file:
            return
            
        timestamp = datetime.now().strftime("%H:%M:%S")
        status = "✅ SUCESSO" if success else "❌ FALHA"
        
        with open(self.current_session_file, 'a', encoding='utf-8') as f:
            f.write(f"""
🔌 EXECUÇÃO DE PLUGIN ({timestamp})
Plugin: {plugin_name}
Status: {status}
Tempo: {execution_time:.2f}s
""")
            
            if discoveries:
                f.write(f"Descobertas: {discoveries}\n")
            
            if error:
                f.write(f"Erro: {error}\n")
                
            f.write("\n")
    
    def log_discovery(self, discovery_type: str, details: str):
        """Registra uma descoberta importante"""
        if not self.current_session_file:
            return
            
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        with open(self.current_session_file, 'a', encoding='utf-8') as f:
            f.write(f"""
🔍 DESCOBERTA ({timestamp})
Tipo: {discovery_type}
Detalhes: {details}

""")
    
    def end_session(self, stats: Dict[str, Any] = None):
        """Finaliza a sessão"""
        if not self.current_session_file:
            return
            
        end_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        with open(self.current_session_file, 'a', encoding='utf-8') as f:
            f.write(f"""
=================================================================
RESUMO FINAL DA SESSÃO
=================================================================
Fim: {end_time}
""")
            
            if stats:
                f.write(f"""
Estatísticas:
• Duração: {stats.get('duration_seconds', 0):.1f}s
• Plugins executados: {stats.get('plugins_executed', 0)}
• Vulnerabilidades encontradas: {stats.get('vulnerabilities_found', 0)}
• Iterações utilizadas: {stats.get('iterations_used', 0)}
""")
            
            f.write("""
=================================================================
""")
        
        session_id = self.session_id
        self.current_session_file = None
        self.session_id = None
        return session_id
    
    def create_context_summary(self, context: Dict[str, Any]) -> str:
        """Cria resumo legível do contexto"""
        target = context.get('target', 'N/A')
        iteration = context.get('current_iteration', 0)
        
        # Contar descobertas
        plugins_data = context.get('plugins_data', {})
        total_hosts = len(context.get('hosts', []))
        total_ports = len(context.get('open_ports', []))
        total_services = len(context.get('services', []))
        total_vulns = len(context.get('vulnerabilities', []))
        
        # Plugins executados
        executed_plugins = context.get('executed_plugins', [])
        
        summary = f"""Alvo: {target}
Iteração: {iteration}
Hosts descobertos: {total_hosts}
Portas abertas: {total_ports}
Serviços identificados: {total_services}
Vulnerabilidades: {total_vulns}
Plugins executados: {', '.join(executed_plugins) if executed_plugins else 'Nenhum'}"""
        
        return summary
    
    def get_all_sessions(self) -> list:
        """Lista todas as sessões de conversa"""
        txt_files = list(self.history_dir.glob("conversation_*.txt"))
        return [f.stem for f in sorted(txt_files, reverse=True)]
    
    def read_session(self, session_id: str) -> str:
        """Lê o conteúdo completo de uma sessão"""
        session_file = self.history_dir / f"{session_id}.txt"
        
        if not session_file.exists():
            return f"Sessão {session_id} não encontrada."
            
        with open(session_file, 'r', encoding='utf-8') as f:
            return f.read()
