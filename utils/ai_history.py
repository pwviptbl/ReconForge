"""
Módulo para gerenciar histórico de interações com a IA
Permite análise de comportamento e melhorias no prompt
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import os

class AIHistoryManager:
    """Gerenciador de histórico de interações com IA"""
    
    def __init__(self, history_dir: str = "history"):
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(exist_ok=True)
        self.current_session = None
        self.session_file = None
        
    def start_session(self, target: str, mode: str = "auto") -> str:
        """Inicia uma nova sessão de histórico"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_id = f"session_{target.replace('.', '_')}_{timestamp}"
        
        self.current_session = {
            "session_id": session_id,
            "target": target,
            "mode": mode,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "total_iterations": 0,
            "ai_interactions": [],
            "plugins_executed": [],
            "discoveries_timeline": [],
            "metadata": {
                "ai_model": None,
                "ai_temperature": None,
                "total_tokens_used": 0,
                "avg_response_time": 0
            }
        }
        
        self.session_file = self.history_dir / f"{session_id}.json"
        self._save_session()
        return session_id
    
    def log_ai_interaction(self, iteration: int, context: Dict[str, Any], 
                          prompt: str, response: Dict[str, Any], 
                          response_time: float):
        """Registra uma interação com a IA"""
        if not self.current_session:
            return
            
        interaction = {
            "iteration": iteration,
            "timestamp": datetime.now().isoformat(),
            "context_summary": self._summarize_context(context),
            "prompt": {
                "content": prompt,
                "length": len(prompt),
                "contains_discoveries": "discoveries" in prompt.lower(),
                "contains_vulnerabilities": "vulnerabilidade" in prompt.lower() or "vulnerability" in prompt.lower()
            },
            "response": {
                "decision": response.get("decision"),
                "plugin": response.get("plugin"),
                "reasoning": response.get("reasoning", ""),
                "confidence": response.get("confidence", "unknown"),
                "response_time_seconds": response_time
            },
            "analysis": {
                "prompt_complexity": self._analyze_prompt_complexity(prompt),
                "reasoning_quality": self._analyze_reasoning_quality(response.get("reasoning", "")),
                "decision_pattern": self._categorize_decision(response)
            }
        }
        
        self.current_session["ai_interactions"].append(interaction)
        self.current_session["total_iterations"] = iteration
        self._update_metadata(response_time)
        self._save_session()
    
    def log_plugin_execution(self, plugin_name: str, execution_time: float, 
                           success: bool, discoveries_made: bool, 
                           error: str = None):
        """Registra execução de plugin"""
        if not self.current_session:
            return
            
        plugin_log = {
            "timestamp": datetime.now().isoformat(),
            "plugin_name": plugin_name,
            "execution_time": execution_time,
            "success": success,
            "discoveries_made": discoveries_made,
            "error": error,
            "iteration": self.current_session["total_iterations"]
        }
        
        self.current_session["plugins_executed"].append(plugin_log)
        self._save_session()
    
    def log_discovery(self, discovery_type: str, details: Dict[str, Any]):
        """Registra uma descoberta importante"""
        if not self.current_session:
            return
            
        discovery = {
            "timestamp": datetime.now().isoformat(),
            "type": discovery_type,  # 'port', 'service', 'vulnerability', 'technology'
            "details": details,
            "iteration": self.current_session["total_iterations"]
        }
        
        self.current_session["discoveries_timeline"].append(discovery)
        self._save_session()
    
    def end_session(self, final_stats: Dict[str, Any] = None):
        """Finaliza a sessão atual"""
        if not self.current_session:
            return
            
        self.current_session["end_time"] = datetime.now().isoformat()
        if final_stats:
            self.current_session["final_stats"] = final_stats
            
        # Calcular estatísticas finais
        self.current_session["session_stats"] = self._calculate_session_stats()
        self._save_session()
        
        session_id = self.current_session["session_id"]
        self.current_session = None
        self.session_file = None
        return session_id
    
    def get_session_analysis(self, session_id: str = None) -> Dict[str, Any]:
        """Retorna análise detalhada de uma sessão"""
        if session_id:
            session_file = self.history_dir / f"{session_id}.json"
            if not session_file.exists():
                return {"error": "Session not found"}
            with open(session_file, 'r', encoding='utf-8') as f:
                session = json.load(f)
        else:
            session = self.current_session
            
        if not session:
            return {"error": "No session data"}
            
        return {
            "session_overview": {
                "id": session["session_id"],
                "target": session["target"],
                "duration": self._calculate_duration(session),
                "total_iterations": session["total_iterations"],
                "plugins_count": len(session["plugins_executed"]),
                "discoveries_count": len(session["discoveries_timeline"])
            },
            "ai_behavior_analysis": self._analyze_ai_behavior(session),
            "plugin_performance": self._analyze_plugin_performance(session),
            "discovery_timeline": session["discoveries_timeline"],
            "improvement_suggestions": self._generate_improvement_suggestions(session)
        }
    
    def get_all_sessions(self) -> List[str]:
        """Retorna lista de todas as sessões"""
        return [f.stem for f in self.history_dir.glob("session_*.json")]
    
    def _summarize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Cria resumo do contexto para o histórico"""
        plugins_data = context.get("plugins_data", {})
        return {
            "target": context.get("target"),
            "current_iteration": context.get("current_iteration", 0),
            "plugins_executed_count": len([p for p in plugins_data.keys() if plugins_data[p]]),
            "discoveries_count": sum(len(data.get("discoveries", [])) if isinstance(data, dict) else 0 
                                   for data in plugins_data.values() if data),
            "has_vulnerabilities": any("vulnerabilities" in str(data).lower() 
                                     for data in plugins_data.values() if data)
        }
    
    def _analyze_prompt_complexity(self, prompt: str) -> Dict[str, Any]:
        """Analisa complexidade do prompt"""
        return {
            "length": len(prompt),
            "word_count": len(prompt.split()),
            "contains_json": "{" in prompt and "}" in prompt,
            "contains_lists": "[" in prompt and "]" in prompt,
            "technical_terms": sum(1 for term in ["port", "service", "vulnerability", "scan", "plugin"] 
                                 if term in prompt.lower())
        }
    
    def _analyze_reasoning_quality(self, reasoning: str) -> Dict[str, Any]:
        """Analisa qualidade do raciocínio da IA"""
        if not reasoning:
            return {"quality": "none", "length": 0}
            
        quality_indicators = {
            "mentions_context": any(word in reasoning.lower() 
                                  for word in ["anterior", "já", "executado", "descoberto"]),
            "explains_choice": any(word in reasoning.lower() 
                                 for word in ["porque", "pois", "devido", "razão"]),
            "mentions_next_steps": any(word in reasoning.lower() 
                                     for word in ["próximo", "seguir", "continuar"]),
            "technical_accuracy": any(word in reasoning.lower() 
                                    for word in ["porta", "serviço", "vulnerabilidade"])
        }
        
        quality_score = sum(quality_indicators.values())
        return {
            "quality": "high" if quality_score >= 3 else "medium" if quality_score >= 2 else "low",
            "score": quality_score,
            "length": len(reasoning),
            "indicators": quality_indicators
        }
    
    def _categorize_decision(self, response: Dict[str, Any]) -> str:
        """Categoriza o tipo de decisão da IA"""
        decision = response.get("decision", "unknown")
        plugin = response.get("plugin", "")
        
        if decision == "execute_plugin":
            if "nmap" in plugin.lower():
                return "deep_analysis"
            elif "web" in plugin.lower():
                return "web_investigation"
            elif "port" in plugin.lower() or "rust" in plugin.lower():
                return "port_discovery"
            elif "vuln" in plugin.lower() or "nuclei" in plugin.lower():
                return "vulnerability_search"
            else:
                return "reconnaissance"
        elif decision == "stop":
            return "termination"
        else:
            return "unknown"
    
    def _analyze_ai_behavior(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa padrões de comportamento da IA"""
        interactions = session.get("ai_interactions", [])
        if not interactions:
            return {}
            
        decisions = [i["response"]["decision"] for i in interactions]
        plugins_chosen = [i["response"]["plugin"] for i in interactions if i["response"]["plugin"]]
        reasoning_quality = [i["analysis"]["reasoning_quality"]["quality"] for i in interactions]
        
        return {
            "decision_patterns": {
                "most_common_decision": max(set(decisions), key=decisions.count) if decisions else None,
                "plugin_diversity": len(set(plugins_chosen)),
                "avg_response_time": sum(i["response"]["response_time_seconds"] for i in interactions) / len(interactions),
                "reasoning_quality_distribution": {
                    "high": reasoning_quality.count("high"),
                    "medium": reasoning_quality.count("medium"),
                    "low": reasoning_quality.count("low")
                }
            },
            "progression_analysis": self._analyze_decision_progression(interactions),
            "efficiency_metrics": self._calculate_efficiency_metrics(interactions, session)
        }
    
    def _analyze_plugin_performance(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa performance dos plugins"""
        plugins = session.get("plugins_executed", [])
        if not plugins:
            return {}
            
        plugin_stats = {}
        for plugin in plugins:
            name = plugin["plugin_name"]
            if name not in plugin_stats:
                plugin_stats[name] = {
                    "executions": 0,
                    "total_time": 0,
                    "successes": 0,
                    "discoveries": 0
                }
            
            plugin_stats[name]["executions"] += 1
            plugin_stats[name]["total_time"] += plugin["execution_time"]
            if plugin["success"]:
                plugin_stats[name]["successes"] += 1
            if plugin["discoveries_made"]:
                plugin_stats[name]["discoveries"] += 1
        
        # Calcular médias e eficiência
        for name, stats in plugin_stats.items():
            stats["avg_time"] = stats["total_time"] / stats["executions"]
            stats["success_rate"] = stats["successes"] / stats["executions"]
            stats["discovery_rate"] = stats["discoveries"] / stats["executions"]
        
        return plugin_stats
    
    def _analyze_decision_progression(self, interactions: List[Dict]) -> Dict[str, Any]:
        """Analisa progressão das decisões"""
        if len(interactions) < 2:
            return {}
            
        progression = []
        for i in range(1, len(interactions)):
            prev = interactions[i-1]["analysis"]["decision_pattern"]
            curr = interactions[i]["analysis"]["decision_pattern"]
            progression.append(f"{prev}->{curr}")
        
        return {
            "common_progressions": {prog: progression.count(prog) for prog in set(progression)},
            "shows_logical_flow": self._check_logical_flow(interactions),
            "repeats_patterns": len(progression) != len(set(progression))
        }
    
    def _check_logical_flow(self, interactions: List[Dict]) -> bool:
        """Verifica se há fluxo lógico nas decisões"""
        patterns = [i["analysis"]["decision_pattern"] for i in interactions]
        # Lógica simplificada: reconnaissance -> discovery -> analysis -> vulnerability_search
        logical_order = ["reconnaissance", "port_discovery", "deep_analysis", "vulnerability_search"]
        
        current_stage = 0
        for pattern in patterns:
            if pattern in logical_order:
                pattern_stage = logical_order.index(pattern)
                if pattern_stage >= current_stage:
                    current_stage = pattern_stage
                else:
                    return False  # Retrocesso ilógico
        return True
    
    def _calculate_efficiency_metrics(self, interactions: List[Dict], session: Dict[str, Any]) -> Dict[str, Any]:
        """Calcula métricas de eficiência"""
        discoveries = len(session.get("discoveries_timeline", []))
        total_time = sum(p["execution_time"] for p in session.get("plugins_executed", []))
        
        return {
            "discoveries_per_iteration": discoveries / len(interactions) if interactions else 0,
            "time_per_discovery": total_time / discoveries if discoveries > 0 else float('inf'),
            "iterations_efficiency": len(interactions) / max(discoveries, 1)
        }
    
    def _generate_improvement_suggestions(self, session: Dict[str, Any]) -> List[str]:
        """Gera sugestões de melhoria baseadas na análise"""
        suggestions = []
        
        behavior = session.get("session_stats", {}).get("ai_behavior_analysis", {})
        decision_patterns = behavior.get("decision_patterns", {})
        
        # Análise de qualidade do raciocínio
        reasoning_quality = decision_patterns.get("reasoning_quality_distribution", {})
        if reasoning_quality.get("low", 0) > reasoning_quality.get("high", 0):
            suggestions.append("Melhorar qualidade do prompt para raciocínio mais detalhado")
        
        # Análise de eficiência
        efficiency = behavior.get("efficiency_metrics", {})
        if efficiency.get("discoveries_per_iteration", 0) < 0.5:
            suggestions.append("Ajustar estratégia para aumentar taxa de descobertas")
        
        # Análise de diversidade de plugins
        if decision_patterns.get("plugin_diversity", 0) < 3:
            suggestions.append("Incentivar maior diversidade na escolha de plugins")
        
        return suggestions
    
    def _calculate_session_stats(self) -> Dict[str, Any]:
        """Calcula estatísticas finais da sessão"""
        if not self.current_session:
            return {}
            
        return {
            "ai_behavior_analysis": self._analyze_ai_behavior(self.current_session),
            "plugin_performance": self._analyze_plugin_performance(self.current_session),
            "overall_efficiency": self._calculate_overall_efficiency()
        }
    
    def _calculate_overall_efficiency(self) -> Dict[str, Any]:
        """Calcula eficiência geral da sessão"""
        session = self.current_session
        total_time = sum(p["execution_time"] for p in session.get("plugins_executed", []))
        discoveries = len(session.get("discoveries_timeline", []))
        iterations = session.get("total_iterations", 0)
        
        return {
            "total_execution_time": total_time,
            "discoveries_made": discoveries,
            "iterations_used": iterations,
            "efficiency_score": discoveries / max(iterations, 1) if iterations > 0 else 0
        }
    
    def _calculate_duration(self, session: Dict[str, Any]) -> float:
        """Calcula duração da sessão em segundos"""
        if not session.get("end_time"):
            return 0
            
        start = datetime.fromisoformat(session["start_time"])
        end = datetime.fromisoformat(session["end_time"])
        return (end - start).total_seconds()
    
    def _update_metadata(self, response_time: float):
        """Atualiza metadados da sessão"""
        metadata = self.current_session["metadata"]
        
        # Atualizar tempo médio de resposta
        interactions_count = len(self.current_session["ai_interactions"])
        if interactions_count == 1:
            metadata["avg_response_time"] = response_time
        else:
            current_avg = metadata["avg_response_time"]
            metadata["avg_response_time"] = (current_avg * (interactions_count - 1) + response_time) / interactions_count
    
    def _save_session(self):
        """Salva sessão atual no arquivo"""
        if self.current_session and self.session_file:
            with open(self.session_file, 'w', encoding='utf-8') as f:
                json.dump(self.current_session, f, indent=2, ensure_ascii=False)
