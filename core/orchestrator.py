"""
Orquestrador principal do VarreduraIA
Coordena o loop de IA e execução de plugins
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from .config import get_config
from .plugin_manager import PluginManager
from .ai_agent import AIAgent
from utils.logger import get_logger
from utils.ai_history import AIHistoryManager
from utils.simple_ai_logger import SimpleAILogger


class PentestOrchestrator:
    """Orquestrador principal do sistema"""
    
    def __init__(self, config_file: Optional[str] = None, verbose: bool = False, manual_mode: bool = False):
        self.logger = get_logger('Orchestrator')
        self.config_file = config_file
        self.manual_mode = manual_mode
        
        # Inicializar componentes
        self.plugin_manager = PluginManager()
        self.ai_agent = AIAgent()
        self.history_manager = AIHistoryManager()
        self.simple_logger = SimpleAILogger()  # Logger simples de conversas
        
        # Estado do pentest
        self.context = {}
        self.results = {}
        self.session_id = None
        
        self.logger.info("🎯 VarreduraIA Orquestrador inicializado")
    
    def run_pentest(self, target: str, max_iterations: int = 20) -> Dict[str, Any]:
        """
        Executa pentest completo no alvo

        Args:
            target: Alvo da varredura
            max_iterations: Número máximo de iterações

        Returns:
            Dict com resultados do pentest
        """
        self.logger.info(f"🚀 Iniciando pentest: {target}")
        
        # Iniciar sessão de histórico (sistema completo)
        self.session_id = self.history_manager.start_session(target)
        
        # Iniciar logger simples de conversas
        self.simple_session_id = self.simple_logger.start_session(target)
        
        # Inicializar contexto
        self.context = {
            'target': target,
            'max_iterations': max_iterations,
            'current_iteration': 0,
            'start_time': datetime.now(),
            'executed_plugins': [],
            'plugin_states': {},  # Rastreia o estado de cada plugin (success, failed)
            'discoveries': {
                'hosts': [],
                'open_ports': [],
                'services': [],
                'technologies': []
            },
            'vulnerabilities': [],
            'errors': [],
            'manual_mode': self.manual_mode
        }
        
        try:
            # Executar loop principal
            self._run_main_loop()
            
            # Gerar relatório final
            report_path = self._generate_report()
            
            end_time = datetime.now()
            duration = (end_time - self.context['start_time']).total_seconds()
            
            # Resultado final
            result = {
                'success': True,
                'target': target,
                'duration_seconds': duration,
                'iterations_completed': self.context['current_iteration'],
                'plugins_executed': len(self.context['executed_plugins']),
                'vulnerabilities_found': len(self.context['vulnerabilities']),
                'discoveries': self.context['discoveries'],
                'report_path': report_path,
                'context': self.context
            }
            
            # Finalizar sessão de histórico
            final_stats = {
                "duration_seconds": duration,
                "plugins_executed": len(self.context['executed_plugins']),
                "vulnerabilities_found": len(self.context['vulnerabilities']),
                "iterations_used": self.context['current_iteration']
            }
            self.history_manager.end_session(final_stats)
            
            # Finalizar logger simples
            self.simple_logger.end_session(final_stats)
            
            self.logger.info(f"✅ Pentest concluído em {duration:.1f}s")
            self.logger.info(f"📊 {len(self.context['executed_plugins'])} plugins, "
                           f"{len(self.context['vulnerabilities'])} vulnerabilidades")
            
            return result
            
        except Exception as e:
            self.logger.error(f"💥 Erro no pentest: {e}")
            return {
                'success': False,
                'error': str(e),
                'target': target,
                'context': self.context
            }
    
    def _run_main_loop(self):
        """Loop principal de execução"""
        self.logger.info("🔄 Iniciando loop principal de IA")
        
        # NOVA FUNCIONALIDADE: Executar plugins obrigatórios primeiro
        mandatory_plugins = self._get_mandatory_plugins()
        if mandatory_plugins:
            self.logger.info(f"🎯 Executando {len(mandatory_plugins)} plugins obrigatórios primeiro")
            self._execute_mandatory_plugins(mandatory_plugins)
        
        no_progress_count = 0
        max_no_progress = get_config('loop.auto_stop.no_progress_limit', 3)
        
        while self.context['current_iteration'] < self.context['max_iterations']:
            self.context['current_iteration'] += 1
            iteration = self.context['current_iteration']
            
            self.logger.info(f"🔄 Iteração {iteration}/{self.context['max_iterations']}")
            
            # Obter plugins disponíveis
            available_plugins = self._get_available_plugins()
            
            if not available_plugins:
                self.logger.info("🛑 Nenhum plugin disponível, parando")
                break
            
            # Decidir próxima ação: manual ou IA
            if self.context.get('manual_mode', False):
                decision = self._run_manual_iteration(available_plugins)
            else:
                # Consultar IA para próxima ação (capturar para histórico)
                ai_start_time = time.time()
                decision = self.ai_agent.decide_next_action(self.context, available_plugins)
                ai_response_time = time.time() - ai_start_time

                # Registrar interação com IA no histórico
                prompt_context = self.ai_agent.get_last_prompt() if hasattr(self.ai_agent, 'get_last_prompt') else "N/A"
                self.history_manager.log_ai_interaction(
                    iteration=iteration,
                    context=self.context,
                    prompt=prompt_context,
                    response=decision,
                    response_time=ai_response_time
                )

                # Registrar no logger simples de conversas
                context_summary = self.simple_logger.create_context_summary(self.context)
                self.simple_logger.log_interaction(
                    iteration=iteration,
                    prompt=prompt_context,
                    response=decision,
                    response_time=ai_response_time,
                    context_summary=context_summary
                )
            
            if decision['action'] == 'stop':
                self.logger.info(f"🛑 IA decidiu parar: {decision['reasoning']}")
                break
            
            elif decision['action'] == 'execute_plugin':
                plugin_name = decision.get('plugin')
                
                if not plugin_name:
                    self.logger.warning("⚠️ IA não especificou plugin, pulando iteração")
                    continue
                
                # Executar plugin
                progress_made = self._execute_plugin_iteration(plugin_name, decision)
                
                if not progress_made:
                    no_progress_count += 1
                    self.logger.warning(f"⚠️ Sem progresso: {no_progress_count}/{max_no_progress}")
                    
                    if no_progress_count >= max_no_progress:
                        self.logger.info("🛑 Parando por falta de progresso")
                        break
                else:
                    no_progress_count = 0
            
            # Pausa entre iterações
            min_interval = get_config('loop.min_interval', 2)
            time.sleep(min_interval)
            
            # Verificar critérios de parada automática
            if self._should_auto_stop():
                break
        
        self.logger.info(f"🏁 Loop concluído após {self.context['current_iteration']} iterações")
    
    def _run_manual_iteration(self, available_plugins: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Processa uma iteração no modo manual"""
        print("\n" + "="*50)
        self.logger.info("👨‍💻 Modo de Decisão Manual")
        print("="*50)

        # 1. Apresentar resumo do contexto
        print("\n🔍 Resumo das Descobertas Atuais:")
        discoveries = self.context.get('discoveries', {})
        vulnerabilities = self.context.get('vulnerabilities', [])

        print(f"  - Hosts: {len(discoveries.get('hosts', []))}")
        if discoveries.get('hosts'):
            for host in discoveries['hosts']:
                print(f"    • {host}")

        print(f"  - Portas Abertas: {len(discoveries.get('open_ports', []))}")
        if discoveries.get('open_ports'):
            ports_display = []
            for port in sorted(discoveries['open_ports']):
                # Tentar encontrar o serviço correspondente
                service_info = ""
                for service in discoveries.get('services', []):
                    if isinstance(service, dict) and service.get('port') == port:
                        service_name = service.get('service', 'unknown')
                        if service.get('version'):
                            service_info = f" ({service_name} {service.get('version')})"
                        else:
                            service_info = f" ({service_name})"
                        break
                ports_display.append(f"{port}{service_info}")
            print(f"    • {', '.join(ports_display)}")

        print(f"  - Serviços: {len(discoveries.get('services', []))}")
        if discoveries.get('services'):
            services_display = []
            for service in discoveries['services']:
                if isinstance(service, dict):
                    port = service.get('port', 'N/A')
                    service_name = service.get('service', 'unknown')
                    version = service.get('version', '')
                    product = service.get('product', '')
                    details = f"{service_name}"
                    if version:
                        details += f" {version}"
                    if product and product != version:
                        details += f" ({product})"
                    services_display.append(f"{port}:{details}")
                else:
                    services_display.append(str(service))
            print(f"    • {', '.join(services_display)}")

        print(f"  - Tecnologias: {len(discoveries.get('technologies', []))}")
        if discoveries.get('technologies'):
            for tech in discoveries['technologies']:
                print(f"    • {tech}")

        print(f"  - Vulnerabilidades: {len(vulnerabilities)}")
        if vulnerabilities:
            for vuln in vulnerabilities[:5]:  # Mostrar apenas as primeiras 5
                severity = vuln.get('severity', 'unknown')
                description = vuln.get('description', vuln.get('title', 'N/A'))
                print(f"    • [{severity.upper()}] {description}")
            if len(vulnerabilities) > 5:
                print(f"    • ... e mais {len(vulnerabilities) - 5} vulnerabilidades")

        # 2. Listar plugins disponíveis
        print("\n🔌 Plugins Disponíveis:")
        if not available_plugins:
            print("  Nenhum plugin disponível.")
        else:
            for i, plugin_info in enumerate(available_plugins):
                print(f"  [{i+1}] {plugin_info['name']} ({plugin_info.get('category', 'N/A')}) - {plugin_info.get('description', 'N/A')}")

        print("\n" + "-"*50)

        # 3. Solicitar ação do usuário
        while True:
            try:
                choice_str = input("👉 Escolha o número do plugin para executar, ou 's' para parar: ")

                if choice_str.lower() in ['s', 'sair', 'stop']:
                    return {'action': 'stop', 'reasoning': 'Usuário decidiu parar'}

                choice = int(choice_str) - 1

                if 0 <= choice < len(available_plugins):
                    selected_plugin_name = available_plugins[choice]['name']
                    self.logger.info(f"✅ Usuário selecionou: {selected_plugin_name}")
                    return {
                        'action': 'execute_plugin',
                        'plugin': selected_plugin_name,
                        'reasoning': 'Seleção manual do usuário'
                    }
                else:
                    self.logger.warning("❌ Opção inválida, tente novamente.")

            except ValueError:
                self.logger.warning("❌ Entrada inválida. Digite um número ou 's'.")
            except (KeyboardInterrupt, EOFError):
                self.logger.info("\n🛑 Operação cancelada pelo usuário.")
                return {'action': 'stop', 'reasoning': 'Usuário cancelou a operação'}

    def _get_available_plugins(self) -> List[Dict[str, Any]]:
        """Obtém lista de plugins disponíveis para execução com seus detalhes"""
        all_plugins = list(self.plugin_manager.plugins.keys())
        executed = set(self.context['executed_plugins'])
        
        # Filtrar plugins já executados
        available_names = [p for p in all_plugins if p not in executed]
        
        # Obter informações detalhadas e filtrar por adequação ao alvo
        suitable = []
        for plugin_name in available_names:
            plugin = self.plugin_manager.get_plugin(plugin_name)
            if plugin and plugin.validate_target(self.context['target']):
                suitable.append(plugin.get_info())
        
        return suitable
    
    def _get_mandatory_plugins(self) -> List[Dict[str, Any]]:
        """Obtém lista de plugins obrigatórios configurados"""
        mandatory_config = get_config('plugins.mandatory', [])
        
        if not mandatory_config:
            return []
        
        mandatory_plugins = []
        for plugin_config in mandatory_config:
            if isinstance(plugin_config, str):
                # Configuração simples: apenas nome do plugin
                mandatory_plugins.append({
                    'name': plugin_config,
                    'config': {}
                })
            elif isinstance(plugin_config, dict):
                # Configuração avançada: nome + configurações específicas
                mandatory_plugins.append(plugin_config)
        
        return mandatory_plugins
    
    def _execute_mandatory_plugins(self, mandatory_plugins: List[Dict[str, Any]]):
        """Executa plugins obrigatórios em sequência"""
        for plugin_config in mandatory_plugins:
            plugin_name = plugin_config['name']
            custom_config = plugin_config.get('config', {})
            
            self.logger.info(f"📋 Executando plugin obrigatório: {plugin_name}")
            
            try:
                # Executar plugin com configuração personalizada se fornecida
                if custom_config:
                    result = self.plugin_manager.execute_plugin(
                        plugin_name, 
                        self.context['target'], 
                        self.context,
                        **custom_config
                    )
                else:
                    result = self.plugin_manager.execute_plugin(
                        plugin_name, 
                        self.context['target'], 
                        self.context
                    )
                
                # Processar resultado
                previous_state = self._get_current_state()
                self.context['executed_plugins'].append(plugin_name)
                
                if result.success:
                    self.context['plugin_states'][plugin_name] = 'success'
                    self._update_context_with_result(result)
                    current_state = self._get_current_state()
                    progress_made = self._compare_states(previous_state, current_state)
                    
                    if progress_made:
                        self.logger.info(f"✅ Plugin obrigatório {plugin_name} descobriu novas informações")
                    else:
                        self.logger.info(f"ℹ️ Plugin obrigatório {plugin_name} executou sem novas descobertas")
                else:
                    self.context['plugin_states'][plugin_name] = 'failed'
                    self.logger.warning(f"❌ Plugin obrigatório {plugin_name} falhou: {result.error}")
                    self.context['errors'].append({
                        'plugin': plugin_name,
                        'error': result.error,
                        'summary': result.summary,
                        'timestamp': result.timestamp,
                        'mandatory': True
                    })
                
            except Exception as e:
                self.logger.error(f"💥 Erro executando plugin obrigatório {plugin_name}: {e}")
                self.context['errors'].append({
                    'plugin': plugin_name,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat(),
                    'mandatory': True
                })
    
    def _execute_plugin_iteration(self, plugin_name: str, decision: Dict) -> bool:
        """
        Executa um plugin e atualiza contexto
        
        Returns:
            True se houve progresso (novas descobertas)
        """
        self.logger.info(f"🔌 Executando plugin: {plugin_name}")
        self.logger.info(f"💭 Motivo: {decision.get('reasoning', 'N/A')}")
        
        # Backup do estado atual para comparar progresso
        previous_state = self._get_current_state()
        
        # Executar plugin
        result = self.plugin_manager.execute_plugin(
            plugin_name, 
            self.context['target'], 
            self.context
        )
        
        # Registrar execução do plugin no histórico
        discoveries_made = False
        if result.success:
            current_state = self._get_current_state()
            discoveries_made = self._compare_states(previous_state, current_state)
        
        self.history_manager.log_plugin_execution(
            plugin_name=plugin_name,
            execution_time=result.execution_time,
            success=result.success,
            discoveries_made=discoveries_made,
            error=str(result.error) if result.error else None
        )
        
        # Registrar no logger simples
        discoveries_text = f"Novas descobertas: {discoveries_made}" if result.success else ""
        error_text = str(result.error) if result.error else ""
        self.simple_logger.log_plugin_execution(
            plugin_name=plugin_name,
            execution_time=result.execution_time,
            success=result.success,
            discoveries=discoveries_text,
            error=error_text
        )
        
        # Atualizar contexto
        self.context['executed_plugins'].append(plugin_name)

        if result.success:
            self.context['plugin_states'][plugin_name] = 'success'
            self._update_context_with_result(result)

            # Verificar se houve progresso
            current_state = self._get_current_state()
            progress_made = self._compare_states(previous_state, current_state)

            if progress_made:
                self.logger.info(f"✅ Plugin {plugin_name} descobriu novas informações")
            else:
                self.logger.info(f"ℹ️ Plugin {plugin_name} executou sem novas descobertas")

            return progress_made
        else:
            self.context['plugin_states'][plugin_name] = 'failed'
            self.logger.warning(f"❌ Plugin {plugin_name} falhou: {result.error}")
            self.context['errors'].append({
                'plugin': plugin_name,
                'error': result.error,
                'summary': result.summary,
                'timestamp': result.timestamp
            })
            return False
    
    def _update_context_with_result(self, result):
        """Atualiza contexto com resultado do plugin"""
        data = result.data
        
        # Atualizar descobertas
        if 'hosts' in data:
            new_hosts = [h for h in data['hosts'] if h not in self.context['discoveries']['hosts']]
            self.context['discoveries']['hosts'].extend(new_hosts)
        
        if 'open_ports' in data:
            new_ports = [p for p in data['open_ports'] if p not in self.context['discoveries']['open_ports']]
            self.context['discoveries']['open_ports'].extend(new_ports)
        
        if 'services' in data:
            new_services = [s for s in data['services'] if s not in self.context['discoveries']['services']]
            self.context['discoveries']['services'].extend(new_services)
        
        if 'technologies' in data:
            new_techs = [t for t in data['technologies'] if t not in self.context['discoveries']['technologies']]
            self.context['discoveries']['technologies'].extend(new_techs)
        
        # Atualizar vulnerabilidades
        if 'vulnerabilities' in data:
            self.context['vulnerabilities'].extend(data['vulnerabilities'])
        
        # Armazenar resultado completo
        self.results[result.plugin_name] = result
    
    def _get_current_state(self) -> Dict:
        """Obtém estado atual para comparação de progresso"""
        return {
            'hosts_count': len(self.context['discoveries']['hosts']),
            'ports_count': len(self.context['discoveries']['open_ports']),
            'services_count': len(self.context['discoveries']['services']),
            'technologies_count': len(self.context['discoveries']['technologies']),
            'vulnerabilities_count': len(self.context['vulnerabilities'])
        }
    
    def _compare_states(self, previous: Dict, current: Dict) -> bool:
        """Compara estados para determinar se houve progresso"""
        for key in previous:
            if current.get(key, 0) > previous.get(key, 0):
                return True
        return False
    
    def _should_auto_stop(self) -> bool:
        """Verifica critérios de parada automática"""
        # Parar se muitas vulnerabilidades críticas
        critical_limit = get_config('loop.auto_stop.critical_vuln_limit', 5)
        critical_vulns = [v for v in self.context['vulnerabilities'] 
                         if v.get('severity', '').lower() in ['critical', 'high']]
        
        if len(critical_vulns) >= critical_limit:
            self.logger.info(f"🛑 Parando: {len(critical_vulns)} vulnerabilidades críticas encontradas")
            return True
        
        return False
    
    def _generate_report(self) -> str:
        """Gera relatório final e retorna caminho do arquivo"""
        data_dir = Path(get_config('output.data_dir', 'data'))
        data_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime(get_config('output.timestamp_format', '%Y%m%d_%H%M%S'))
        report_file = data_dir / f"pentest_{timestamp}.json"
        
        # Preparar dados do relatório
        report_data = {
            'metadata': {
                'target': self.context['target'],
                'start_time': self.context['start_time'].isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': (datetime.now() - self.context['start_time']).total_seconds(),
                'iterations': self.context['current_iteration'],
                'ai_connected': self.ai_agent.is_connected()
            },
            'execution': {
                'plugins_executed': self.context['executed_plugins'],
                'total_plugins_available': len(self.plugin_manager.plugins),
                'errors': self.context['errors']
            },
            'discoveries': self.context['discoveries'],
            'vulnerabilities': self.context['vulnerabilities'],
            'detailed_results': {
                name: {
                    'success': result.success,
                    'execution_time': result.execution_time,
                    'data': result.data,
                    'error': result.error
                }
                for name, result in self.results.items()
            }
        }
        
        # Salvar relatório
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        self.logger.info(f"📄 Relatório salvo: {report_file}")
        return str(report_file)
