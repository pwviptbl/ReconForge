#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de Decisão Inteligente
Analisa resultados de scan inicial e decide próximos passos usando IA
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime

from modulos.analise_gemini import AnalisadorGemini
from utils.logger import obter_logger

class DecisaoIA:
    """Classe para tomada de decisões inteligentes baseada em IA"""
    
    def __init__(self):
        """Inicializa o módulo de decisão IA"""
        self.logger = obter_logger('DecisaoIA')
        self.analisador = AnalisadorGemini()
        
        # Templates de prompts específicos para decisão
        self.templates_decisao = {
            'decidir_proximos_passos': """
Analise os seguintes resultados de scan inicial de portas e decida os próximos passos:

RESULTADOS DO SCAN INICIAL:
{resultados_scan}

MÓDULOS DISPONÍVEIS:
1. Nmap Básico - Varredura simples de portas
2. Nmap Completo - Detecção de versão e serviços  
3. Nmap Vulnerabilidades - Scripts NSE de vulnerabilidades
4. Nmap Serviços Web - Análise específica de HTTP/HTTPS
5. Nmap SMB - Análise de serviços SMB/NetBIOS
6. Nmap Descoberta de Rede - Discovery de hosts na rede

Com base nos serviços encontrados, responda APENAS em formato JSON:
{{
    "executar_nmap_avancado": true/false,
    "modulos_recomendados": ["nome_modulo1", "nome_modulo2"],
    "justificativa": "explicação da decisão",
    "prioridade": "alta/media/baixa",
    "portas_prioritarias": ["porta1", "porta2"],
    "tempo_estimado": "estimativa em minutos"
}}

IMPORTANTE: Responda APENAS o JSON, sem texto adicional.
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
"""
        }
    
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
            if not self.analisador.conectado and not self.analisador.conectar():
                return self._decisao_fallback(resultados_scan_inicial)
            
            # Preparar dados para análise
            dados_formatados = self._formatar_resultados_scan(resultados_scan_inicial)
            
            # Gerar prompt de decisão
            prompt = self.templates_decisao['decidir_proximos_passos'].format(
                resultados_scan=dados_formatados
            )
            
            # Executar consulta IA
            resposta_ia = self.analisador._executar_consulta(prompt)
            
            if resposta_ia:
                # Tentar parsear JSON da resposta
                decisao_ia = self._parsear_decisao_ia(resposta_ia)
                
                if decisao_ia:
                    # Enriquecer decisão com análise local
                    decisao_final = self._enriquecer_decisao(decisao_ia, resultados_scan_inicial)
                    
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
            # Extrair serviços dos resultados
            servicos = self._extrair_servicos_scan(resultados_scan)
            
            if not servicos:
                return {
                    'servicos_criticos': [],
                    'servicos_interessantes': [],
                    'nivel_interesse_geral': 'baixo',
                    'recomendacoes_especificas': {}
                }
            
            # Conectar ao Gemini se necessário
            if not self.analisador.conectado and not self.analisador.conectar():
                return self._analise_servicos_local(servicos)
            
            # Formatar serviços para análise
            servicos_formatados = json.dumps(servicos, indent=2, ensure_ascii=False)
            
            # Gerar prompt
            prompt = self.templates_decisao['analisar_servicos_encontrados'].format(
                servicos_detectados=servicos_formatados
            )
            
            # Executar análise
            resposta_ia = self.analisador._executar_consulta(prompt)
            
            if resposta_ia:
                analise_ia = self._parsear_analise_servicos(resposta_ia)
                if analise_ia:
                    return analise_ia
            
            # Fallback para análise local
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
    
    def _enriquecer_decisao(self, decisao_ia: Dict[str, Any], resultados_scan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enriquece decisão da IA com análise local
        Args:
            decisao_ia (Dict): Decisão da IA
            resultados_scan (Dict): Resultados do scan
        Returns:
            Dict[str, Any]: Decisão enriquecida
        """
        decisao_final = {
            'timestamp': datetime.now().isoformat(),
            'fonte_decisao': 'ia_gemini',
            'executar_nmap_avancado': decisao_ia.get('executar_nmap_avancado', False),
            'modulos_recomendados': decisao_ia.get('modulos_recomendados', []),
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
        
        # Análise local para decisão
        analise_local = self._gerar_analise_local(resultados_scan)
        nivel_interesse = analise_local.get('nivel_interesse', 'baixo')
        
        # Decidir baseado em regras simples
        executar_nmap = False
        modulos_recomendados = []
        justificativa = ""
        prioridade = "baixa"
        
        if nivel_interesse == 'alto':
            executar_nmap = True
            modulos_recomendados = ['varredura_vulnerabilidades', 'varredura_completa']
            justificativa = "Serviços críticos detectados - análise aprofundada necessária"
            prioridade = "alta"
        elif nivel_interesse == 'medio':
            executar_nmap = True
            modulos_recomendados = ['varredura_completa']
            justificativa = "Serviços interessantes detectados - análise recomendada"
            prioridade = "media"
        elif total_portas >= 5:
            executar_nmap = True
            modulos_recomendados = ['varredura_basica']
            justificativa = "Múltiplas portas abertas - verificação adicional recomendada"
            prioridade = "media"
        else:
            justificativa = "Poucos serviços expostos - scan inicial suficiente"
        
        # Adicionar módulos específicos baseado nos serviços
        if analise_local.get('servicos_web_detectados', 0) > 0:
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
                'total_hosts': resumo_scan.get('hosts_ativos', 0),
                'total_portas': total_portas,
                'hosts_interessantes': len(hosts_com_portas)
            }
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


if __name__ == "__main__":
    # Teste do módulo de decisão
    decisao = DecisaoIA()
    
    # Dados de teste
    dados_teste = {
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
    
    print("Testando decisão IA...")
    resultado = decisao.decidir_proximos_passos(dados_teste)
    
    print(f"Executar Nmap avançado: {resultado.get('executar_nmap_avancado', False)}")
    print(f"Módulos recomendados: {resultado.get('modulos_recomendados', [])}")
    print(f"Justificativa: {resultado.get('justificativa_ia', 'N/A')}")
    print(f"Prioridade: {resultado.get('prioridade', 'N/A')}")