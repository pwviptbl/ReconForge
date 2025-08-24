#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de análise inteligente usando Gemini AI
Analisa resultados de varreduras Nmap e fornece insights de segurança
"""

import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

import google.generativeai as genai
from core.configuracao import obter_config
from utils.logger import obter_logger, log_manager

class AnalisadorGemini:
    """Analisador inteligente usando API do Gemini"""
    
    def __init__(self):
        """Inicializa o analisador Gemini"""
        self.logger = obter_logger('AnalisadorGemini')
        self.chave_api = obter_config('api.gemini.chave_api')
        self.modelo_nome = obter_config('api.gemini.modelo', 'gemini-2.5-pro')
        self.timeout = obter_config('api.gemini.timeout', 30)
        self.max_tentativas = obter_config('api.gemini.max_tentativas', 3)
        
        self.modelo = None
        self.conectado = False
        
        # Templates de prompts em português
        self.templates_prompt = {
            'analise_geral': """
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
            
            'analise_servicos': """
Analise os serviços descobertos na varredura:

{dados_servicos}

Forneça análise sobre:
1. Serviços expostos e sua segurança
2. Versões desatualizadas identificadas
3. Configurações inseguras detectadas
4. Recomendações específicas por serviço
5. Vetores de ataque potenciais

Responda em português com foco em hardening de serviços.
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
    
    def conectar(self) -> bool:
        """
        Estabelece conexão com a API do Gemini
        Returns:
            bool: True se conectado com sucesso
        """
        try:
            if not self.chave_api or self.chave_api.startswith('${'):
                self.logger.error("Chave da API Gemini não configurada")
                return False
            
            # Configurar API
            genai.configure(api_key=self.chave_api)
            
            # Inicializar modelo
            self.modelo = genai.GenerativeModel(self.modelo_nome)
            
            # Teste de conexão
            resposta_teste = self.modelo.generate_content("Teste de conexão.")
            
            if resposta_teste and resposta_teste.text:
                self.conectado = True
                self.logger.info(f"Conectado ao Gemini {self.modelo_nome}")
                log_manager.log_api_gemini('conectar', True, f"Modelo: {self.modelo_nome}")
                return True
            else:
                self.logger.error("Resposta inválida do Gemini no teste")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro ao conectar com Gemini: {str(e)}")
            log_manager.log_api_gemini('conectar', False, str(e))
            return False
    
    def analisar_varredura_completa(self, resultados_varredura: Dict[str, Any]) -> Dict[str, Any]:
        """
        Análise completa dos resultados de varredura
        Args:
            resultados_varredura (Dict): Resultados da varredura Nmap
        Returns:
            Dict[str, Any]: Análise completa gerada pelo Gemini
        """
        if not self.conectado and not self.conectar():
            return {'erro': 'Não foi possível conectar ao Gemini'}
        
        try:
            # Preparar dados para análise
            dados_formatados = self._formatar_dados_varredura(resultados_varredura)
            
            # Gerar prompt
            prompt = self.templates_prompt['analise_geral'].format(
                dados_varredura=dados_formatados
            )
            
            # Executar análise
            resposta = self._executar_consulta(prompt)
            
            if resposta:
                analise = {
                    'timestamp': datetime.now().isoformat(),
                    'tipo_analise': 'completa',
                    'modelo_utilizado': self.modelo_nome,
                    'resultados_originais': resultados_varredura,
                    'analise_ia': resposta,
                    'resumo_tecnico': self._extrair_resumo_tecnico(resposta),
                    'nivel_risco_geral': self._determinar_nivel_risco(resultados_varredura),
                    'recomendacoes_prioritarias': self._extrair_recomendacoes(resposta)
                }
                
                log_manager.log_api_gemini('analise_completa', True, 
                                         f"Hosts analisados: {len(resultados_varredura.get('dados', {}).get('hosts', []))}")
                return analise
            else:
                return {'erro': 'Falha na geração da análise'}
                
        except Exception as e:
            self.logger.error(f"Erro na análise completa: {str(e)}")
            log_manager.log_api_gemini('analise_completa', False, str(e))
            return {'erro': f'Erro na análise: {str(e)}'}
    
    def analisar_vulnerabilidades(self, resultados_varredura: Dict[str, Any]) -> Dict[str, Any]:
        """
        Análise focada em vulnerabilidades
        Args:
            resultados_varredura (Dict): Resultados da varredura
        Returns:
            Dict[str, Any]: Análise de vulnerabilidades
        """
        if not self.conectado and not self.conectar():
            return {'erro': 'Não foi possível conectar ao Gemini'}
        
        try:
            # Extrair apenas dados de vulnerabilidades
            vulnerabilidades = self._extrair_vulnerabilidades(resultados_varredura)
            
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
            prompt = self.templates_prompt['analise_vulnerabilidades'].format(
                dados_vulnerabilidades=dados_vuln
            )
            
            # Executar análise
            resposta = self._executar_consulta(prompt)
            
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
                
                log_manager.log_api_gemini('analise_vulnerabilidades', True, 
                                         f"Vulnerabilidades analisadas: {len(vulnerabilidades)}")
                return analise
            else:
                return {'erro': 'Falha na análise de vulnerabilidades'}
                
        except Exception as e:
            self.logger.error(f"Erro na análise de vulnerabilidades: {str(e)}")
            log_manager.log_api_gemini('analise_vulnerabilidades', False, str(e))
            return {'erro': f'Erro na análise: {str(e)}'}
    
    def analisar_servicos(self, resultados_varredura: Dict[str, Any]) -> Dict[str, Any]:
        """
        Análise focada em serviços descobertos
        Args:
            resultados_varredura (Dict): Resultados da varredura
        Returns:
            Dict[str, Any]: Análise de serviços
        """
        if not self.conectado and not self.conectar():
            return {'erro': 'Não foi possível conectar ao Gemini'}
        
        try:
            # Extrair dados de serviços
            servicos = self._extrair_servicos(resultados_varredura)
            
            if not servicos:
                return {
                    'timestamp': datetime.now().isoformat(),
                    'tipo_analise': 'servicos',
                    'analise_ia': 'Nenhum serviço específico identificado na varredura.',
                    'servicos_encontrados': 0
                }
            
            # Formatar dados de serviços
            dados_servicos = json.dumps(servicos, indent=2, ensure_ascii=False)
            
            # Gerar prompt
            prompt = self.templates_prompt['analise_servicos'].format(
                dados_servicos=dados_servicos
            )
            
            # Executar análise
            resposta = self._executar_consulta(prompt)
            
            if resposta:
                analise = {
                    'timestamp': datetime.now().isoformat(),
                    'tipo_analise': 'servicos',
                    'modelo_utilizado': self.modelo_nome,
                    'servicos_encontrados': len(servicos),
                    'analise_ia': resposta,
                    'servicos_detalhados': servicos,
                    'servicos_criticos': self._identificar_servicos_criticos(servicos),
                    'versoes_desatualizadas': self._identificar_versoes_antigas(servicos)
                }
                
                log_manager.log_api_gemini('analise_servicos', True, 
                                         f"Serviços analisados: {len(servicos)}")
                return analise
            else:
                return {'erro': 'Falha na análise de serviços'}
                
        except Exception as e:
            self.logger.error(f"Erro na análise de serviços: {str(e)}")
            log_manager.log_api_gemini('analise_servicos', False, str(e))
            return {'erro': f'Erro na análise: {str(e)}'}
    
    def gerar_plano_pentest(self, resultados_varredura: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera plano estruturado de pentest baseado nos resultados
        Args:
            resultados_varredura (Dict): Resultados da varredura
        Returns:
            Dict[str, Any]: Plano de pentest gerado
        """
        if not self.conectado and not self.conectar():
            return {'erro': 'Não foi possível conectar ao Gemini'}
        
        try:
            # Preparar dados resumidos para o plano
            dados_resumidos = self._resumir_dados_para_plano(resultados_varredura)
            
            # Gerar prompt
            prompt = self.templates_prompt['plano_pentest'].format(
                dados_varredura=dados_resumidos
            )
            
            # Executar geração do plano
            resposta = self._executar_consulta(prompt)
            
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
                
                log_manager.log_api_gemini('plano_pentest', True, 'Plano de pentest gerado')
                return plano
            else:
                return {'erro': 'Falha na geração do plano'}
                
        except Exception as e:
            self.logger.error(f"Erro na geração do plano: {str(e)}")
            log_manager.log_api_gemini('plano_pentest', False, str(e))
            return {'erro': f'Erro na geração: {str(e)}'}
    
    def _executar_consulta(self, prompt: str) -> Optional[str]:
        """
        Executa consulta ao Gemini com retry
        Args:
            prompt (str): Prompt para o modelo
        Returns:
            Optional[str]: Resposta do modelo ou None
        """
        for tentativa in range(self.max_tentativas):
            try:
                resposta = self.modelo.generate_content(prompt)
                
                if resposta and resposta.text:
                    return resposta.text.strip()
                else:
                    self.logger.warning(f"Resposta vazia na tentativa {tentativa + 1}")
                    
            except Exception as e:
                self.logger.warning(f"Erro na tentativa {tentativa + 1}: {str(e)}")
                
                if tentativa == self.max_tentativas - 1:
                    self.logger.error(f"Falha após {self.max_tentativas} tentativas")
                    return None
        
        return None
    
    def _formatar_dados_varredura(self, resultados: Dict[str, Any]) -> str:
        """
        Formata dados de varredura para análise
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
    
    def _extrair_vulnerabilidades(self, resultados: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extrai vulnerabilidades dos resultados
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
    
    def _extrair_servicos(self, resultados: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extrai informações de serviços dos resultados
        Args:
            resultados (Dict): Resultados da varredura
        Returns:
            List[Dict]: Lista de serviços encontrados
        """
        servicos = []
        
        for host in resultados.get('dados', {}).get('hosts', []):
            host_ip = host.get('endereco', 'N/A')
            
            for porta in host.get('portas', []):
                if porta.get('estado') == 'open' and porta.get('servico'):
                    servicos.append({
                        'host': host_ip,
                        'porta': f"{porta['numero']}/{porta['protocolo']}",
                        'servico': porta.get('servico', ''),
                        'produto': porta.get('produto', ''),
                        'versao': porta.get('versao', ''),
                        'scripts_executados': len(porta.get('scripts', []))
                    })
        
        return servicos
    
    def _determinar_nivel_risco(self, resultados: Dict[str, Any]) -> str:
        """
        Determina nível de risco geral
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
    
    def _determinar_nivel_risco_vulnerabilidades(self, vulnerabilidades: List[Dict]) -> str:
        """Determina nível de risco baseado em vulnerabilidades"""
        if len(vulnerabilidades) >= 5:
            return 'Crítico'
        elif len(vulnerabilidades) >= 2:
            return 'Alto'
        elif len(vulnerabilidades) >= 1:
            return 'Médio'
        else:
            return 'Baixo'
    
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
    
    def _identificar_servicos_criticos(self, servicos: List[Dict]) -> List[Dict]:
        """Identifica serviços críticos"""
        servicos_criticos = ['ssh', 'rdp', 'telnet', 'ftp', 'http', 'https', 'smb', 'sql']
        criticos = []
        
        for servico in servicos:
            if servico.get('servico', '').lower() in servicos_criticos:
                criticos.append(servico)
        
        return criticos
    
    def _identificar_versoes_antigas(self, servicos: List[Dict]) -> List[Dict]:
        """Identifica versões potencialmente antigas"""
        versoes_antigas = []
        
        for servico in servicos:
            versao = servico.get('versao', '')
            if versao and any(char.isdigit() for char in versao):
                # Análise simples - pode ser melhorada
                versoes_antigas.append(servico)
        
        return versoes_antigas
    
    def _resumir_dados_para_plano(self, resultados: Dict[str, Any]) -> str:
        """Resume dados para geração de plano"""
        return self._formatar_dados_varredura(resultados)[:1000]  # Resumo limitado
    
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


if __name__ == "__main__":
    # Teste do analisador
    analisador = AnalisadorGemini()
    
    if analisador.conectar():
        print("✓ Analisador Gemini conectado com sucesso!")
        
        # Teste com dados mockados
        dados_teste = {
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
        
        print("Executando análise de teste...")
        resultado = analisador.analisar_varredura_completa(dados_teste)
        
        if 'erro' not in resultado:
            print("✓ Análise executada com sucesso!")
            print(f"Nível de risco: {resultado.get('nivel_risco_geral', 'N/A')}")
        else:
            print(f"✗ Erro na análise: {resultado['erro']}")
    else:
        print("✗ Falha ao conectar com Gemini")