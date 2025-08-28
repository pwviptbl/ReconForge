#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gerenciador de Histórico de Interações com IA
Salva e gerencia conversas para análise futura
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

from utils.logger import obter_logger


class GerenciadorHistorico:
    """Gerencia histórico de interações com IA"""
    
    def __init__(self, pasta_historico: str = None):
        """
        Inicializa o gerenciador de histórico
        
        Args:
            pasta_historico (str): Caminho para pasta de histórico
        """
        self.logger = obter_logger('HistoricoIA')
        
        # Definir pasta de histórico
        if pasta_historico:
            self.pasta_historico = Path(pasta_historico)
        else:
            # Pasta padrão relativa ao projeto
            self.pasta_historico = Path(__file__).parent
        
        # Criar pasta se não existir
        self.pasta_historico.mkdir(parents=True, exist_ok=True)
        
        # Sessão atual
        self.sessao_atual = None
        self.contador_interacao = 0
        
        self.logger.info(f"Gerenciador de histórico inicializado: {self.pasta_historico}")
    
    def iniciar_sessao(self, alvo: str, tipo_execucao: str = "pentest_inteligente") -> str:
        """
        Inicia uma nova sessão de histórico
        
        Args:
            alvo (str): Alvo da sessão
            tipo_execucao (str): Tipo de execução
            
        Returns:
            str: ID da sessão
        """
        timestamp = datetime.now()
        sessao_id = f"{tipo_execucao}_{timestamp.strftime('%Y%m%d_%H%M%S')}"
        
        self.sessao_atual = {
            'sessao_id': sessao_id,
            'alvo': alvo,
            'tipo_execucao': tipo_execucao,
            'timestamp_inicio': timestamp.isoformat(),
            'timestamp_fim': None,
            'total_interacoes': 0,
            'interacoes': [],
            'metadados': {
                'versao_sistema': '1.0',
                'modelo_ia': 'gemini-2.5-flash'
            }
        }
        
        self.contador_interacao = 0
        
        self.logger.info(f"Nova sessão iniciada: {sessao_id} para alvo {alvo}")
        return sessao_id
    
    def registrar_interacao(self, 
                          prompt_enviado: str, 
                          resposta_recebida: str,
                          contexto_adicional: Optional[Dict] = None,
                          tempo_resposta: Optional[float] = None,
                          tipo_prompt: str = "decisao_loop") -> None:
        """
        Registra uma interação com a IA
        
        Args:
            prompt_enviado (str): Prompt enviado para IA
            resposta_recebida (str): Resposta recebida da IA
            contexto_adicional (Dict): Contexto adicional (opcional)
            tempo_resposta (float): Tempo de resposta em segundos
            tipo_prompt (str): Tipo do prompt
        """
        if not self.sessao_atual:
            self.logger.warning("Nenhuma sessão ativa. Iniciando sessão genérica.")
            self.iniciar_sessao("unknown", "interacao_generica")
        
        self.contador_interacao += 1
        timestamp = datetime.now()
        
        interacao = {
            'numero_interacao': self.contador_interacao,
            'timestamp': timestamp.isoformat(),
            'tipo_prompt': tipo_prompt,
            'prompt': {
                'texto': prompt_enviado,
                'tamanho_caracteres': len(prompt_enviado),
                'linhas': prompt_enviado.count('\n') + 1
            },
            'resposta': {
                'texto': resposta_recebida,
                'tamanho_caracteres': len(resposta_recebida) if resposta_recebida else 0,
                'linhas': resposta_recebida.count('\n') + 1 if resposta_recebida else 0,
                'sucesso': bool(resposta_recebida)
            },
            'metricas': {
                'tempo_resposta_segundos': tempo_resposta,
                'tokens_prompt_estimados': self._estimar_tokens(prompt_enviado),
                'tokens_resposta_estimados': self._estimar_tokens(resposta_recebida) if resposta_recebida else 0
            },
            'contexto_adicional': contexto_adicional or {}
        }
        
        self.sessao_atual['interacoes'].append(interacao)
        self.sessao_atual['total_interacoes'] = self.contador_interacao
        
        self.logger.debug(f"Interação {self.contador_interacao} registrada: {tipo_prompt}")
    
    def finalizar_sessao(self, resultado_final: Optional[Dict] = None) -> str:
        """
        Finaliza a sessão atual e salva no arquivo
        
        Args:
            resultado_final (Dict): Resultado final da sessão
            
        Returns:
            str: Caminho do arquivo salvo
        """
        if not self.sessao_atual:
            self.logger.warning("Nenhuma sessão ativa para finalizar")
            return None
        
        # Finalizar sessão
        self.sessao_atual['timestamp_fim'] = datetime.now().isoformat()
        
        if resultado_final:
            self.sessao_atual['resultado_final'] = resultado_final
        
        # Calcular estatísticas da sessão
        self.sessao_atual['estatisticas'] = self._calcular_estatisticas_sessao()
        
        # Salvar arquivo
        arquivo_sessao = self._salvar_sessao()
        
        self.logger.info(f"Sessão finalizada e salva: {arquivo_sessao}")
        
        # Limpar sessão atual
        sessao_id = self.sessao_atual['sessao_id']
        self.sessao_atual = None
        self.contador_interacao = 0
        
        return arquivo_sessao
    
    def _calcular_estatisticas_sessao(self) -> Dict[str, Any]:
        """Calcula estatísticas da sessão"""
        if not self.sessao_atual or not self.sessao_atual['interacoes']:
            return {}
        
        interacoes = self.sessao_atual['interacoes']
        
        # Estatísticas básicas
        total_chars_prompts = sum(i['prompt']['tamanho_caracteres'] for i in interacoes)
        total_chars_respostas = sum(i['resposta']['tamanho_caracteres'] for i in interacoes)
        
        # Tempo de resposta
        tempos_resposta = [i['metricas']['tempo_resposta_segundos'] 
                          for i in interacoes 
                          if i['metricas']['tempo_resposta_segundos'] is not None]
        
        # Tokens estimados
        total_tokens_prompts = sum(i['metricas']['tokens_prompt_estimados'] for i in interacoes)
        total_tokens_respostas = sum(i['metricas']['tokens_resposta_estimados'] for i in interacoes)
        
        # Taxa de sucesso
        sucessos = sum(1 for i in interacoes if i['resposta']['sucesso'])
        taxa_sucesso = (sucessos / len(interacoes)) * 100 if interacoes else 0
        
        # Tipos de prompt
        tipos_prompt = {}
        for interacao in interacoes:
            tipo = interacao['tipo_prompt']
            tipos_prompt[tipo] = tipos_prompt.get(tipo, 0) + 1
        
        estatisticas = {
            'total_interacoes': len(interacoes),
            'taxa_sucesso_percent': round(taxa_sucesso, 2),
            'caracteres': {
                'total_prompts': total_chars_prompts,
                'total_respostas': total_chars_respostas,
                'media_prompt': round(total_chars_prompts / len(interacoes), 2),
                'media_resposta': round(total_chars_respostas / len(interacoes), 2) if sucessos > 0 else 0
            },
            'tokens_estimados': {
                'total_prompts': total_tokens_prompts,
                'total_respostas': total_tokens_respostas,
                'total_geral': total_tokens_prompts + total_tokens_respostas
            },
            'tempo_resposta': {
                'total_segundos': sum(tempos_resposta) if tempos_resposta else 0,
                'media_segundos': round(sum(tempos_resposta) / len(tempos_resposta), 2) if tempos_resposta else 0,
                'min_segundos': min(tempos_resposta) if tempos_resposta else 0,
                'max_segundos': max(tempos_resposta) if tempos_resposta else 0
            },
            'tipos_prompt': tipos_prompt,
            'duracao_sessao_minutos': self._calcular_duracao_sessao()
        }
        
        return estatisticas
    
    def _calcular_duracao_sessao(self) -> float:
        """Calcula duração da sessão em minutos"""
        if not self.sessao_atual:
            return 0
        
        inicio = datetime.fromisoformat(self.sessao_atual['timestamp_inicio'])
        fim = datetime.now()
        
        duracao = (fim - inicio).total_seconds() / 60
        return round(duracao, 2)
    
    def _estimar_tokens(self, texto: str) -> int:
        """
        Estima quantidade de tokens de um texto
        Estimativa simples: ~4 caracteres por token
        """
        if not texto:
            return 0
        return max(1, len(texto) // 4)
    
    def _salvar_sessao(self) -> str:
        """Salva a sessão atual em arquivo JSON"""
        if not self.sessao_atual:
            return None
        
        # Nome do arquivo
        sessao_id = self.sessao_atual['sessao_id']
        nome_arquivo = f"{sessao_id}.json"
        caminho_arquivo = self.pasta_historico / nome_arquivo
        
        # Salvar arquivo
        try:
            with open(caminho_arquivo, 'w', encoding='utf-8') as f:
                json.dump(self.sessao_atual, f, ensure_ascii=False, indent=2)
            
            self.logger.info(f"Sessão salva: {caminho_arquivo}")
            return str(caminho_arquivo)
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar sessão: {e}")
            return None
    
    def listar_sessoes(self, limite: int = 10) -> List[Dict[str, Any]]:
        """
        Lista sessões salvas (mais recentes primeiro)
        
        Args:
            limite (int): Limite de sessões a retornar
            
        Returns:
            List[Dict]: Lista de informações de sessões
        """
        try:
            arquivos_json = list(self.pasta_historico.glob("*.json"))
            arquivos_json.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            sessoes = []
            for arquivo in arquivos_json[:limite]:
                try:
                    with open(arquivo, 'r', encoding='utf-8') as f:
                        dados = json.load(f)
                    
                    # Resumo da sessão
                    resumo = {
                        'arquivo': arquivo.name,
                        'sessao_id': dados.get('sessao_id', 'unknown'),
                        'alvo': dados.get('alvo', 'unknown'),
                        'timestamp_inicio': dados.get('timestamp_inicio'),
                        'total_interacoes': dados.get('total_interacoes', 0),
                        'taxa_sucesso': dados.get('estatisticas', {}).get('taxa_sucesso_percent', 0),
                        'duracao_minutos': dados.get('estatisticas', {}).get('duracao_sessao_minutos', 0)
                    }
                    
                    sessoes.append(resumo)
                    
                except Exception as e:
                    self.logger.warning(f"Erro ao ler sessão {arquivo}: {e}")
            
            return sessoes
            
        except Exception as e:
            self.logger.error(f"Erro ao listar sessões: {e}")
            return []
    
    def carregar_sessao(self, sessao_id: str) -> Optional[Dict[str, Any]]:
        """
        Carrega uma sessão específica
        
        Args:
            sessao_id (str): ID da sessão
            
        Returns:
            Dict: Dados da sessão ou None se não encontrada
        """
        try:
            arquivo = self.pasta_historico / f"{sessao_id}.json"
            
            if not arquivo.exists():
                self.logger.warning(f"Sessão não encontrada: {sessao_id}")
                return None
            
            with open(arquivo, 'r', encoding='utf-8') as f:
                dados = json.load(f)
            
            return dados
            
        except Exception as e:
            self.logger.error(f"Erro ao carregar sessão {sessao_id}: {e}")
            return None
    
    def gerar_relatorio_analitico(self, sessao_id: str = None) -> Dict[str, Any]:
        """
        Gera relatório analítico de uma sessão ou todas
        
        Args:
            sessao_id (str): ID da sessão específica (opcional)
            
        Returns:
            Dict: Relatório analítico
        """
        if sessao_id:
            # Análise de sessão específica
            dados = self.carregar_sessao(sessao_id)
            if not dados:
                return {}
            
            return self._analisar_sessao_individual(dados)
        else:
            # Análise de todas as sessões
            return self._analisar_todas_sessoes()
    
    def _analisar_sessao_individual(self, dados: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa uma sessão individual"""
        interacoes = dados.get('interacoes', [])
        estatisticas = dados.get('estatisticas', {})
        
        # Análise de padrões de prompt
        padroes_prompt = self._analisar_padroes_prompt(interacoes)
        
        # Análise de qualidade das respostas
        qualidade_respostas = self._analisar_qualidade_respostas(interacoes)
        
        # Pontos de melhoria
        melhorias = self._identificar_melhorias(interacoes, estatisticas)
        
        return {
            'sessao_id': dados.get('sessao_id'),
            'resumo_geral': estatisticas,
            'padroes_prompt': padroes_prompt,
            'qualidade_respostas': qualidade_respostas,
            'pontos_melhoria': melhorias,
            'timestamp_analise': datetime.now().isoformat()
        }
    
    def _analisar_todas_sessoes(self) -> Dict[str, Any]:
        """Analisa todas as sessões para padrões gerais"""
        sessoes = self.listar_sessoes(limite=50)  # Últimas 50 sessões
        
        if not sessoes:
            return {'erro': 'Nenhuma sessão encontrada'}
        
        # Estatísticas agregadas
        total_interacoes = sum(s['total_interacoes'] for s in sessoes)
        taxa_sucesso_media = sum(s['taxa_sucesso'] for s in sessoes) / len(sessoes)
        duracao_media = sum(s['duracao_minutos'] for s in sessoes) / len(sessoes)
        
        # Análise temporal
        analise_temporal = self._analisar_tendencias_temporais(sessoes)
        
        return {
            'total_sessoes_analisadas': len(sessoes),
            'periodo_analise': f"Últimas {len(sessoes)} sessões",
            'estatisticas_agregadas': {
                'total_interacoes': total_interacoes,
                'taxa_sucesso_media': round(taxa_sucesso_media, 2),
                'duracao_media_minutos': round(duracao_media, 2)
            },
            'analise_temporal': analise_temporal,
            'timestamp_analise': datetime.now().isoformat()
        }
    
    def _analisar_padroes_prompt(self, interacoes: List[Dict]) -> Dict[str, Any]:
        """Analisa padrões nos prompts"""
        tamanhos = [i['prompt']['tamanho_caracteres'] for i in interacoes]
        tipos = [i['tipo_prompt'] for i in interacoes]
        
        return {
            'tamanho_prompt': {
                'media': round(sum(tamanhos) / len(tamanhos), 2) if tamanhos else 0,
                'min': min(tamanhos) if tamanhos else 0,
                'max': max(tamanhos) if tamanhos else 0
            },
            'distribuicao_tipos': {tipo: tipos.count(tipo) for tipo in set(tipos)},
            'evolucao_tamanho': tamanhos  # Para análise de tendências
        }
    
    def _analisar_qualidade_respostas(self, interacoes: List[Dict]) -> Dict[str, Any]:
        """Analisa qualidade das respostas"""
        respostas_validas = [i for i in interacoes if i['resposta']['sucesso']]
        
        if not respostas_validas:
            return {'erro': 'Nenhuma resposta válida'}
        
        tamanhos_resposta = [r['resposta']['tamanho_caracteres'] for r in respostas_validas]
        tempos_resposta = [r['metricas']['tempo_resposta_segundos'] 
                          for r in respostas_validas 
                          if r['metricas']['tempo_resposta_segundos'] is not None]
        
        return {
            'taxa_sucesso': len(respostas_validas) / len(interacoes) * 100,
            'tamanho_resposta': {
                'media': round(sum(tamanhos_resposta) / len(tamanhos_resposta), 2),
                'min': min(tamanhos_resposta),
                'max': max(tamanhos_resposta)
            },
            'tempo_resposta': {
                'media_segundos': round(sum(tempos_resposta) / len(tempos_resposta), 2) if tempos_resposta else 0,
                'min_segundos': min(tempos_resposta) if tempos_resposta else 0,
                'max_segundos': max(tempos_resposta) if tempos_resposta else 0
            }
        }
    
    def _identificar_melhorias(self, interacoes: List[Dict], estatisticas: Dict) -> List[str]:
        """Identifica pontos de melhoria"""
        melhorias = []
        
        # Taxa de sucesso baixa
        taxa_sucesso = estatisticas.get('taxa_sucesso_percent', 0)
        if taxa_sucesso < 90:
            melhorias.append(f"Taxa de sucesso baixa ({taxa_sucesso}%) - verificar conectividade e prompts")
        
        # Tempo de resposta alto
        tempo_medio = estatisticas.get('tempo_resposta', {}).get('media_segundos', 0)
        if tempo_medio > 15:
            melhorias.append(f"Tempo de resposta alto ({tempo_medio}s) - otimizar prompts ou conexão")
        
        # Prompts muito longos
        tamanho_medio_prompt = estatisticas.get('caracteres', {}).get('media_prompt', 0)
        if tamanho_medio_prompt > 3000:
            melhorias.append(f"Prompts muito longos (média {tamanho_medio_prompt} chars) - considerar resumir contexto")
        
        # Poucas interações por sessão
        total_interacoes = len(interacoes)
        if total_interacoes < 3:
            melhorias.append("Poucas interações por sessão - sistema pode estar parando muito cedo")
        
        if not melhorias:
            melhorias.append("Sessão com boa performance geral")
        
        return melhorias
    
    def _analisar_tendencias_temporais(self, sessoes: List[Dict]) -> Dict[str, Any]:
        """Analisa tendências temporais nas sessões"""
        # Ordenar por timestamp
        sessoes_ordenadas = sorted(sessoes, key=lambda x: x['timestamp_inicio'] or '')
        
        if len(sessoes_ordenadas) < 2:
            return {'erro': 'Dados insuficientes para análise temporal'}
        
        # Dividir em duas metades para comparação
        meio = len(sessoes_ordenadas) // 2
        primeira_metade = sessoes_ordenadas[:meio]
        segunda_metade = sessoes_ordenadas[meio:]
        
        # Calcular médias
        taxa_sucesso_inicial = sum(s['taxa_sucesso'] for s in primeira_metade) / len(primeira_metade)
        taxa_sucesso_recente = sum(s['taxa_sucesso'] for s in segunda_metade) / len(segunda_metade)
        
        duracao_inicial = sum(s['duracao_minutos'] for s in primeira_metade) / len(primeira_metade)
        duracao_recente = sum(s['duracao_minutos'] for s in segunda_metade) / len(segunda_metade)
        
        return {
            'melhoria_taxa_sucesso': round(taxa_sucesso_recente - taxa_sucesso_inicial, 2),
            'variacao_duracao': round(duracao_recente - duracao_inicial, 2),
            'tendencia_geral': 'melhorando' if taxa_sucesso_recente > taxa_sucesso_inicial else 'estável_ou_piorando'
        }


# Instância global para uso fácil
historico_global = None

def obter_gerenciador_historico() -> GerenciadorHistorico:
    """Obtém instância global do gerenciador de histórico"""
    global historico_global
    if historico_global is None:
        historico_global = GerenciadorHistorico()
    return historico_global
