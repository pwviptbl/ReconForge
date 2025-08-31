#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gerenciador de Histórico de Interações com IA
Salva e gerencia conversas para análise futura
Implementa aprendizado de máquina para análise de padrões e recomendações
"""

import os
import json
import uuid
import hashlib
import pickle
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
import warnings
import concurrent.futures

# Bibliotecas de análise de dados e ML
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.pipeline import Pipeline
import joblib

# Otimização com processamento paralelo (se disponível)
try:
    import ray
    RAY_DISPONIVEL = True
except ImportError:
    RAY_DISPONIVEL = False

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


class AprendizadoMaquina:
    """
    Classe para implementar aprendizado de máquina com dados históricos
    de varreduras e interações com IA
    """
    
    def __init__(self, pasta_dados: str = None, pasta_modelos: str = None):
        """
        Inicializa o sistema de aprendizado de máquina
        
        Args:
            pasta_dados: Caminho para a pasta com dados JSON
            pasta_modelos: Caminho para salvar modelos treinados
        """
        self.logger = obter_logger('AprendizadoML')
        
        # Definir pasta de dados
        if pasta_dados:
            self.pasta_dados = Path(pasta_dados)
        else:
            # Pasta padrão
            self.pasta_dados = Path(__file__).parent.parent / 'dados'
        
        # Definir pasta de modelos
        if pasta_modelos:
            self.pasta_modelos = Path(pasta_modelos)
        else:
            # Pasta padrão para modelos
            self.pasta_modelos = Path(__file__).parent / 'modelos'
            self.pasta_modelos.mkdir(parents=True, exist_ok=True)
        
        # Modelos treinados
        self.modelos = {}
        
        # Dados processados
        self.dados_processados = None
        
        # Inicializar Ray para processamento paralelo (se disponível)
        if RAY_DISPONIVEL:
            try:
                if not ray.is_initialized():
                    ray.init(ignore_reinit_error=True, num_cpus=4)
                self.logger.info("Ray inicializado para processamento paralelo")
            except Exception as e:
                self.logger.warning(f"Erro ao inicializar Ray: {e}. Usando processamento sequencial.")
        
        self.logger.info(f"Sistema de aprendizado de máquina inicializado")
    
    def carregar_e_processar_dados(self, limite_arquivos: int = 100) -> pd.DataFrame:
        """
        Carrega e processa dados JSON da pasta de dados
        
        Args:
            limite_arquivos: Número máximo de arquivos a processar
            
        Returns:
            DataFrame com dados processados
        """
        self.logger.info(f"Carregando dados de {self.pasta_dados}")
        
        arquivos_json = list(self.pasta_dados.glob("*.json"))
        self.logger.info(f"Encontrados {len(arquivos_json)} arquivos JSON")
        
        if not arquivos_json:
            self.logger.warning("Nenhum arquivo de dados encontrado")
            return pd.DataFrame()
        
        # Ordenar por data (mais recentes primeiro)
        arquivos_json.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        arquivos_a_processar = arquivos_json[:limite_arquivos]
        
        # Carregar dados
        dados_brutos = []
        
        # Usar processamento paralelo se disponível
        if RAY_DISPONIVEL:
            dados_brutos = self._carregar_dados_paralelo(arquivos_a_processar)
        else:
            dados_brutos = self._carregar_dados_sequencial(arquivos_a_processar)
        
        # Converter para DataFrame
        if not dados_brutos:
            self.logger.warning("Nenhum dado válido foi carregado")
            return pd.DataFrame()
        
        # Criar DataFrame
        df = pd.DataFrame(dados_brutos)
        
        # Anonimizar dados sensíveis
        df = self._anonimizar_dados(df)
        
        # Processar e extrair características
        df_processado = self._extrair_caracteristicas(df)
        
        self.dados_processados = df_processado
        self.logger.info(f"Dados processados com sucesso: {len(df_processado)} registros")
        
        return df_processado
    
    def _carregar_dados_sequencial(self, arquivos: List[Path]) -> List[Dict]:
        """Carrega dados de forma sequencial"""
        dados = []
        
        for arquivo in arquivos:
            try:
                with open(arquivo, 'r', encoding='utf-8') as f:
                    conteudo = json.load(f)
                
                # Extrair informações relevantes
                dados.append(self._extrair_dados_varredura(conteudo, arquivo.name))
                
            except Exception as e:
                self.logger.warning(f"Erro ao processar arquivo {arquivo.name}: {e}")
        
        return dados
    
    def _carregar_dados_paralelo(self, arquivos: List[Path]) -> List[Dict]:
        """Carrega dados em paralelo usando Ray ou ThreadPoolExecutor"""
        dados = []
        
        if RAY_DISPONIVEL:
            # Definir função remota Ray
            @ray.remote
            def processar_arquivo_ray(caminho):
                try:
                    with open(caminho, 'r', encoding='utf-8') as f:
                        conteudo = json.load(f)
                    return self._extrair_dados_varredura(conteudo, Path(caminho).name)
                except Exception as e:
                    print(f"Erro ao processar {Path(caminho).name}: {e}")
                    return None
            
            # Processar arquivos em paralelo
            refs = [processar_arquivo_ray.remote(str(arquivo)) for arquivo in arquivos]
            resultados = ray.get(refs)
            dados = [r for r in resultados if r is not None]
            
        else:
            # Fallback para ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor() as executor:
                def processar_arquivo(arquivo):
                    try:
                        with open(arquivo, 'r', encoding='utf-8') as f:
                            conteudo = json.load(f)
                        return self._extrair_dados_varredura(conteudo, arquivo.name)
                    except Exception as e:
                        self.logger.warning(f"Erro ao processar {arquivo.name}: {e}")
                        return None
                
                resultados = executor.map(processar_arquivo, arquivos)
                dados = [r for r in resultados if r is not None]
        
        return dados
    
    def _extrair_dados_varredura(self, conteudo: Dict, nome_arquivo: str) -> Dict:
        """Extrai dados relevantes de um arquivo de varredura"""
        dados = {
            'arquivo': nome_arquivo,
            'timestamp': conteudo.get('timestamp_inicio', ''),
            'alvo_original': conteudo.get('alvo_original', ''),
            'sucesso': conteudo.get('sucesso_geral', False),
            'tempo_total': conteudo.get('tempo_total', ''),
            'num_modulos': len(conteudo.get('contexto_execucao', {}).get('modulos_executados', [])),
            'modulos_executados': conteudo.get('contexto_execucao', {}).get('modulos_executados', []),
            'ips_descobertos': len(conteudo.get('contexto_execucao', {}).get('ips_descobertos', [])),
            'total_portas': sum(len(portas) for portas in conteudo.get('contexto_execucao', {}).get('portas_abertas', {}).values()),
            'vulnerabilidades': len(conteudo.get('contexto_execucao', {}).get('vulnerabilidades_encontradas', [])),
            'motivo_finalizacao': conteudo.get('contexto_execucao', {}).get('motivo_finalizacao', ''),
        }
        
        # Extrair métricas adicionais se disponíveis
        if 'estatisticas' in conteudo:
            dados['pontuacao_risco'] = conteudo.get('estatisticas', {}).get('pontuacao_risco_final', 0)
        
        return dados
    
    def _anonimizar_dados(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Anonimiza dados sensíveis no DataFrame
        
        Args:
            df: DataFrame com dados brutos
            
        Returns:
            DataFrame com dados anonimizados
        """
        # Criar cópia para não modificar o original
        df_anon = df.copy()
        
        # Anonimizar alvos com hash
        if 'alvo_original' in df_anon.columns:
            df_anon['alvo_hash'] = df_anon['alvo_original'].apply(
                lambda x: hashlib.sha256(str(x).encode()).hexdigest()[:16] if x else None
            )
            # Remover alvos originais
            df_anon.drop('alvo_original', axis=1, inplace=True)
        
        self.logger.info("Dados anonimizados com sucesso")
        return df_anon
    
    def _extrair_caracteristicas(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extrai características adicionais dos dados para ML
        
        Args:
            df: DataFrame com dados brutos
            
        Returns:
            DataFrame enriquecido com características
        """
        # Criar cópia
        df_proc = df.copy()
        
        # Converter timestamp para datetime
        if 'timestamp' in df_proc.columns:
            df_proc['timestamp'] = pd.to_datetime(df_proc['timestamp'], errors='coerce')
            
            # Extrair características temporais
            df_proc['dia_semana'] = df_proc['timestamp'].dt.dayofweek
            df_proc['hora_dia'] = df_proc['timestamp'].dt.hour
            df_proc['mes'] = df_proc['timestamp'].dt.month
        
        # Extrair características de modulos executados
        if 'modulos_executados' in df_proc.columns:
            # One-hot encoding de módulos comuns
            modulos_comuns = [
                'resolucao_dns', 
                'scan_inicial',
                'nmap_varredura_basica', 
                'nmap_varredura_completa',
                'scanner_web_avancado',
                'detector_tecnologias_python',
                'scanner_vulnerabilidades'
            ]
            
            for modulo in modulos_comuns:
                df_proc[f'modulo_{modulo}'] = df_proc['modulos_executados'].apply(
                    lambda x: 1 if modulo in x else 0
                )
        
        # Converter tempo_total para segundos
        if 'tempo_total' in df_proc.columns:
            def converter_tempo_para_segundos(tempo_str):
                try:
                    if isinstance(tempo_str, str):
                        if 'minutos' in tempo_str:
                            minutos = float(tempo_str.split()[0])
                            return minutos * 60
                        elif 'segundos' in tempo_str:
                            return float(tempo_str.split()[0])
                    return 0
                except:
                    return 0
            
            df_proc['duracao_segundos'] = df_proc['tempo_total'].apply(converter_tempo_para_segundos)
        
        # Categorizar por complexidade
        if 'num_modulos' in df_proc.columns and 'total_portas' in df_proc.columns:
            df_proc['complexidade'] = 'baixa'
            mask = (df_proc['num_modulos'] >= 3) | (df_proc['total_portas'] >= 5)
            df_proc.loc[mask, 'complexidade'] = 'media'
            mask = (df_proc['num_modulos'] >= 5) | (df_proc['total_portas'] >= 10)
            df_proc.loc[mask, 'complexidade'] = 'alta'
        
        return df_proc
    
    def treinar_modelos(self) -> Dict:
        """
        Treina diferentes modelos de ML com os dados processados
        
        Returns:
            Dicionário com métricas dos modelos treinados
        """
        if self.dados_processados is None or len(self.dados_processados) < 10:
            self.logger.warning("Dados insuficientes para treinamento. Carregue mais dados.")
            return {}
        
        resultados_treino = {}
        df = self.dados_processados
        
        # 1. Modelo de classificação para prever sucesso
        resultados_treino['classificacao_sucesso'] = self._treinar_modelo_classificacao(df)
        
        # 2. Modelo de clustering para identificar padrões
        resultados_treino['clustering'] = self._treinar_modelo_clustering(df)
        
        # 3. Modelo de detecção de anomalias
        resultados_treino['deteccao_anomalias'] = self._treinar_modelo_anomalias(df)
        
        self.logger.info(f"Treinamento completo. Modelos disponíveis: {list(self.modelos.keys())}")
        
        return resultados_treino
    
    def _treinar_modelo_classificacao(self, df: pd.DataFrame) -> Dict:
        """Treina modelo de classificação para prever sucesso"""
        if 'sucesso' not in df.columns:
            return {'erro': 'Coluna sucesso não encontrada'}
        
        try:
            # Selecionar características
            colunas_numericas = df.select_dtypes(include=['number']).columns.tolist()
            colunas_numericas = [c for c in colunas_numericas if c != 'sucesso' and not c.startswith('timestamp')]
            
            # Verificar se temos dados suficientes
            if len(colunas_numericas) < 2:
                return {'erro': 'Características numéricas insuficientes'}
            
            if len(df) < 10:
                return {'erro': 'Quantidade de amostras insuficiente'}
            
            # Preparar dados
            X = df[colunas_numericas].fillna(0)
            y = df['sucesso'].astype(int)
            
            # Dividir dados
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            
            # Treinar modelo
            modelo = Pipeline([
                ('scaler', StandardScaler()),
                ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
            ])
            
            modelo.fit(X_train, y_train)
            
            # Avaliar modelo
            y_pred = modelo.predict(X_test)
            acuracia = accuracy_score(y_test, y_pred)
            
            # Guardar modelo
            self.modelos['classificacao_sucesso'] = modelo
            
            # Salvar modelo em disco
            caminho_modelo = self.pasta_modelos / 'modelo_classificacao_sucesso.joblib'
            joblib.dump(modelo, caminho_modelo)
            
            # Características importantes
            feature_importances = modelo.named_steps['classifier'].feature_importances_
            features_dict = dict(zip(colunas_numericas, feature_importances))
            
            return {
                'acuracia': acuracia,
                'caracteristicas_importantes': sorted(features_dict.items(), key=lambda x: x[1], reverse=True),
                'n_samples': len(X),
                'caminho_modelo': str(caminho_modelo)
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao treinar modelo de classificação: {e}")
            return {'erro': str(e)}
    
    def _treinar_modelo_clustering(self, df: pd.DataFrame) -> Dict:
        """Treina modelo de clustering para agrupar padrões similares"""
        try:
            # Selecionar características numéricas
            colunas_numericas = df.select_dtypes(include=['number']).columns.tolist()
            
            # Verificar se temos dados suficientes
            if len(colunas_numericas) < 3:
                return {'erro': 'Características numéricas insuficientes'}
            
            if len(df) < 10:
                return {'erro': 'Quantidade de amostras insuficiente'}
            
            # Preparar dados
            X = df[colunas_numericas].fillna(0)
            
            # Normalizar dados
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            # Determinar número ideal de clusters
            inertia = []
            max_clusters = min(8, len(df) // 2)
            for i in range(1, max_clusters + 1):
                kmeans = KMeans(n_clusters=i, random_state=42, n_init=10)
                kmeans.fit(X_scaled)
                inertia.append(kmeans.inertia_)
            
            # Escolher número de clusters (método "elbow")
            optimal_clusters = 3  # valor padrão
            
            # Treinar modelo final
            kmeans = KMeans(n_clusters=optimal_clusters, random_state=42, n_init=10)
            clusters = kmeans.fit_predict(X_scaled)
            
            # Adicionar clusters ao DataFrame
            df_copy = df.copy()
            df_copy['cluster'] = clusters
            
            # Analisar características de cada cluster
            cluster_profiles = {}
            for i in range(optimal_clusters):
                cluster_df = df_copy[df_copy['cluster'] == i]
                profile = {
                    'n_samples': len(cluster_df),
                    'percent': round(len(cluster_df) / len(df) * 100, 1)
                }
                
                # Estatísticas por coluna numérica
                for col in colunas_numericas:
                    if col in cluster_df.columns:
                        profile[f'{col}_mean'] = cluster_df[col].mean()
                
                cluster_profiles[f'cluster_{i}'] = profile
            
            # Guardar modelo
            self.modelos['clustering'] = {
                'kmeans': kmeans,
                'scaler': scaler,
                'colunas': colunas_numericas
            }
            
            # Salvar modelo
            caminho_modelo = self.pasta_modelos / 'modelo_clustering.joblib'
            joblib.dump(self.modelos['clustering'], caminho_modelo)
            
            return {
                'n_clusters': optimal_clusters,
                'cluster_profiles': cluster_profiles,
                'inertia': inertia,
                'caminho_modelo': str(caminho_modelo)
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao treinar modelo de clustering: {e}")
            return {'erro': str(e)}
    
    def _treinar_modelo_anomalias(self, df: pd.DataFrame) -> Dict:
        """Treina modelo de detecção de anomalias"""
        try:
            # Selecionar características numéricas
            colunas_numericas = df.select_dtypes(include=['number']).columns.tolist()
            
            # Verificar se temos dados suficientes
            if len(colunas_numericas) < 3:
                return {'erro': 'Características numéricas insuficientes'}
            
            if len(df) < 10:
                return {'erro': 'Quantidade de amostras insuficiente'}
            
            # Preparar dados
            X = df[colunas_numericas].fillna(0)
            
            # Normalizar dados
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            # Treinar modelo
            modelo = IsolationForest(contamination=0.1, random_state=42)
            modelo.fit(X_scaled)
            
            # Predição de anomalias (-1 para anomalias, 1 para normais)
            anomalias = modelo.predict(X_scaled)
            
            # Adicionar predições ao DataFrame
            df_copy = df.copy()
            df_copy['anomalia'] = anomalias
            
            # Contar anomalias
            count_anomalias = sum(1 for a in anomalias if a == -1)
            percentual_anomalias = count_anomalias / len(anomalias) * 100
            
            # Guardar modelo
            self.modelos['deteccao_anomalias'] = {
                'modelo': modelo,
                'scaler': scaler,
                'colunas': colunas_numericas
            }
            
            # Salvar modelo
            caminho_modelo = self.pasta_modelos / 'modelo_anomalias.joblib'
            joblib.dump(self.modelos['deteccao_anomalias'], caminho_modelo)
            
            return {
                'total_anomalias': count_anomalias,
                'percentual_anomalias': round(percentual_anomalias, 2),
                'n_samples': len(X),
                'caminho_modelo': str(caminho_modelo)
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao treinar modelo de anomalias: {e}")
            return {'erro': str(e)}
    
    def carregar_modelos_salvos(self) -> Dict:
        """
        Carrega modelos salvos do disco
        
        Returns:
            Dict com status do carregamento
        """
        resultados = {}
        
        try:
            # Verificar e carregar modelo de classificação
            caminho_class = self.pasta_modelos / 'modelo_classificacao_sucesso.joblib'
            if caminho_class.exists():
                self.modelos['classificacao_sucesso'] = joblib.load(caminho_class)
                resultados['classificacao_sucesso'] = 'carregado'
            
            # Verificar e carregar modelo de clustering
            caminho_cluster = self.pasta_modelos / 'modelo_clustering.joblib'
            if caminho_cluster.exists():
                self.modelos['clustering'] = joblib.load(caminho_cluster)
                resultados['clustering'] = 'carregado'
            
            # Verificar e carregar modelo de anomalias
            caminho_anomalias = self.pasta_modelos / 'modelo_anomalias.joblib'
            if caminho_anomalias.exists():
                self.modelos['deteccao_anomalias'] = joblib.load(caminho_anomalias)
                resultados['deteccao_anomalias'] = 'carregado'
            
            self.logger.info(f"Modelos carregados: {list(resultados.keys())}")
            
        except Exception as e:
            self.logger.error(f"Erro ao carregar modelos: {e}")
            resultados['erro'] = str(e)
        
        return resultados
    
    def prever_sucesso_varredura(self, dados_alvo: Dict) -> Dict:
        """
        Prevê probabilidade de sucesso para uma nova varredura
        
        Args:
            dados_alvo: Dicionário com características do alvo
            
        Returns:
            Dict com previsões e recomendações
        """
        if 'classificacao_sucesso' not in self.modelos:
            self.logger.warning("Modelo de classificação não carregado. Tentando carregar do disco...")
            self.carregar_modelos_salvos()
            
            if 'classificacao_sucesso' not in self.modelos:
                return {'erro': 'Modelo de classificação não disponível'}
        
        try:
            # Extrair features do modelo
            modelo = self.modelos['classificacao_sucesso']
            if isinstance(modelo, Pipeline):
                # Para scikit-learn Pipeline
                feature_names = modelo.feature_names_in_
            else:
                return {'erro': 'Modelo em formato não suportado'}
            
            # Criar vetor de features
            features = []
            for feat in feature_names:
                features.append(dados_alvo.get(feat, 0))
            
            # Fazer previsão
            X = np.array(features).reshape(1, -1)
            probabilidade = modelo.predict_proba(X)[0][1]  # Probabilidade da classe 1 (sucesso)
            
            return {
                'probabilidade_sucesso': round(probabilidade * 100, 1),
                'recomendacao': 'Prosseguir com varredura' if probabilidade > 0.6 else 'Considerar ajustes na varredura'
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao fazer previsão: {e}")
            return {'erro': f'Falha na previsão: {str(e)}'}
    
    def detectar_anomalias(self, dados_varredura: Dict) -> Dict:
        """
        Detecta se uma varredura é anômala com base no modelo
        
        Args:
            dados_varredura: Dicionário com dados da varredura
            
        Returns:
            Dict com resultado da detecção
        """
        if 'deteccao_anomalias' not in self.modelos:
            self.logger.warning("Modelo de detecção de anomalias não disponível")
            self.carregar_modelos_salvos()
            
            if 'deteccao_anomalias' not in self.modelos:
                return {'erro': 'Modelo de detecção de anomalias não disponível'}
        
        try:
            # Obter componentes do modelo
            info_modelo = self.modelos['deteccao_anomalias']
            modelo = info_modelo['modelo']
            scaler = info_modelo['scaler']
            colunas = info_modelo['colunas']
            
            # Criar vetor de features
            features = []
            for col in colunas:
                features.append(dados_varredura.get(col, 0))
            
            # Escalar e prever
            X = np.array(features).reshape(1, -1)
            X_scaled = scaler.transform(X)
            resultado = modelo.predict(X_scaled)[0]
            
            # -1 para anomalias, 1 para normais
            is_anomalia = (resultado == -1)
            
            return {
                'anomalia_detectada': is_anomalia,
                'confianca': abs(modelo.score_samples(X_scaled)[0]),
                'recomendacao': 'Investigar varredura com cuidado' if is_anomalia else 'Varredura com padrão normal'
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao detectar anomalia: {e}")
            return {'erro': f'Falha na detecção: {str(e)}'}
    
    def sugerir_modulos(self, contexto_atual: Dict) -> Dict:
        """
        Sugere próximos módulos com base em padrões históricos
        
        Args:
            contexto_atual: Dicionário com contexto da varredura atual
            
        Returns:
            Dict com sugestões de módulos
        """
        # Verificar se temos dados processados
        if self.dados_processados is None or len(self.dados_processados) < 5:
            return {
                'erro': 'Dados insuficientes para sugestões',
                'modulos_sugeridos': ['nmap_varredura_basica', 'scanner_vulnerabilidades']  # fallback
            }
        
        try:
            # Obter módulos já executados
            modulos_executados = contexto_atual.get('modulos_executados', [])
            
            # Filtrar dados similares
            df = self.dados_processados
            
            # Selecionar apenas varreduras bem sucedidas
            df_sucesso = df[df['sucesso'] == True].copy()
            
            if len(df_sucesso) < 3:
                return {
                    'erro': 'Dados de sucesso insuficientes',
                    'modulos_sugeridos': ['nmap_varredura_basica', 'scanner_vulnerabilidades']
                }
            
            # Agrupar por padrão de módulos e contar frequência
            modulos_por_frequencia = {}
            
            # Obter todas as colunas de módulo
            colunas_modulo = [c for c in df_sucesso.columns if c.startswith('modulo_')]
            
            # Contar frequência de uso de cada módulo
            for modulo in colunas_modulo:
                nome_modulo = modulo.replace('modulo_', '')
                if nome_modulo not in modulos_executados:  # Não sugerir módulos já executados
                    contagem = df_sucesso[modulo].sum()
                    if contagem > 0:
                        modulos_por_frequencia[nome_modulo] = contagem
            
            # Ordenar por frequência
            modulos_ordenados = sorted(modulos_por_frequencia.items(), key=lambda x: x[1], reverse=True)
            
            # Selecionar top 3
            modulos_sugeridos = [m[0] for m in modulos_ordenados[:3]]
            
            # Se não tiver sugestões, usar defaults
            if not modulos_sugeridos:
                modulos_disponiveis = ['scanner_vulnerabilidades', 'detector_tecnologias_python', 'scanner_web_avancado']
                modulos_sugeridos = [m for m in modulos_disponiveis if m not in modulos_executados][:2]
            
            return {
                'modulos_sugeridos': modulos_sugeridos,
                'confianca': 'alta' if len(df_sucesso) > 10 else 'media'
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao sugerir módulos: {e}")
            return {
                'erro': str(e),
                'modulos_sugeridos': ['scanner_vulnerabilidades']
            }
    
    def analisar_tendencias(self) -> Dict:
        """
        Analisa tendências gerais nos dados de varredura
        
        Returns:
            Dict com análises de tendências
        """
        if self.dados_processados is None or len(self.dados_processados) < 5:
            return {'erro': 'Dados insuficientes para análise de tendências'}
        
        try:
            df = self.dados_processados
            
            # Converter para datetime se necessário
            if 'timestamp' in df.columns and not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            
            # Ordenar por timestamp
            df = df.sort_values('timestamp')
            
            # Calcular tendência de sucesso ao longo do tempo
            if 'sucesso' in df.columns:
                # Dividir em janelas temporais
                df['periodo'] = pd.qcut(range(len(df)), 4, labels=['primeiro', 'segundo', 'terceiro', 'quarto'])
                
                # Taxa de sucesso por período
                sucesso_por_periodo = df.groupby('periodo')['sucesso'].mean()
                
                # Verificar tendência
                primeiro_valor = sucesso_por_periodo.iloc[0] if len(sucesso_por_periodo) > 0 else 0
                ultimo_valor = sucesso_por_periodo.iloc[-1] if len(sucesso_por_periodo) > 0 else 0
                
                tendencia_sucesso = {
                    'direcao': 'melhorando' if ultimo_valor > primeiro_valor else 'piorando',
                    'variacao': round((ultimo_valor - primeiro_valor) * 100, 1),
                    'taxa_atual': round(ultimo_valor * 100, 1)
                }
            else:
                tendencia_sucesso = {'erro': 'Dados de sucesso não disponíveis'}
            
            # Módulos mais utilizados
            colunas_modulo = [c for c in df.columns if c.startswith('modulo_')]
            modulos_utilizados = {}
            
            for modulo in colunas_modulo:
                nome = modulo.replace('modulo_', '')
                contagem = df[modulo].sum()
                if contagem > 0:
                    modulos_utilizados[nome] = int(contagem)
            
            # Ordenar por uso
            modulos_ordenados = sorted(modulos_utilizados.items(), key=lambda x: x[1], reverse=True)
            
            # Calcular duração média por mês (se houver dados suficientes)
            duracao_por_mes = {}
            
            if 'timestamp' in df.columns and 'duracao_segundos' in df.columns:
                # Extrair ano e mês
                df['ano_mes'] = df['timestamp'].dt.strftime('%Y-%m')
                
                # Calcular média por mês
                duracao_mensal = df.groupby('ano_mes')['duracao_segundos'].mean()
                
                for mes, duracao in duracao_mensal.items():
                    duracao_por_mes[mes] = round(duracao, 1)
            
            return {
                'tendencia_sucesso': tendencia_sucesso,
                'modulos_mais_utilizados': dict(modulos_ordenados[:5]),
                'duracao_por_mes': duracao_por_mes,
                'total_registros_analisados': len(df)
            }
            
        except Exception as e:
            self.logger.error(f"Erro na análise de tendências: {e}")
            return {'erro': f'Falha na análise: {str(e)}'}

# Instância global para uso fácil
historico_global = None
ml_global = None

def obter_gerenciador_historico() -> GerenciadorHistorico:
    """Obtém instância global do gerenciador de histórico"""
    global historico_global
    if historico_global is None:
        historico_global = GerenciadorHistorico()
    return historico_global

def obter_aprendizado_maquina() -> AprendizadoMaquina:
    """Obtém instância global do sistema de aprendizado de máquina"""
    global ml_global
    if ml_global is None:
        ml_global = AprendizadoMaquina()
    return ml_global
