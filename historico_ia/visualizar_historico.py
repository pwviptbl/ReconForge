#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utilitário CLI para visualizar histórico de interações com IA
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

# Adicionar pasta do projeto ao path para imports
sys.path.append(str(Path(__file__).parent.parent))

from historico_ia.gerenciador_historico import GerenciadorHistorico
from utils.logger import obter_logger


def exibir_lista_sessoes(gerenciador: GerenciadorHistorico, limite: int = 10):
    """Exibe lista de sessões"""
    print(f"\n📊 ÚLTIMAS {limite} SESSÕES DE IA:")
    print("=" * 80)
    
    sessoes = gerenciador.listar_sessoes(limite)
    
    if not sessoes:
        print("❌ Nenhuma sessão encontrada")
        return
    
    for i, sessao in enumerate(sessoes, 1):
        timestamp = sessao.get('timestamp_inicio', 'N/A')
        try:
            data_formatada = datetime.fromisoformat(timestamp).strftime('%d/%m/%Y %H:%M:%S')
        except:
            data_formatada = timestamp
        
        print(f"{i:2d}. 📅 {data_formatada}")
        print(f"    🎯 Alvo: {sessao.get('alvo', 'N/A')}")
        print(f"    🔄 Interações: {sessao.get('total_interacoes', 0)}")
        print(f"    ✅ Taxa Sucesso: {sessao.get('taxa_sucesso', 0):.1f}%")
        print(f"    ⏱️  Duração: {sessao.get('duracao_minutos', 0):.1f} min")
        print(f"    📁 Arquivo: {sessao.get('arquivo', 'N/A')}")
        print()


def exibir_detalhes_sessao(gerenciador: GerenciadorHistorico, sessao_id: str):
    """Exibe detalhes de uma sessão específica"""
    print(f"\n🔍 DETALHES DA SESSÃO: {sessao_id}")
    print("=" * 80)
    
    dados = gerenciador.carregar_sessao(sessao_id)
    
    if not dados:
        print("❌ Sessão não encontrada")
        return
    
    # Informações gerais
    print(f"🎯 Alvo: {dados.get('alvo', 'N/A')}")
    print(f"📅 Início: {dados.get('timestamp_inicio', 'N/A')}")
    print(f"📅 Fim: {dados.get('timestamp_fim', 'N/A')}")
    print(f"🔄 Total de Interações: {dados.get('total_interacoes', 0)}")
    
    # Estatísticas
    stats = dados.get('estatisticas', {})
    if stats:
        print(f"\n📈 ESTATÍSTICAS:")
        print(f"  ✅ Taxa de Sucesso: {stats.get('taxa_sucesso_percent', 0):.1f}%")
        print(f"  ⏱️  Tempo Médio de Resposta: {stats.get('tempo_resposta', {}).get('media_segundos', 0):.2f}s")
        print(f"  📝 Média Chars Prompt: {stats.get('caracteres', {}).get('media_prompt', 0):.0f}")
        print(f"  💬 Média Chars Resposta: {stats.get('caracteres', {}).get('media_resposta', 0):.0f}")
        print(f"  🎫 Total Tokens Estimados: {stats.get('tokens_estimados', {}).get('total_geral', 0):,}")
    
    # Tipos de prompt
    tipos = stats.get('tipos_prompt', {})
    if tipos:
        print(f"\n🏷️  TIPOS DE PROMPT:")
        for tipo, count in tipos.items():
            print(f"  • {tipo}: {count}")
    
    # Últimas interações
    interacoes = dados.get('interacoes', [])
    if interacoes:
        print(f"\n💬 ÚLTIMAS 3 INTERAÇÕES:")
        for interacao in interacoes[-3:]:
            num = interacao.get('numero_interacao', 0)
            tipo = interacao.get('tipo_prompt', 'N/A')
            sucesso = "✅" if interacao.get('resposta', {}).get('sucesso', False) else "❌"
            tempo = interacao.get('metricas', {}).get('tempo_resposta_segundos', 0)
            
            print(f"  {num:2d}. {sucesso} {tipo} ({tempo:.1f}s)")
            
            # Mostrar resumo do prompt
            prompt = interacao.get('prompt', {}).get('texto', '')
            if prompt:
                preview = prompt[:100].replace('\n', ' ')
                print(f"      📝 Prompt: {preview}{'...' if len(prompt) > 100 else ''}")
            
            # Mostrar resumo da resposta
            resposta = interacao.get('resposta', {}).get('texto', '')
            if resposta:
                preview = resposta[:100].replace('\n', ' ')
                print(f"      💬 Resposta: {preview}{'...' if len(resposta) > 100 else ''}")
            print()


def exibir_interacao_completa(gerenciador: GerenciadorHistorico, sessao_id: str, numero_interacao: int):
    """Exibe uma interação completa"""
    print(f"\n🔍 INTERAÇÃO {numero_interacao} DA SESSÃO {sessao_id}")
    print("=" * 80)
    
    dados = gerenciador.carregar_sessao(sessao_id)
    if not dados:
        print("❌ Sessão não encontrada")
        return
    
    interacoes = dados.get('interacoes', [])
    interacao = None
    
    for i in interacoes:
        if i.get('numero_interacao') == numero_interacao:
            interacao = i
            break
    
    if not interacao:
        print(f"❌ Interação {numero_interacao} não encontrada")
        return
    
    # Informações da interação
    timestamp = interacao.get('timestamp', 'N/A')
    tipo = interacao.get('tipo_prompt', 'N/A')
    tempo = interacao.get('metricas', {}).get('tempo_resposta_segundos', 0)
    sucesso = interacao.get('resposta', {}).get('sucesso', False)
    
    print(f"📅 Timestamp: {timestamp}")
    print(f"🏷️  Tipo: {tipo}")
    print(f"⏱️  Tempo de Resposta: {tempo:.2f}s")
    print(f"✅ Sucesso: {'Sim' if sucesso else 'Não'}")
    
    # Contexto adicional
    contexto = interacao.get('contexto_adicional', {})
    if contexto:
        print(f"\n🔧 CONTEXTO ADICIONAL:")
        for key, value in contexto.items():
            print(f"  • {key}: {value}")
    
    # Prompt completo
    prompt = interacao.get('prompt', {}).get('texto', '')
    print(f"\n📝 PROMPT ENVIADO ({len(prompt)} caracteres):")
    print("-" * 40)
    print(prompt)
    
    # Resposta completa
    resposta = interacao.get('resposta', {}).get('texto', '')
    print(f"\n💬 RESPOSTA RECEBIDA ({len(resposta)} caracteres):")
    print("-" * 40)
    if resposta:
        print(resposta)
    else:
        print("❌ Nenhuma resposta recebida")


def gerar_relatorio_analitico(gerenciador: GerenciadorHistorico, sessao_id: str = None):
    """Gera relatório analítico"""
    if sessao_id:
        print(f"\n📊 RELATÓRIO ANALÍTICO - SESSÃO: {sessao_id}")
    else:
        print(f"\n📊 RELATÓRIO ANALÍTICO - TODAS AS SESSÕES")
    
    print("=" * 80)
    
    relatorio = gerenciador.gerar_relatorio_analitico(sessao_id)
    
    if not relatorio or 'erro' in relatorio:
        print("❌ Erro ao gerar relatório ou dados insuficientes")
        return
    
    if sessao_id:
        # Relatório de sessão específica
        resumo = relatorio.get('resumo_geral', {})
        print(f"🎯 Sessão: {relatorio.get('sessao_id', 'N/A')}")
        print(f"🔄 Total Interações: {resumo.get('total_interacoes', 0)}")
        print(f"✅ Taxa Sucesso: {resumo.get('taxa_sucesso_percent', 0):.1f}%")
        print(f"⏱️  Tempo Médio: {resumo.get('tempo_resposta', {}).get('media_segundos', 0):.2f}s")
        
        # Padrões de prompt
        padroes = relatorio.get('padroes_prompt', {})
        if padroes:
            print(f"\n📝 PADRÕES DE PROMPT:")
            dist = padroes.get('distribuicao_tipos', {})
            for tipo, count in dist.items():
                print(f"  • {tipo}: {count}")
        
        # Pontos de melhoria
        melhorias = relatorio.get('pontos_melhoria', [])
        if melhorias:
            print(f"\n🔧 PONTOS DE MELHORIA:")
            for i, melhoria in enumerate(melhorias, 1):
                print(f"  {i}. {melhoria}")
    
    else:
        # Relatório geral
        stats = relatorio.get('estatisticas_agregadas', {})
        print(f"📊 Total Sessões Analisadas: {relatorio.get('total_sessoes_analisadas', 0)}")
        print(f"🔄 Total Interações: {stats.get('total_interacoes', 0):,}")
        print(f"✅ Taxa Sucesso Média: {stats.get('taxa_sucesso_media', 0):.1f}%")
        print(f"⏱️  Duração Média: {stats.get('duracao_media_minutos', 0):.1f} min")
        
        # Análise temporal
        temporal = relatorio.get('analise_temporal', {})
        if temporal:
            print(f"\n📈 ANÁLISE TEMPORAL:")
            melhoria = temporal.get('melhoria_taxa_sucesso', 0)
            if melhoria > 0:
                print(f"  ✅ Taxa de sucesso melhorou {melhoria:.1f}%")
            elif melhoria < 0:
                print(f"  ❌ Taxa de sucesso piorou {abs(melhoria):.1f}%")
            else:
                print(f"  ➖ Taxa de sucesso estável")
            
            tendencia = temporal.get('tendencia_geral', '')
            print(f"  📊 Tendência Geral: {tendencia}")


def main():
    """Função principal"""
    if len(sys.argv) < 2:
        print("🤖 VISUALIZADOR DE HISTÓRICO IA")
        print("=" * 40)
        print("Uso:")
        print("  python visualizar_historico.py listar [limite]")
        print("  python visualizar_historico.py sessao <sessao_id>")
        print("  python visualizar_historico.py interacao <sessao_id> <numero>")
        print("  python visualizar_historico.py relatorio [sessao_id]")
        print("\nExemplos:")
        print("  python visualizar_historico.py listar 5")
        print("  python visualizar_historico.py sessao pentest_inteligente_20250828_160537")
        print("  python visualizar_historico.py interacao pentest_inteligente_20250828_160537 3")
        print("  python visualizar_historico.py relatorio")
        return
    
    comando = sys.argv[1]
    gerenciador = GerenciadorHistorico()
    
    if comando == "listar":
        limite = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        exibir_lista_sessoes(gerenciador, limite)
    
    elif comando == "sessao":
        if len(sys.argv) < 3:
            print("❌ Erro: especifique o ID da sessão")
            return
        sessao_id = sys.argv[2]
        exibir_detalhes_sessao(gerenciador, sessao_id)
    
    elif comando == "interacao":
        if len(sys.argv) < 4:
            print("❌ Erro: especifique o ID da sessão e número da interação")
            return
        sessao_id = sys.argv[2]
        numero = int(sys.argv[3])
        exibir_interacao_completa(gerenciador, sessao_id, numero)
    
    elif comando == "relatorio":
        sessao_id = sys.argv[2] if len(sys.argv) > 2 else None
        gerar_relatorio_analitico(gerenciador, sessao_id)
    
    else:
        print(f"❌ Comando desconhecido: {comando}")


if __name__ == "__main__":
    main()
