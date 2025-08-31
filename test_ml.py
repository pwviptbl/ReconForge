#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste do Sistema de Aprendizado de Máquina
Fase 2 - Aprendizado Contínuo e Adaptabilidade
"""

import os
import sys
import json
import time
from pathlib import Path

# Adicionar diretório raiz ao path para importar módulos
sys.path.append(str(Path(__file__).parent))

from historico_ia.gerenciador_historico import obter_aprendizado_maquina
from core.configuracao import GerenciadorConfiguracao

# Configuração de log
def log(mensagem):
    """Log simples para testes"""
    print(f"[{time.strftime('%H:%M:%S')}] {mensagem}")

def main():
    """Função principal para testar o sistema de aprendizado de máquina"""
    log("📊 Teste do Sistema de Aprendizado de Máquina - Fase 2")
    log("===================================================")
    
    # Carregar configurações
    log("🔧 Carregando configurações...")
    config_manager = GerenciadorConfiguracao()
    config = config_manager.configuracoes
    
    # Inicializar sistema de ML
    log("🧠 Inicializando sistema de aprendizado de máquina...")
    ml = obter_aprendizado_maquina()
    
    # Etapa 1: Carregar e processar dados
    log("📂 Carregando e processando dados históricos...")
    df = ml.carregar_e_processar_dados()
    
    if df is None or df.empty:
        log("❌ Nenhum dado encontrado para processamento. Verifique a pasta 'dados/'.")
        return
    
    log(f"✅ Dados processados: {len(df)} registros")
    
    # Mostrar algumas estatísticas básicas
    if not df.empty:
        log("\n📊 Estatísticas básicas:")
        
        # Contar sucessos/falhas
        if 'sucesso' in df.columns:
            total_sucesso = df['sucesso'].sum()
            total_falha = len(df) - total_sucesso
            taxa_sucesso = (total_sucesso / len(df)) * 100
            log(f"- Taxa de sucesso: {taxa_sucesso:.2f}% ({total_sucesso} sucessos, {total_falha} falhas)")
        
        # Módulos mais executados
        modulos_colunas = [c for c in df.columns if c.startswith('modulo_')]
        if modulos_colunas:
            log("\n📋 Módulos mais utilizados:")
            for coluna in modulos_colunas:
                if df[coluna].sum() > 0:
                    nome_modulo = coluna.replace('modulo_', '')
                    log(f"- {nome_modulo}: {int(df[coluna].sum())} execuções")
    
    # Etapa 2: Treinar modelos
    log("\n🧠 Treinando modelos de aprendizado de máquina...")
    resultado_treino = ml.treinar_modelos()
    
    if not resultado_treino:
        log("⚠️ Não foi possível treinar os modelos. Verificando se existem modelos salvos...")
        resultado_carregamento = ml.carregar_modelos_salvos()
        
        if resultado_carregamento:
            log(f"✅ Modelos carregados: {', '.join(k for k, v in resultado_carregamento.items() if v == 'carregado')}")
        else:
            log("❌ Nenhum modelo salvo encontrado.")
            return
    else:
        log("✅ Modelos treinados com sucesso!")
        
        # Mostrar métricas de treinamento
        if 'classificacao_sucesso' in resultado_treino:
            acuracia = resultado_treino['classificacao_sucesso'].get('acuracia', 0)
            log(f"- Modelo de classificação: Acurácia de {acuracia*100:.2f}%")
            
            # Características importantes
            if 'caracteristicas_importantes' in resultado_treino['classificacao_sucesso']:
                log("\n🔍 Características mais importantes:")
                for caract, imp in resultado_treino['classificacao_sucesso']['caracteristicas_importantes'][:5]:
                    log(f"- {caract}: {imp:.4f}")
        
        if 'clustering' in resultado_treino:
            n_clusters = resultado_treino['clustering'].get('n_clusters', 0)
            log(f"- Modelo de clustering: {n_clusters} clusters identificados")
    
    # Etapa 3: Testar sugestões de módulos
    log("\n🧪 Testando sugestões de módulos...")
    
    # Contexto de teste 1: Início de varredura
    contexto_teste_1 = {
        'modulos_executados': ['resolucao_dns'],
        'ips_descobertos': ['192.168.1.1'],
        'portas_abertas': {'192.168.1.1': [80, 443, 22]},
        'vulnerabilidades_encontradas': []
    }
    
    sugestao_1 = ml.sugerir_modulos(contexto_teste_1)
    log(f"- Sugestão para início de varredura: {sugestao_1.get('modulos_sugeridos', [])}")
    
    # Contexto de teste 2: Varredura avançada
    contexto_teste_2 = {
        'modulos_executados': ['resolucao_dns', 'nmap_varredura_basica', 'nmap_varredura_completa'],
        'ips_descobertos': ['192.168.1.1'],
        'portas_abertas': {'192.168.1.1': [80, 443, 22, 3306, 8080]},
        'vulnerabilidades_encontradas': [{'tipo': 'ssl', 'porta': 443}]
    }
    
    sugestao_2 = ml.sugerir_modulos(contexto_teste_2)
    log(f"- Sugestão para varredura avançada: {sugestao_2.get('modulos_sugeridos', [])}")
    
    # Etapa 4: Detectar anomalias
    log("\n🔍 Testando detecção de anomalias...")
    
    # Caso normal
    caso_normal = {
        'num_modulos': 3,
        'ips_descobertos': 1,
        'total_portas': 4,
        'vulnerabilidades': 0
    }
    
    resultado_normal = ml.detectar_anomalias(caso_normal)
    if resultado_normal and 'erro' not in resultado_normal:
        status = "Anômalo" if resultado_normal.get('anomalia_detectada', False) else "Normal"
        log(f"- Caso normal detectado como: {status}")
        
    # Caso anômalo
    caso_anomalo = {
        'num_modulos': 10,
        'ips_descobertos': 50,
        'total_portas': 200,
        'vulnerabilidades': 30
    }
    
    resultado_anomalo = ml.detectar_anomalias(caso_anomalo)
    if resultado_anomalo and 'erro' not in resultado_anomalo:
        status = "Anômalo" if resultado_anomalo.get('anomalia_detectada', False) else "Normal"
        log(f"- Caso extremo detectado como: {status}")
    
    # Etapa 5: Analisar tendências
    log("\n📈 Analisando tendências...")
    tendencias = ml.analisar_tendencias()
    
    if tendencias and 'erro' not in tendencias:
        log(f"- Tendência de sucesso: {tendencias.get('tendencia_sucesso', {}).get('direcao', 'desconhecida')}")
        log(f"- Taxa atual de sucesso: {tendencias.get('tendencia_sucesso', {}).get('taxa_atual', 0)}%")
        
        # Módulos mais utilizados
        modulos_utilizados = tendencias.get('modulos_mais_utilizados', {})
        if modulos_utilizados:
            log("\n📊 Módulos mais utilizados historicamente:")
            for modulo, contagem in modulos_utilizados.items():
                log(f"- {modulo}: {contagem} execuções")
    
    log("\n✅ Teste do sistema de aprendizado de máquina concluído!")

if __name__ == "__main__":
    main()
