#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utilitário para ajustar configurações de timeout do VarreduraIA
"""

import sys
import yaml
import argparse
from pathlib import Path

def carregar_config():
    """Carrega a configuração atual"""
    config_path = Path(__file__).parent.parent / 'config' / 'nmap_timeouts.yaml'
    
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    return None

def salvar_config(config):
    """Salva a configuração"""
    config_path = Path(__file__).parent.parent / 'config' / 'nmap_timeouts.yaml'
    
    with open(config_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, default_flow_style=False, indent=2, sort_keys=False)

def listar_timeouts():
    """Lista os timeouts atuais"""
    config = carregar_config()
    if not config:
        print("❌ Arquivo de configuração não encontrado!")
        return
    
    print("📋 Timeouts Atuais:")
    print("=" * 50)
    
    for varredura, timeout in config['timeouts'].items():
        minutos = timeout / 60
        print(f"  {varredura:<25} {timeout:>4}s ({minutos:>4.1f} min)")
    
    print("\n📊 Configurações de Performance:")
    for chave, valor in config['performance'].items():
        print(f"  {chave:<25} {valor}")

def ajustar_timeout(tipo_varredura, novo_timeout):
    """Ajusta o timeout de um tipo específico de varredura"""
    config = carregar_config()
    if not config:
        print("❌ Arquivo de configuração não encontrado!")
        return
    
    if tipo_varredura not in config['timeouts']:
        print(f"❌ Tipo de varredura '{tipo_varredura}' não encontrado!")
        print("Tipos disponíveis:", list(config['timeouts'].keys()))
        return
    
    timeout_anterior = config['timeouts'][tipo_varredura]
    config['timeouts'][tipo_varredura] = novo_timeout
    
    salvar_config(config)
    
    print(f"✅ Timeout ajustado para '{tipo_varredura}':")
    print(f"   Anterior: {timeout_anterior}s ({timeout_anterior/60:.1f} min)")
    print(f"   Novo:     {novo_timeout}s ({novo_timeout/60:.1f} min)")

def ajustar_performance(parametro, novo_valor):
    """Ajusta um parâmetro de performance"""
    config = carregar_config()
    if not config:
        print("❌ Arquivo de configuração não encontrado!")
        return
    
    if parametro not in config['performance']:
        print(f"❌ Parâmetro '{parametro}' não encontrado!")
        print("Parâmetros disponíveis:", list(config['performance'].keys()))
        return
    
    valor_anterior = config['performance'][parametro]
    
    # Converter para int se necessário
    try:
        novo_valor = int(novo_valor)
    except ValueError:
        pass
    
    config['performance'][parametro] = novo_valor
    
    salvar_config(config)
    
    print(f"✅ Parâmetro '{parametro}' ajustado:")
    print(f"   Anterior: {valor_anterior}")
    print(f"   Novo:     {novo_valor}")

def recomendar_timeouts():
    """Recomenda timeouts baseados no ambiente"""
    print("🔧 Recomendações de Timeout por Ambiente:")
    print("=" * 50)
    
    print("\n🏠 Rede Local (LAN):")
    print("  varredura_basica:          180s (3 min)")
    print("  varredura_completa:        300s (5 min)")
    print("  varredura_vulnerabilidades: 600s (10 min)")
    print("  varredura_servicos_web:    300s (5 min)")
    
    print("\n🌐 Rede Externa/WAN:")
    print("  varredura_basica:          300s (5 min)")
    print("  varredura_completa:        600s (10 min)")
    print("  varredura_vulnerabilidades: 900s (15 min)")
    print("  varredura_servicos_web:    600s (10 min)")
    
    print("\n🐌 Rede Lenta/Instável:")
    print("  varredura_basica:          600s (10 min)")
    print("  varredura_completa:        900s (15 min)")
    print("  varredura_vulnerabilidades: 1200s (20 min)")
    print("  varredura_servicos_web:    900s (15 min)")
    
    print("\n⚡ Performance Máxima:")
    print("  varredura_basica:          120s (2 min)")
    print("  varredura_completa:        240s (4 min)")
    print("  varredura_vulnerabilidades: 480s (8 min)")
    print("  varredura_servicos_web:    240s (4 min)")

def aplicar_preset(preset):
    """Aplica um preset de configurações"""
    config = carregar_config()
    if not config:
        print("❌ Arquivo de configuração não encontrado!")
        return
    
    presets = {
        'lan': {
            'varredura_basica': 180,
            'varredura_completa': 300,
            'varredura_vulnerabilidades': 600,
            'varredura_servicos_web': 300,
            'varredura_smb': 180,
            'descoberta_rede': 120,
            'varredura_personalizada': 300,
            'varredura_adaptativa': 240
        },
        'wan': {
            'varredura_basica': 300,
            'varredura_completa': 600,
            'varredura_vulnerabilidades': 900,
            'varredura_servicos_web': 600,
            'varredura_smb': 300,
            'descoberta_rede': 180,
            'varredura_personalizada': 600,
            'varredura_adaptativa': 450
        },
        'lento': {
            'varredura_basica': 600,
            'varredura_completa': 900,
            'varredura_vulnerabilidades': 1200,
            'varredura_servicos_web': 900,
            'varredura_smb': 600,
            'descoberta_rede': 300,
            'varredura_personalizada': 900,
            'varredura_adaptativa': 720
        },
        'rapido': {
            'varredura_basica': 120,
            'varredura_completa': 240,
            'varredura_vulnerabilidades': 480,
            'varredura_servicos_web': 240,
            'varredura_smb': 120,
            'descoberta_rede': 60,
            'varredura_personalizada': 240,
            'varredura_adaptativa': 180
        }
    }
    
    if preset not in presets:
        print(f"❌ Preset '{preset}' não encontrado!")
        print("Presets disponíveis:", list(presets.keys()))
        return
    
    config['timeouts'].update(presets[preset])
    salvar_config(config)
    
    print(f"✅ Preset '{preset}' aplicado com sucesso!")
    listar_timeouts()

def main():
    parser = argparse.ArgumentParser(description="Utilitário de configuração de timeouts VarreduraIA")
    subparsers = parser.add_subparsers(dest='comando', help='Comandos disponíveis')
    
    # Comando listar
    parser_listar = subparsers.add_parser('listar', help='Lista timeouts atuais')
    
    # Comando ajustar timeout
    parser_timeout = subparsers.add_parser('timeout', help='Ajusta timeout de varredura')
    parser_timeout.add_argument('tipo', help='Tipo de varredura')
    parser_timeout.add_argument('valor', type=int, help='Novo timeout em segundos')
    
    # Comando ajustar performance
    parser_perf = subparsers.add_parser('performance', help='Ajusta parâmetro de performance')
    parser_perf.add_argument('parametro', help='Parâmetro de performance')
    parser_perf.add_argument('valor', help='Novo valor')
    
    # Comando recomendar
    parser_rec = subparsers.add_parser('recomendar', help='Mostra recomendações de timeout')
    
    # Comando preset
    parser_preset = subparsers.add_parser('preset', help='Aplica preset de configurações')
    parser_preset.add_argument('tipo', choices=['lan', 'wan', 'lento', 'rapido'], 
                              help='Tipo de preset')
    
    args = parser.parse_args()
    
    if not args.comando:
        parser.print_help()
        return
    
    if args.comando == 'listar':
        listar_timeouts()
    elif args.comando == 'timeout':
        ajustar_timeout(args.tipo, args.valor)
    elif args.comando == 'performance':
        ajustar_performance(args.parametro, args.valor)
    elif args.comando == 'recomendar':
        recomendar_timeouts()
    elif args.comando == 'preset':
        aplicar_preset(args.tipo)

if __name__ == "__main__":
    main()
