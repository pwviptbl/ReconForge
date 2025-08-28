#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de configuração inicial do VarreduraIA
Configura o arquivo de configuração YAML a partir do template
"""

import sys
import shutil
from pathlib import Path
from typing import Optional

def setup_configuracao() -> bool:
    """
    Configura o arquivo de configuração inicial
    Returns:
        bool: True se configurado com sucesso
    """
    config_dir = Path(__file__).parent / "config"
    arquivo_exemplo = config_dir / "default.yaml.example"
    arquivo_config = config_dir / "default.yaml"
    
    print("=== Setup do VarreduraIA ===\n")
    
    # Verificar se o arquivo de exemplo existe
    if not arquivo_exemplo.exists():
        print(f" Arquivo de exemplo não encontrado: {arquivo_exemplo}")
        return False
    
    # Verificar se já existe configuração
    if arquivo_config.exists():
        resposta = input(f"  Arquivo de configuração já existe em {arquivo_config}\n"
                        "Deseja sobrescrever? (s/N): ").strip().lower()
        if resposta not in ['s', 'sim', 'y', 'yes']:
            print(" Mantendo configuração existente")
            return True
    
    try:
        # Copiar arquivo de exemplo
        shutil.copy2(arquivo_exemplo, arquivo_config)
        print(f" Arquivo de configuração criado: {arquivo_config}")
        
        # Configuração interativa básica
        print("\n=== Configuração Básica ===")
        
        # Configurar chave API do Gemini
        print("\n1. Configuração da API Gemini")
        print("Para obter sua chave API:")
        print("   1. Acesse: https://aistudio.google.com/app/apikey")
        print("   2. Faça login com sua conta Google")
        print("   3. Clique em 'Create API Key'")
        print("   4. Copie a chave gerada")
        
        chave_api = input("\nDigite sua chave API do Gemini (ou deixe vazio para configurar depois): ").strip()
        
        if chave_api:
            # Ler e atualizar arquivo
            with open(arquivo_config, 'r', encoding='utf-8') as f:
                conteudo = f.read()
            
            # Substituir placeholder pela chave real
            conteudo = conteudo.replace('SUA_CHAVE_API_AQUI', chave_api)
            
            with open(arquivo_config, 'w', encoding='utf-8') as f:
                f.write(conteudo)
            
            print(" Chave API configurada!")
        else:
            print("  Lembre-se de editar o arquivo e configurar sua chave API")
        
        print(f"\n Configuração inicial concluída!")
        print(f" Para ajustes adicionais, edite: {arquivo_config}")
        
        return True
        
    except Exception as e:
        print(f" Erro durante a configuração: {str(e)}")
        return False

def verificar_configuracao() -> bool:
    """
    Verifica se a configuração está válida
    Returns:
        bool: True se válida
    """
    config_dir = Path(__file__).parent / "config"
    arquivo_config = config_dir / "default.yaml"
    
    if not arquivo_config.exists():
        print(f" Arquivo de configuração não encontrado: {arquivo_config}")
        print("Execute: python setup.py para criar a configuração inicial")
        return False
    
    try:
        # Tentar carregar e validar configuração
        sys.path.insert(0, str(Path(__file__).parent))
        from core.configuracao import config
        
        # Verificar configurações essenciais
        erros = config.validar_configuracoes()
        
        if erros:
            print("  Problemas encontrados na configuração:")
            for erro, descricao in erros.items():
                print(f"   - {erro}: {descricao}")
            print(f"\n Edite o arquivo: {arquivo_config}")
            return False
        else:
            print(" Configuração válida!")
            return True
            
    except Exception as e:
        print(f" Erro ao validar configuração: {str(e)}")
        return False

def main():
    """Função principal"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Setup e validação da configuração do VarreduraIA',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--setup', action='store_true', 
                       help='Executar configuração inicial')
    parser.add_argument('--check', action='store_true', 
                       help='Verificar configuração atual')
    
    args = parser.parse_args()
    
    if args.setup:
        sucesso = setup_configuracao()
        return 0 if sucesso else 1
    elif args.check:
        sucesso = verificar_configuracao()
        return 0 if sucesso else 1
    else:
        # Comportamento padrão: setup se não existe config, senão check
        config_dir = Path(__file__).parent / "config"
        arquivo_config = config_dir / "default.yaml"
        
        if not arquivo_config.exists():
            print(" Primeira execução detectada. Iniciando configuração...")
            sucesso = setup_configuracao()
        else:
            sucesso = verificar_configuracao()
        
        return 0 if sucesso else 1

if __name__ == "__main__":
    sys.exit(main())
