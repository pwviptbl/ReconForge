#!/usr/bin/env python3
import sys
import os

# Adicionar diretório atual ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from core.agente_ia_central import AgenteIACentral
    print("✅ Importação bem-sucedida!")
    print(f"Classe AgenteIACentral: {AgenteIACentral}")
except ImportError as e:
    print(f"❌ Erro de importação: {e}")
except Exception as e:
    print(f"❌ Erro geral: {e}")
