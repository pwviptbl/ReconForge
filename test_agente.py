#!/usr/bin/env python3
import sys
import os
import yaml

# Adicionar diretório atual ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def testar_agente():
    try:
        # Carregar configuração
        config_path = os.path.join('config', 'default.yaml')
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        config_ia = config.get('ia_centralizada', {})

        # Usar chave API do Gemini se não estiver definida na seção ia_centralizada
        if not config_ia.get('chave_api'):
            config_ia['chave_api'] = config.get('api', {}).get('gemini', {}).get('chave_api')

        print("🔧 Configuração IA carregada:")
        print(f"  - Agente habilitado: {config_ia.get('habilitar_agente_autonomo', False)}")
        print(f"  - Chave API presente: {bool(config_ia.get('chave_api'))}")
        print(f"  - Fallback local: {config_ia.get('fallback_local_habilitado', True)}")
        print(f"  - Modelo: {config_ia.get('modelo_principal', 'N/A')}")

        if not config_ia.get('habilitar_agente_autonomo', False):
            print("⚠️ Agente IA Central desabilitado na configuração")
            return

        if not config_ia.get('chave_api'):
            print("❌ Chave API do Gemini não encontrada")
            return

        # Importar e inicializar agente
        from core.agente_ia_central import AgenteIACentral

        print("🚀 Inicializando Agente IA Central...")
        agente = AgenteIACentral(config_ia)

        print("✅ Agente IA Central inicializado com sucesso!")

        # Testar uma decisão simples
        contexto_teste = {
            'ips_descobertos': ['192.168.1.1'],
            'portas_abertas': {},
            'servicos_detectados': {},
            'vulnerabilidades_encontradas': []
        }

        modulos_disponiveis = ['scanner_portas_python', 'scanner_vulnerabilidades']

        print("🧠 Testando tomada de decisão...")
        decisao = agente.tomar_decisao(contexto_teste, modulos_disponiveis)

        print(f"✅ Decisão tomada: {decisao}")

        agente.finalizar()

    except Exception as e:
        print(f"❌ Erro durante teste: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    testar_agente()
