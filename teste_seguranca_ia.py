#!/usr/bin/env python3
"""
Teste de segurança - anonimização no contexto de IA
Demonstra como IPs são mascarados antes do envio para IA
"""

import json
from modulos.decisao_ia import DecisaoIA
from utils.anonimizador_ip import criar_contexto_seguro_para_ia

def teste_contexto_seguro():
    """Testa criação de contexto seguro para IA"""
    
    print("🔒 Teste de Contexto Seguro para IA")
    print("=" * 50)
    
    # Simular dados reais de varredura
    dados_reais = {
        'resumo_scan': {
            'total_ips_scaneados': 3,
            'hosts_ativos': 2,
            'total_portas_abertas': 5,
            'hosts_com_portas_abertas': [
                {
                    'ip': '192.168.1.100',
                    'portas_abertas': 3,
                    'portas': [22, 80, 443]
                },
                {
                    'ip': '10.0.0.1', 
                    'portas_abertas': 2,
                    'portas': [80, 8080]
                }
            ]
        },
        'resultados_detalhados': {
            'hosts': [
                {
                    'endereco': '192.168.1.100',
                    'hostname': 'servidor-interno.empresa.local',
                    'status': 'up',
                    'portas': [
                        {
                            'numero': 22,
                            'protocolo': 'tcp',
                            'estado': 'open',
                            'servico': 'ssh',
                            'produto': 'OpenSSH',
                            'versao': '8.2p1'
                        }
                    ]
                }
            ]
        },
        'informacoes_sensíveis': {
            'credenciais': 'admin:password123',
            'caminhos_completos': '/home/usuario/documentos/senhas.txt',
            'tokens': 'sk-abc123def456ghi789'
        }
    }
    
    print("\n📋 Dados REAIS (NÃO devem ir para IA):")
    print(json.dumps(dados_reais, indent=2, ensure_ascii=False)[:500] + "...")
    
    # Criar contexto seguro
    print("\n🛡️ Aplicando medidas de segurança...")
    contexto_seguro = criar_contexto_seguro_para_ia(dados_reais)
    
    print("\n🔒 Dados SEGUROS (podem ir para IA):")
    print(json.dumps(contexto_seguro, indent=2, ensure_ascii=False))
    
    # Mostrar o que foi protegido
    print("\n📊 Análise de Segurança:")
    
    # Verificar anonimização de IPs
    ips_originais = ['192.168.1.100', '10.0.0.1']
    ips_encontrados_no_contexto = []
    
    def encontrar_ips_recursivo(obj):
        if isinstance(obj, dict):
            for chave, valor in obj.items():
                encontrar_ips_recursivo(valor)
        elif isinstance(obj, list):
            for item in obj:
                encontrar_ips_recursivo(item)
        elif isinstance(obj, str):
            for ip_original in ips_originais:
                if ip_original in obj:
                    ips_encontrados_no_contexto.append(ip_original)
    
    encontrar_ips_recursivo(contexto_seguro)
    
    print(f"  • IPs originais: {ips_originais}")
    print(f"  • IPs encontrados no contexto seguro: {list(set(ips_encontrados_no_contexto))}")
    print(f"  • IPs vazaram para IA? {'❌ SIM - PROBLEMA!' if ips_encontrados_no_contexto else '✅ NÃO - SEGURO!'}")
    
    # Verificar se dados sensíveis foram removidos
    contexto_str = json.dumps(contexto_seguro)
    dados_sensiveis_encontrados = []
    
    termos_sensiveis = ['admin:password123', 'senhas.txt', 'sk-abc123']
    for termo in termos_sensiveis:
        if termo in contexto_str:
            dados_sensiveis_encontrados.append(termo)
    
    print(f"  • Dados sensíveis vazaram? {'❌ SIM - PROBLEMA!' if dados_sensiveis_encontrados else '✅ NÃO - SEGURO!'}")
    if dados_sensiveis_encontrados:
        print(f"    Encontrados: {dados_sensiveis_encontrados}")
    
    # Verificar se contexto ainda é útil
    tem_estrutura = bool(contexto_seguro.get('resumo_scan'))
    tem_estatisticas = bool(contexto_seguro.get('resumo_scan', {}).get('total_portas_abertas'))
    
    print(f"  • Contexto mantém estrutura útil? {'✅ SIM' if tem_estrutura else '❌ NÃO'}")
    print(f"  • Contexto mantém estatísticas? {'✅ SIM' if tem_estatisticas else '❌ NÃO'}")
    
    return len(ips_encontrados_no_contexto) == 0 and len(dados_sensiveis_encontrados) == 0

def teste_decisao_ia_com_seguranca():
    """Testa módulo de decisão IA com segurança"""
    
    print("\n\n🧠 Teste de Decisão IA com Segurança")
    print("=" * 50)
    
    # Dados de teste
    dados_scan = {
        'resumo_scan': {
            'total_ips_scaneados': 1,
            'hosts_ativos': 1,
            'total_portas_abertas': 4,
            'hosts_com_portas_abertas': [{
                'ip': '192.168.1.208',  # IP real que não deve vazar
                'portas_abertas': 4,
                'portas': [22, 80, 8080, 443]
            }]
        }
    }
    
    try:
        decisao_ia = DecisaoIA()
        
        print("📤 Simulando envio para IA...")
        print(f"   Anonimização habilitada: {decisao_ia.anonimizar_ips}")
        
        # Simular preparação de contexto (sem enviar realmente para IA)
        contexto_seguro, mapeamento = decisao_ia._preparar_contexto_seguro_para_ia(dados_scan)
        
        print(f"   IPs mapeados: {len(mapeamento)}")
        print(f"   IP original: {list(mapeamento.keys())[0] if mapeamento else 'N/A'}")
        print(f"   IP anonimizado: {list(mapeamento.values())[0] if mapeamento else 'N/A'}")
        
        # Verificar se IP real está no contexto
        contexto_str = json.dumps(contexto_seguro)
        ip_real_presente = '192.168.1.208' in contexto_str
        
        print(f"   IP real no contexto? {'❌ SIM - PROBLEMA!' if ip_real_presente else '✅ NÃO - SEGURO!'}")
        
        return not ip_real_presente
        
    except Exception as e:
        print(f"   ⚠️ Erro no teste: {e}")
        return False

if __name__ == "__main__":
    print("🔐 TESTE DE SEGURANÇA - ANONIMIZAÇÃO DE IPs")
    print("=" * 60)
    
    # Teste 1: Contexto seguro
    resultado1 = teste_contexto_seguro()
    
    # Teste 2: Decisão IA
    resultado2 = teste_decisao_ia_com_seguranca()
    
    # Resultado final
    print("\n\n" + "=" * 60)
    print("📊 RESULTADO FINAL DOS TESTES")
    print("=" * 60)
    
    print(f"✅ Teste 1 - Contexto Seguro: {'PASSOU' if resultado1 else 'FALHOU'}")
    print(f"✅ Teste 2 - Decisão IA: {'PASSOU' if resultado2 else 'FALHOU'}")
    
    if resultado1 and resultado2:
        print("\n🎉 TODOS OS TESTES PASSARAM!")
        print("🔒 IPs estão sendo anonimizados corretamente")
        print("💡 É seguro usar a IA sem vazar informações sensíveis")
    else:
        print("\n⚠️ ALGUNS TESTES FALHARAM!")
        print("🔍 Revise a implementação de segurança")
    
    print("\n" + "=" * 60)
