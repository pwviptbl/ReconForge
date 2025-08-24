#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de exemplo e teste do sistema de pentest
Demonstra funcionalidades sem necessidade de Nmap instalado
"""

import sys
import json
from pathlib import Path

# Adicionar diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent))

from core.configuracao import config
from utils.logger import obter_logger
from modulos.analise_gemini import AnalisadorGemini

def teste_configuracao():
    """Testa o sistema de configuração"""
    print("=== Teste de Configuração ===")
    
    # Testar carregamento de configurações
    logger = obter_logger('Teste')
    logger.info("Testando sistema de configuração")
    
    # Exibir configurações padrão
    configs = config.obter_todas_configuracoes()
    print(f"Configurações carregadas: {len(configs)} seções")
    
    # Testar validação
    erros = config.validar_configuracoes()
    if erros:
        print(f"Erros de configuração encontrados: {len(erros)}")
        for erro, descricao in erros.items():
            print(f"  - {erro}: {descricao}")
    else:
        print("✓ Configurações válidas")
    
    return True

def teste_dados_mockados():
    """Testa análise IA com dados mockados"""
    print("\n=== Teste com Dados Mockados ===")
    
    # Criar dados de teste que simulam uma varredura
    dados_teste = {
        'tipo_varredura': 'completo',
        'timestamp': '2024-08-24T00:00:00',
        'sucesso': True,
        'dados': {
            'resumo': {
                'hosts_total': 1,
                'hosts_ativos': 1,
                'portas_abertas': 5,
                'servicos_detectados': 3,
                'vulnerabilidades': 2
            },
            'hosts': [{
                'endereco': '192.168.1.100',
                'hostname': 'test-server.local',
                'status': 'up',
                'os': {
                    'nome': 'Linux 4.x',
                    'precisao': '95',
                    'familia': 'Linux'
                },
                'portas': [
                    {
                        'numero': 22,
                        'protocolo': 'tcp',
                        'estado': 'open',
                        'servico': 'ssh',
                        'produto': 'OpenSSH',
                        'versao': '7.4',
                        'scripts': []
                    },
                    {
                        'numero': 80,
                        'protocolo': 'tcp',
                        'estado': 'open',
                        'servico': 'http',
                        'produto': 'Apache',
                        'versao': '2.4.6',
                        'scripts': [
                            {
                                'id': 'http-vuln-cve2017-5638',
                                'saida': 'Vulnerabilidade Apache Struts encontrada',
                                'elementos': []
                            }
                        ]
                    },
                    {
                        'numero': 443,
                        'protocolo': 'tcp',
                        'estado': 'open',
                        'servico': 'https',
                        'produto': 'Apache',
                        'versao': '2.4.6',
                        'scripts': []
                    },
                    {
                        'numero': 3306,
                        'protocolo': 'tcp',
                        'estado': 'open',
                        'servico': 'mysql',
                        'produto': 'MySQL',
                        'versao': '5.5.62',
                        'scripts': [
                            {
                                'id': 'mysql-vuln-cve2012-2122',
                                'saida': 'Vulnerabilidade de autenticação MySQL',
                                'elementos': []
                            }
                        ]
                    },
                    {
                        'numero': 5432,
                        'protocolo': 'tcp',
                        'estado': 'open',
                        'servico': 'postgresql',
                        'produto': 'PostgreSQL',
                        'versao': '9.6.2',
                        'scripts': []
                    }
                ],
                'scripts': []
            }]
        }
    }
    
    print("Dados de teste criados:")
    print(f"  Host: {dados_teste['dados']['hosts'][0]['endereco']}")
    print(f"  Portas abertas: {dados_teste['dados']['resumo']['portas_abertas']}")
    print(f"  Serviços: {dados_teste['dados']['resumo']['servicos_detectados']}")
    print(f"  Vulnerabilidades: {dados_teste['dados']['resumo']['vulnerabilidades']}")
    
    # Salvar dados de exemplo
    exemplo_file = "exemplo_varredura.json"
    with open(exemplo_file, 'w', encoding='utf-8') as f:
        json.dump(dados_teste, f, indent=2, ensure_ascii=False)
    
    print(f"\n✓ Dados de exemplo salvos em: {exemplo_file}")
    
    # Testar análise IA se API configurada
    try:
        analisador = AnalisadorGemini()
        if analisador.conectar():
            print("\n=== Testando Análise IA ===")
            resultado = analisador.analisar_varredura_completa(dados_teste)
            
            if 'erro' not in resultado:
                print("✓ Análise IA executada com sucesso!")
                print(f"Nível de risco: {resultado.get('nivel_risco_geral', 'N/A')}")
                
                # Salvar resultado da análise
                analise_file = "exemplo_analise_ia.json"
                with open(analise_file, 'w', encoding='utf-8') as f:
                    json.dump(resultado, f, indent=2, ensure_ascii=False)
                print(f"✓ Análise IA salva em: {analise_file}")
            else:
                print(f"✗ Erro na análise IA: {resultado['erro']}")
        else:
            print("⚠ API Gemini não configurada - pulando teste de IA")
    except Exception as e:
        print(f"⚠ Erro ao testar IA: {str(e)}")
    
    return True

def teste_relatorio():
    """Testa geração de relatório"""
    print("\n=== Teste de Relatório ===")
    
    # Verificar se existe arquivo de exemplo
    exemplo_file = "exemplo_varredura.json"
    if not Path(exemplo_file).exists():
        print(f"✗ Arquivo de exemplo não encontrado: {exemplo_file}")
        return False
    
    try:
        # Testar CLI de relatório
        import subprocess
        resultado = subprocess.run([
            sys.executable, "cli/comandos.py", "relatorio", 
            "--arquivo", exemplo_file, 
            "--formato", "texto"
        ], capture_output=True, text=True, timeout=30)
        
        if resultado.returncode == 0:
            print("✓ Geração de relatório texto funcionando")
            print("Exemplo de saída:")
            print(resultado.stdout[:500] + "..." if len(resultado.stdout) > 500 else resultado.stdout)
        else:
            print(f"✗ Erro na geração de relatório: {resultado.stderr}")
    
    except Exception as e:
        print(f"⚠ Erro ao testar relatório: {str(e)}")
    
    return True

def demonstracao_completa():
    """Executa demonstração completa do sistema"""
    print("=" * 60)
    print("DEMONSTRAÇÃO DO SISTEMA DE PENTEST")
    print("=" * 60)
    
    # Teste 1: Configuração
    if not teste_configuracao():
        print("✗ Falha no teste de configuração")
        return False
    
    # Teste 2: Dados mockados e IA
    if not teste_dados_mockados():
        print("✗ Falha no teste de dados mockados")
        return False
    
    # Teste 3: Relatório
    if not teste_relatorio():
        print("✗ Falha no teste de relatório")
        return False
    
    print("\n" + "=" * 60)
    print("✓ DEMONSTRAÇÃO CONCLUÍDA COM SUCESSO!")
    print("=" * 60)
    
    print("\nPróximos passos:")
    print("1. Instale o Nmap para varreduras reais:")
    print("   - Windows: choco install nmap")
    print("   - Ou download: https://nmap.org/download.html")
    print()
    print("2. Configure a API Gemini:")
    print("   - python main.py --configurar")
    print("   - Obtenha chave em: https://aistudio.google.com/app/apikey")
    print()
    print("3. Execute varreduras reais:")
    print("   - python main.py --alvo scanme.nmap.org --tipo completo --ia")
    print()
    print("4. Use a interface CLI completa:")
    print("   - python main.py --cli")
    
    return True

if __name__ == "__main__":
    demonstracao_completa()