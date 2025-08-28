#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste do Orquestrador Inteligente
Valida a nova implementação com loop adaptativo
"""

import sys
from pathlib import Path

# Adicionar o diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent))

from utils.logger import obter_logger, log_manager
from core.orquestrador_inteligente import OrquestradorInteligente, ContextoExecucao
from datetime import datetime


def teste_contexto_execucao():
    """Testa a classe ContextoExecucao"""
    logger = obter_logger('TesteContexto')
    logger.info("🧪 Testando ContextoExecucao...")
    
    contexto = ContextoExecucao(
        alvo_original="example.com",
        timestamp_inicio=datetime.now().isoformat()
    )
    
    # Testar adição de dados
    contexto.ips_descobertos = ["192.168.1.100", "192.168.1.101"]
    contexto.portas_abertas = {
        "192.168.1.100": [22, 80, 443],
        "192.168.1.101": [80, 8080]
    }
    contexto.modulos_executados = ["resolucao_dns", "scan_inicial"]
    
    logger.info(f"✓ Contexto criado com {len(contexto.ips_descobertos)} IPs")
    logger.info(f"✓ {sum(len(p) for p in contexto.portas_abertas.values())} portas abertas")
    return contexto


def teste_carregamento_modulos():
    """Testa carregamento dinâmico de módulos"""
    logger = obter_logger('TesteModulos')
    logger.info("🧪 Testando carregamento de módulos...")
    
    # Mock básico para teste
    class MockModulo:
        def resolver_dns(self, alvo):
            return {'sucesso': True, 'ips': ['192.168.1.100']}
        
        def varredura_completa(self, ip):
            return {'sucesso': True, 'dados': {'portas_abertas': [22, 80, 443]}}
        
        def _executar_consulta_gemini(self, prompt):
            return '{"acao": "parar", "justificativa": "teste mockado"}'
    
    mock = MockModulo()
    
    try:
        orquestrador = OrquestradorInteligente(
            resolver_dns=mock,
            scanner_portas=mock,
            scanner_nmap=mock,
            decisao_ia=mock
        )
        
        logger.info(f"✓ Orquestrador criado com {len(orquestrador.modulos_disponiveis)} módulos")
        logger.info(f"✓ Módulos disponíveis: {list(orquestrador.modulos_disponiveis.keys())[:5]}...")
        return orquestrador
        
    except Exception as e:
        logger.error(f"✗ Erro no carregamento: {str(e)}")
        return None


def teste_decisao_fallback():
    """Testa decisão de fallback baseada em regras"""
    logger = obter_logger('TesteFallback')
    logger.info("🧪 Testando decisão de fallback...")
    
    orquestrador = teste_carregamento_modulos()
    if not orquestrador:
        return False
    
    # Contexto com portas abertas
    contexto = ContextoExecucao(
        alvo_original="example.com",
        timestamp_inicio=datetime.now().isoformat()
    )
    contexto.ips_descobertos = ["192.168.1.100"]
    contexto.portas_abertas = {"192.168.1.100": [22, 80, 443, 8080]}
    contexto.modulos_executados = ["resolucao_dns", "scan_inicial"]
    
    # Testar decisão
    decisao = orquestrador._decisao_fallback_loop(contexto)
    
    logger.info(f"✓ Decisão: {decisao.get('acao', 'N/A')}")
    logger.info(f"✓ Justificativa: {decisao.get('justificativa', 'N/A')}")
    
    if decisao.get('acao') == 'executar_modulo':
        logger.info(f"✓ Módulo recomendado: {decisao.get('modulo', 'N/A')}")
    
    return True


def teste_integracao_basic():
    """Teste de integração básico"""
    logger = obter_logger('TesteIntegracao')
    logger.info("🧪 Testando integração básica...")
    
    try:
        # Tentar importar módulos reais
        from modulos.resolucao_dns import ResolucaoDNS
        from modulos.varredura_rustscan import VarreduraRustScan
        from modulos.varredura_nmap import VarreduraNmap
        from modulos.decisao_ia import DecisaoIA
        
        logger.info("✓ Imports dos módulos reais OK")
        
        # Criar instâncias
        resolver_dns = ResolucaoDNS()
        scanner_portas = VarreduraRustScan()
        scanner_nmap = VarreduraNmap()
        decisao_ia = DecisaoIA()
        
        logger.info("✓ Instâncias dos módulos criadas")
        
        # Criar orquestrador
        orquestrador = OrquestradorInteligente(
            resolver_dns, scanner_portas, scanner_nmap, decisao_ia
        )
        
        logger.info("✓ Orquestrador Inteligente criado com sucesso")
        logger.info(f"✓ {len(orquestrador.modulos_disponiveis)} módulos carregados")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Erro na integração: {str(e)}")
        return False


def teste_prompt_ia():
    """Testa geração de prompt para IA"""
    logger = obter_logger('TestePrompt')
    logger.info("🧪 Testando geração de prompt...")
    
    orquestrador = teste_carregamento_modulos()
    if not orquestrador:
        return False
    
    # Contexto simulado
    contexto = ContextoExecucao(
        alvo_original="example.com",
        timestamp_inicio=datetime.now().isoformat()
    )
    contexto.ips_descobertos = ["192.168.1.100"]
    contexto.portas_abertas = {"192.168.1.100": [22, 80, 443, 3306]}
    contexto.servicos_detectados = {
        "192.168.1.100": {
            80: {"servico": "http", "produto": "Apache", "versao": "2.4.41"},
            3306: {"servico": "mysql", "produto": "MySQL", "versao": "8.0.25"}
        }
    }
    contexto.vulnerabilidades_encontradas = [
        {"ip": "192.168.1.100", "tipo": "ssl-cert", "descricao": "Certificate expired"}
    ]
    contexto.modulos_executados = ["resolucao_dns", "scan_inicial", "nmap_varredura_completa"]
    contexto.pontuacao_risco = 45
    
    # Gerar prompt
    prompt = orquestrador._gerar_prompt_contexto_completo(contexto)
    
    logger.info("✓ Prompt gerado com sucesso")
    logger.info(f"✓ Tamanho do prompt: {len(prompt)} caracteres")
    
    # Verificar se contém informações essenciais
    assert "example.com" in prompt
    assert "192.168.1.100" in prompt
    assert "45/100" in prompt
    assert "mysql" in prompt.lower()
    
    logger.info("✓ Prompt contém todas as informações esperadas")
    return True


def executar_todos_os_testes():
    """Executa todos os testes"""
    logger = obter_logger('TesteSuite')
    logger.info("🚀 Iniciando suite de testes do Orquestrador Inteligente")
    
    testes = [
        ("Contexto de Execução", teste_contexto_execucao),
        ("Carregamento de Módulos", teste_carregamento_modulos),
        ("Decisão Fallback", teste_decisao_fallback),
        ("Geração de Prompt", teste_prompt_ia),
        ("Integração Básica", teste_integracao_basic),
    ]
    
    resultados = []
    
    for nome, funcao_teste in testes:
        try:
            logger.info(f"\n--- {nome} ---")
            resultado = funcao_teste()
            if resultado:
                logger.info(f"✅ {nome}: PASSOU")
                resultados.append(True)
            else:
                logger.error(f"❌ {nome}: FALHOU")
                resultados.append(False)
        except Exception as e:
            logger.error(f"💥 {nome}: ERRO - {str(e)}")
            resultados.append(False)
    
    # Resumo final
    sucessos = sum(resultados)
    total = len(resultados)
    
    logger.info(f"\n{'='*60}")
    logger.info(f"RESUMO DOS TESTES: {sucessos}/{total} PASSARAM")
    logger.info(f"{'='*60}")
    
    if sucessos == total:
        logger.info("🎉 TODOS OS TESTES PASSARAM! Sistema pronto para uso.")
        return True
    else:
        logger.error(f"⚠️ {total - sucessos} testes falharam. Revisar implementação.")
        return False


if __name__ == "__main__":
    # Configurar log para console
    log_manager.definir_console_verbose(True)
    
    # Executar testes
    sucesso = executar_todos_os_testes()
    
    if sucesso:
        print("\n✅ Sistema validado! Você pode executar:")
        print("python main.py --alvo <seu_alvo> --verbose")
    else:
        print("\n❌ Sistema com problemas. Verifique os logs acima.")
    
    sys.exit(0 if sucesso else 1)
