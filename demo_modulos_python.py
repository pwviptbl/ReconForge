#!/usr/bin/env python3
"""
Script de Demonstração dos Novos Módulos Python Puro
Testa cada módulo criado para reduzir dependências externas
"""

import time
from datetime import datetime

def testar_scanner_portas():
    """Testa o scanner de portas Python puro"""
    print("\n🔍 Testando Scanner de Portas Python Puro")
    print("=" * 50)

    try:
        from modulos.scanner_portas_python import ScannerPortasPython
        scanner = ScannerPortasPython()

        # Teste com scan rápido
        alvo = "scanme.nmap.org"
        print(f"🎯 Testando scan rápido em: {alvo}")

        inicio = time.time()
        resultado = scanner.scan_rapido(alvo)
        duracao = time.time() - inicio

        if 'erro' not in resultado:
            portas_abertas = [p for p, status in resultado.get('resultados', {}).items() if status == 'aberta']
            print(f"✅ Scan concluído em {duracao:.2f}s")
            print(f"📊 Portas abertas encontradas: {len(portas_abertas)}")
            if portas_abertas:
                print(f"🔓 Portas: {', '.join(map(str, portas_abertas[:10]))}")
        else:
            print(f"❌ Erro: {resultado['erro']}")

    except Exception as e:
        print(f"❌ Erro ao testar scanner de portas: {e}")

def testar_detector_tecnologias():
    """Testa o detector de tecnologias Python puro"""
    print("\n🔍 Testando Detector de Tecnologias Python Puro")
    print("=" * 50)

    try:
        from modulos.detector_tecnologias_python import DetectorTecnologiasPython
        detector = DetectorTecnologiasPython()

        # Teste com site conhecido
        url = "https://httpbin.org"
        print(f"🎯 Testando detecção em: {url}")

        inicio = time.time()
        resultado = detector.detectar_tecnologias_rapido(url)
        duracao = time.time() - inicio

        if 'erro' not in resultado:
            tecnologias = resultado.get('tecnologias_detectadas', {})
            print(f"✅ Detecção concluída em {duracao:.2f}s")
            print(f"📊 Tecnologias detectadas: {len(tecnologias)}")

            for categoria, techs in tecnologias.items():
                if techs:
                    print(f"🔧 {categoria}: {', '.join(techs[:3])}")
        else:
            print(f"❌ Erro: {resultado['erro']}")

    except Exception as e:
        print(f"❌ Erro ao testar detector de tecnologias: {e}")

def testar_scanner_diretorios():
    """Testa o scanner de diretórios Python puro"""
    print("\n🔍 Testando Scanner de Diretórios Python Puro")
    print("=" * 50)

    try:
        from modulos.scanner_diretorios_python import ScannerDiretoriosPython
        scanner = ScannerDiretoriosPython()

        # Teste com site de teste
        url = "https://httpbin.org"
        print(f"🎯 Testando scan de diretórios em: {url}")

        inicio = time.time()
        resultado = scanner.scan_completo(url, testar_extensoes=False)
        duracao = time.time() - inicio

        if 'erro' not in resultado:
            urls_encontradas = resultado.get('urls_encontradas', [])
            print(f"✅ Scan concluído em {duracao:.2f}s")
            print(f"📊 URLs encontradas: {len(urls_encontradas)}")

            for url_info in urls_encontradas[:5]:
                status_emoji = "✅" if url_info['status_code'] == 200 else "⚠️"
                print(f"  {status_emoji} {url_info['status_code']} - {url_info['caminho']}")
        else:
            print(f"❌ Erro: {resultado['erro']}")

    except Exception as e:
        print(f"❌ Erro ao testar scanner de diretórios: {e}")

def testar_buscador_exploits():
    """Testa o buscador de exploits Python puro"""
    print("\n🔍 Testando Buscador de Exploits Python Puro")
    print("=" * 50)

    try:
        from modulos.buscador_exploits_python import BuscadorExploitsPython
        buscador = BuscadorExploitsPython()

        # Teste com termo genérico
        termo = "apache"
        print(f"🎯 Testando busca de exploits para: {termo}")

        inicio = time.time()
        resultado = buscador.buscar_exploits(termo, fontes=['exploit_db'])
        duracao = time.time() - inicio

        if 'erro' not in resultado:
            exploits = resultado.get('exploits_encontrados', [])
            print(f"✅ Busca concluída em {duracao:.2f}s")
            print(f"📊 Exploits encontrados: {len(exploits)}")

            for exploit in exploits[:3]:
                severidade_emoji = "🔴" if exploit.get('severidade') == 'alta' else "🟡" if exploit.get('severidade') == 'media' else "🟢"
                print(f"  {severidade_emoji} {exploit['titulo'][:50]}...")
                if exploit.get('cve'):
                    print(f"    CVE: {exploit['cve']}")
        else:
            print(f"❌ Erro: {resultado['erro']}")

    except Exception as e:
        print(f"❌ Erro ao testar buscador de exploits: {e}")

def testar_analisador_vulnerabilidades():
    """Testa o analisador de vulnerabilidades web Python puro"""
    print("\n🔍 Testando Analisador de Vulnerabilidades Web Python Puro")
    print("=" * 50)

    try:
        from modulos.analisador_vulnerabilidades_web import AnalisadorVulnerabilidadesWeb
        analisador = AnalisadorVulnerabilidadesWeb()

        # Teste com análise básica
        url = "https://httpbin.org"
        print(f"🎯 Testando análise de vulnerabilidades em: {url}")

        inicio = time.time()
        resultado = analisador.analisar_url(url, testes_completos=False, testar_payloads=False)
        duracao = time.time() - inicio

        if 'erro' not in resultado:
            vulnerabilidades = resultado.get('vulnerabilidades', [])
            headers_seguranca = resultado.get('headers_seguranca', {})

            print(f"✅ Análise concluída em {duracao:.2f}s")
            print(f"📊 Vulnerabilidades encontradas: {len(vulnerabilidades)}")
            print(f"🛡️ Headers de segurança verificados: {len(headers_seguranca)}")

            # Mostrar status dos headers de segurança
            for header, info in headers_seguranca.items():
                if info['criticidade'] in ['alta', 'media']:
                    status_emoji = "✅" if info['status'] == 'presente' else "❌"
                    print(f"  {status_emoji} {header}: {info['status']}")

            if vulnerabilidades:
                print("\\n🚨 Vulnerabilidades encontradas:")
                for vuln in vulnerabilidades[:3]:
                    sev_emoji = "🔴" if vuln['severidade'] == 'alta' else "🟡" if vuln['severidade'] == 'media' else "🟢"
                    print(f"  {sev_emoji} {vuln['tipo']} ({vuln['severidade']})")
        else:
            print(f"❌ Erro: {resultado['erro']}")

    except Exception as e:
        print(f"❌ Erro ao testar analisador de vulnerabilidades: {e}")

def main():
    """Função principal de demonstração"""
    print("🚀 Demonstração dos Novos Módulos Python Puro")
    print("=" * 60)
    print(f"📅 Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\\nEstes módulos substituem ferramentas externas mantendo")
    print("funcionalidades similares usando apenas Python puro + requests")
    print("=" * 60)

    # Executar testes
    testar_scanner_portas()
    testar_detector_tecnologias()
    testar_scanner_diretorios()
    testar_buscador_exploits()
    testar_analisador_vulnerabilidades()

    print("\\n" + "=" * 60)
    print("✅ Demonstração concluída!")
    print("\\n📋 Resumo dos módulos criados:")
    print("• Scanner de Portas Python (substitui Nmap/RustScan)")
    print("• Detector de Tecnologias Python (substitui WhatWeb)")
    print("• Scanner de Diretórios Python (substitui Feroxbuster/Dirbuster)")
    print("• Buscador de Exploits Python (substitui SearchSploit)")
    print("• Analisador de Vulnerabilidades Web (substitui Nikto/SQLMap)")
    print("\\nTodos os módulos estão integrados no orquestrador inteligente!")
    print("=" * 60)

if __name__ == "__main__":
    main()
