#!/usr/bin/env python3
"""
Demonstração prática da anonimização de IPs
Simula um fluxo completo de pentest com segurança
"""

import json
from datetime import datetime

# Simular importações (sem executar código real)
print("🚀 DEMONSTRAÇÃO: VarreduraIA com Anonimização de IPs")
print("=" * 60)

# 1. Dados reais coletados pelo sistema
dados_reais = {
    "timestamp": datetime.now().isoformat(),
    "alvo_original": "empresa.com.br",
    "ips_descobertos": [
        "192.168.10.100",  # Servidor interno
        "192.168.10.101",  # Workstation
        "203.45.67.89"     # IP público da empresa
    ],
    "portas_abertas": {
        "192.168.10.100": [22, 80, 443, 3306],  # Servidor web + MySQL
        "192.168.10.101": [135, 139, 445],      # Windows SMB
        "203.45.67.89": [80, 443]               # Web server público
    },
    "servicos_detectados": {
        "192.168.10.100": {
            "22": {"servico": "ssh", "versao": "OpenSSH 8.2"},
            "3306": {"servico": "mysql", "versao": "MySQL 8.0.25"}
        }
    },
    "vulnerabilidades": [
        {
            "ip": "192.168.10.100",
            "porta": 3306,
            "tipo": "MySQL sem autenticação",
            "criticidade": "ALTA"
        }
    ],
    "credenciais_encontradas": {
        "ftp_user": "admin:password123",
        "mysql_config": "/etc/mysql/conf.d/sensitive.cnf"
    }
}

print("\n📊 PASSO 1: Dados coletados pelo sistema")
print("-" * 40)
print("• IPs descobertos:", len(dados_reais["ips_descobertos"]))
print("• Portas abertas:", sum(len(portas) for portas in dados_reais["portas_abertas"].values()))
print("• Vulnerabilidades:", len(dados_reais["vulnerabilidades"]))
print("• ⚠️ PROBLEMA: Dados contêm IPs reais e informações sensíveis!")

# 2. Aplicação da anonimização
print("\n🔒 PASSO 2: Aplicando anonimização para IA")
print("-" * 40)

# Simular a anonimização (sem importar módulos)
dados_para_ia = {
    "timestamp": dados_reais["timestamp"],
    "alvo_original": "[DOMINIO_ANONIMIZADO]",
    "ips_descobertos": [
        "192.168.200.15",  # IP privado fictício
        "192.168.200.16",  # IP privado fictício  
        "203.0.113.45"     # IP de teste RFC 5737
    ],
    "portas_abertas": {
        "192.168.200.15": [22, 80, 443, 3306],
        "192.168.200.16": [135, 139, 445],
        "203.0.113.45": [80, 443]
    },
    "servicos_detectados": {
        "192.168.200.15": {
            "22": {"servico": "ssh", "versao": "OpenSSH 8.2"},
            "3306": {"servico": "mysql", "versao": "MySQL 8.0.25"}
        }
    },
    "vulnerabilidades": [
        {
            "ip": "192.168.200.15",
            "porta": 3306,
            "tipo": "MySQL sem autenticação",
            "criticidade": "ALTA"
        }
    ],
    "credenciais_encontradas": "[REMOVIDO_POR_SEGURANÇA]",
    "_seguranca": {
        "ips_anonimizados": 3,
        "dados_sensiveis_removidos": 2,
        "tipos_protegidos": ["credenciais", "caminhos_arquivos"]
    }
}

print("✅ IPs anonimizados:")
mapeamento = {
    "192.168.10.100": "192.168.200.15",
    "192.168.10.101": "192.168.200.16", 
    "203.45.67.89": "203.0.113.45"
}

for real, anonimo in mapeamento.items():
    print(f"   {real} → {anonimo}")

print("✅ Dados sensíveis removidos:")
print("   • Credenciais FTP mascaradas")
print("   • Caminhos de arquivos removidos")
print("   • Domínio real anonimizado")

# 3. Contexto enviado para IA
print("\n🧠 PASSO 3: Contexto enviado para Gemini AI")
print("-" * 40)

prompt_para_ia = f"""
Analise os seguintes resultados de varredura e decida os próximos passos:

ALVOS DESCOBERTOS: {len(dados_para_ia['ips_descobertos'])} hosts
- Host 1: {dados_para_ia['ips_descobertos'][0]} (4 portas abertas, MySQL vulnerável)
- Host 2: {dados_para_ia['ips_descobertos'][1]} (3 portas abertas, serviços Windows)
- Host 3: {dados_para_ia['ips_descobertos'][2]} (2 portas abertas, servidor web)

VULNERABILIDADES CRÍTICAS:
- MySQL sem autenticação no host principal
- Serviços SMB expostos

Com base nesta análise, recomende os próximos módulos a executar.
Responda em JSON com os próximos passos.
"""

print("📤 Prompt enviado (anonimizado):")
print(prompt_para_ia[:300] + "...")
print("\n✅ SEGURO: Nenhum IP real ou dado sensível foi enviado para IA externa!")

# 4. Resposta da IA (simulada)
print("\n🤖 PASSO 4: Resposta simulada da IA")
print("-" * 40)

resposta_ia_simulada = {
    "acao": "executar_modulo",
    "modulo": "nmap_varredura_vulnerabilidades", 
    "alvos": ["use_alvos_descobertos"],  # Comando especial
    "justificativa": "MySQL vulnerável detectado, necessária varredura aprofundada",
    "prioridade": "alta",
    "expectativa": "Identificar exploits específicos para MySQL e SMB"
}

print("🧠 IA decidiu:")
print(f"   • Ação: {resposta_ia_simulada['acao']}")
print(f"   • Módulo: {resposta_ia_simulada['modulo']}")
print(f"   • Alvos: {resposta_ia_simulada['alvos']}")
print(f"   • Justificativa: {resposta_ia_simulada['justificativa']}")

# 5. Execução com IPs reais
print("\n⚡ PASSO 5: Execução local com IPs reais")
print("-" * 40)

print("🔄 Sistema resolve alvos para execução:")
alvos_reais_para_execucao = dados_reais["ips_descobertos"]

for i, ip_real in enumerate(alvos_reais_para_execucao):
    print(f"   • Alvo {i+1}: {ip_real}")

print(f"\n🚀 Executando '{resposta_ia_simulada['modulo']}' nos alvos reais...")
print("   [SIMULADO] nmap -sV --script vuln 192.168.10.100")
print("   [SIMULADO] nmap -sV --script vuln 192.168.10.101") 
print("   [SIMULADO] nmap -sV --script vuln 203.45.67.89")

print("\n✅ Comandos executados com IPs reais, mas IA nunca soube dos IPs verdadeiros!")

# 6. Resumo de segurança
print("\n🔐 RESUMO DE SEGURANÇA")
print("=" * 60)

print("✅ PROTEÇÕES APLICADAS:")
print("   • 3 IPs anonimizados antes do envio para IA")
print("   • 2 tipos de dados sensíveis removidos")
print("   • Estrutura de rede preservada para análise")
print("   • Funcionalidade completa mantida")

print("\n✅ BENEFÍCIOS ALCANÇADOS:")
print("   🛡️ Privacidade: IPs internos protegidos")
print("   🧠 Inteligência: IA tomou decisões eficazes")
print("   ⚡ Performance: Zero impacto na velocidade")
print("   📊 Transparência: Processo auditável")

print("\n✅ CONFORMIDADE:")
print("   • LGPD: Dados pessoais protegidos")
print("   • ISO 27001: Controles de segurança aplicados")
print("   • NIST: Função 'Protect' implementada")
print("   • Políticas corporativas: IPs não vazaram")

print("\n🎯 RESULTADO FINAL:")
print("   O sistema conseguiu obter análise inteligente da IA")
print("   SEM comprometer a segurança dos dados sensíveis!")

print("\n" + "=" * 60)
print("💡 Esta é a demonstração de como a anonimização")
print("   preserva segurança SEM sacrificar funcionalidade!")
print("=" * 60)
