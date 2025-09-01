# 🧪 Hosts de Teste para VarreduraIA

## ⚠️ AVISO IMPORTANTE
**Sempre teste apenas em ambientes autorizados!**
Nunca execute testes em sistemas reais sem permissão explícita.

## 🌐 Hosts de Teste Seguros

### 1. **testphp.vulnweb.com** (Recomendado para início)
- Site público com vulnerabilidades conhecidas
- Seguro para testes de aprendizado
- Contém: XSS, SQL Injection, LFI, etc.

### 2. **dvwa.co.uk** (Damn Vulnerable Web Application)
- Aplicação web vulnerável intencionalmente
- Baixe e instale localmente para controle total
- Excelente para aprendizado de pentest

### 3. **juice-shop.herokuapp.com** (OWASP Juice Shop)
- Aplicação moderna com vulnerabilidades
- Hospedada na nuvem, segura para teste
- Baseada em OWASP Top 10

### 4. **hackazon.webscantest.com**
- Loja online vulnerável
- Boa para testes de e-commerce
- Várias vulnerabilidades web

### 5. **zero.webappsecurity.com**
- Aplicação bancária vulnerável
- Simula ambiente financeiro
- Ótima para testes de segurança

## 🚀 Como Testar

### Teste Básico (Web Scan):
```bash
python3 main.py --alvo http://testphp.vulnweb.com/ --web-scan
```

### Teste com Autenticação:
```bash
python3 main.py --alvo http://testphp.vulnweb.com/ --web-scan --usuario test  --senha test 
```

### Teste Completo com IA:
```bash
python3 main.py --alvo http://localhost:8080/e-cidade/login.php --web-gemini --web-scan --usuario dbseller  --senha '' 
```

## 📋 Verificação Prévia

Antes de testar, verifique se:
- ✅ Gemini API está configurada
- ✅ Todos os módulos estão instalados
- ✅ Você tem permissão para testar o alvo
- ✅ O alvo está acessível

## 🔧 Configuração de Teste Local

Para testes mais controlados, considere:
1. Instalar DVWA localmente
2. Usar Docker com aplicações vulneráveis
3. Configurar VM com Metasploitable
4. Usar containers OWASP com vulnerabilidades conhecidas
