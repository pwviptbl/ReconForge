# 🔒 Segurança na Comunicação com IA - Anonimização de IPs

## 📋 Visão Geral

O VarreduraIA agora implementa **anonimização automática de IPs** antes de enviar qualquer contexto para a IA externa (Gemini). Esta medida garante que informações sensíveis como endereços IP reais não sejam expostos durante o processo de análise inteligente.

## 🔐 Como Funciona

### 1. **Anonimização Transparente**
- IPs reais são substituídos por IPs fictícios antes do envio para IA
- A estrutura e tipos de rede são preservados para manter contexto útil
- O sistema mantém mapeamento interno para funcionar corretamente

### 2. **Preservação de Contexto**
- **IPs Privados** (192.168.x.x, 10.x.x.x) → Mantidos como privados fictícios
- **IPs Públicos** → Substituídos por IPs de teste documentados (RFC 5737)
- **Estatísticas** → Mantidas integralmente (quantidade de portas, serviços, etc.)
- **Estrutura** → Preservada para análise eficaz da IA

### 3. **Remoção de Dados Sensíveis**
Além dos IPs, o sistema remove/mascara:
- Credenciais e senhas
- Caminhos completos de arquivos
- Tokens de autenticação
- Números seriais e MACs
- Nomes de usuário específicos

## ⚙️ Configuração

A anonimização é controlada via `config/default.yaml`:

```yaml
api:
  gemini:
    # Configurações de segurança para IA
    anonimizar_ips: true  # RECOMENDADO: anonimiza IPs antes de enviar para IA
    seed_anonimizacao: "varredura_ia_seed_v1"  # Seed para consistência
    contexto_seguro: true  # Remove outras informações sensíveis
```

## 🛡️ Benefícios de Segurança

### ✅ **Proteção de Privacidade**
- IPs internos da rede não são expostos para serviços externos
- Conformidade com políticas de segurança corporativa
- Redução de riscos de vazamento de informações

### ✅ **Funcionalidade Preservada**
- IA ainda pode analisar padrões de rede e recomendar ações
- Decisões inteligentes baseadas em tipos e estruturas de serviços
- Estatísticas e métricas mantidas integralmente

### ✅ **Transparência**
- Logs indicam claramente quando anonimização está ativa
- Contadores mostram quantos IPs foram protegidos
- Processo reversível internamente para execução de comandos

## 📊 Exemplo de Anonimização

### Dados Originais (NÃO enviados para IA):
```json
{
  "ips_descobertos": ["192.168.1.100", "10.0.0.1"],
  "portas_abertas": {
    "192.168.1.100": [22, 80, 443],
    "10.0.0.1": [80, 8080]
  }
}
```

### Dados Anonimizados (enviados para IA):
```json
{
  "ips_descobertos": ["192.168.196.231", "192.168.224.163"],
  "portas_abertas": {
    "192.168.196.231": [22, 80, 443],
    "192.168.224.163": [80, 8080]
  },
  "_aviso_anonimizacao": {
    "status": "IPs anonimizados por segurança",
    "total_anonimizado": 2
  }
}
```

## 🔧 Implementação Técnica

### Componentes Principais:

1. **`utils/anonimizador_ip.py`**
   - Classe `AnonimizadorIP` para mascaramento consistente
   - Funções utilitárias para contexto seguro

2. **`modulos/decisao_ia.py`**
   - Método `_preparar_contexto_seguro_para_ia()`
   - Integração transparente com análises existentes

3. **`core/orquestrador_inteligente.py`**
   - Contexto seguro no loop inteligente
   - Resolução de alvos para execução real

### Fluxo de Segurança:

1. **Coleta de Dados** → IPs reais coletados
2. **Anonimização** → IPs mascarados + limpeza de dados sensíveis  
3. **Envio para IA** → Contexto seguro transmitido
4. **Análise IA** → Decisões baseadas em dados anonimizados
5. **Execução Local** → Comandos aplicados aos IPs reais

## 🧪 Testes de Segurança

Execute o teste de segurança para verificar a proteção:

```bash
cd /home/dbseller/VarreduraIA
source venv/bin/activate
python teste_seguranca_ia.py
```

### Resultados Esperados:
- ✅ IPs reais não encontrados no contexto para IA
- ✅ Dados sensíveis removidos
- ✅ Estrutura e estatísticas preservadas
- ✅ Funcionalidade mantida

## ⚡ Desabilitação (Não Recomendado)

Para desabilitar a anonimização (apenas para ambientes de teste):

```yaml
api:
  gemini:
    anonimizar_ips: false  # ⚠️ CUIDADO: IPs reais serão enviados
```

## 🔍 Monitoramento

### Logs de Segurança:
```
🔒 3 IPs anonimizados para contexto IA
📋 Tipos de IP anonimizados: PRIVADO, PRIVADO, PÚBLICO
🧠 IA decidiu: executar_modulo
🔒 Contexto enviado com IPs anonimizados - privacidade preservada
```

### Métricas de Proteção:
- Número de IPs protegidos por sessão
- Tipos de dados sensíveis removidos
- Verificação de vazamentos de informação

## 📚 Referências de Segurança

- **RFC 5737** - IPv4 Address Blocks Reserved for Documentation
- **RFC 1918** - Address Allocation for Private Internets
- **NIST Cybersecurity Framework** - Protect Function
- **GDPR** - General Data Protection Regulation (aplicável a IPs pessoais)

---

## ✨ Resumo

A **anonimização de IPs** no VarreduraIA garante que:

1. 🛡️ **Privacidade protegida** - IPs reais nunca saem do ambiente local
2. 🧠 **IA funcional** - Análises inteligentes baseadas em estrutura preservada  
3. ⚡ **Performance mantida** - Zero impacto na velocidade de execução
4. 📊 **Transparência total** - Logs claros sobre proteções aplicadas

**Esta é uma implementação de segurança robusta que não compromete a funcionalidade do sistema.**
