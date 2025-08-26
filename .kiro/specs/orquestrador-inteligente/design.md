# Design Document - Orquestrador Inteligente de Varreduras

## Overview

O Orquestrador Inteligente é um sistema que coordena automaticamente múltiplos módulos de varredura baseado em decisões da IA Gemini. O sistema mantém um contexto persistente de toda a operação, consulta a IA a cada etapa para determinar próximos passos, e gera relatórios consolidados integrando todos os resultados.

## Architecture

### Componentes Principais

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI/Interface │────│   Orquestrador   │────│  Contexto de    │
│                 │    │   Principal      │    │  Varredura      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Analisador IA  │────│  Gerenciador de  │────│   Módulos de    │
│   (Gemini)      │    │    Módulos       │    │   Varredura     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  Sistema de      │
                       │  Relatórios      │
                       └──────────────────┘
```

### Fluxo de Execução

1. **Inicialização**: Criar contexto de varredura
2. **Descoberta Inicial**: RustScan + Nmap básico
3. **Loop Principal**: IA decide → Executa módulos → Atualiza contexto → Repete
4. **Finalização**: Gera relatório consolidado

## Components and Interfaces

### 1. Contexto de Varredura (VarreduraContext)

Estrutura central que mantém todo o estado da operação:

```python
class VarreduraContext:
    def __init__(self, alvo: str):
        self.id_sessao = uuid.uuid4()
        self.alvo_original = alvo
        self.ip_resolvido = None
        self.timestamp_inicio = datetime.now()
        self.timestamp_fim = None
        self.status = "iniciando"  # iniciando, em_progresso, concluido, erro
        
        # Fases e progresso
        self.fases_completadas = []
        self.fase_atual = None
        self.progresso_percentual = 0
        
        # Resultados por módulo
        self.resultados = {
            "rustscan": None,
            "nmap": None,
            "nuclei": None,
            "nikto": None,
            "feroxbuster": None,
            "whatweb": None,
            "subfinder": None,
            "sublist3r": None,
            "sqlmap": None,
            "searchsploit": None,
            "zap": None
        }
        
        # Decisões da IA
        self.decisoes_ia = []
        self.proximos_passos = []
        
        # Configurações
        self.configuracao = {
            "modo_agressividade": "alto",  # baixo, medio, alto
            "timeout_modulo": 300,
            "modo_stealth": False,
            "modulos_excluidos": [],
            "profundidade_maxima": 3
        }
        
        # Métricas
        self.metricas = {
            "tempo_total": 0,
            "modulos_executados": 0,
            "vulnerabilidades_encontradas": 0,
            "servicos_descobertos": 0,
            "hosts_descobertos": 0
        }
```

### 2. Gerenciador de Módulos (GerenciadorModulos)

Responsável por executar e coordenar todos os módulos:

```python
class GerenciadorModulos:
    def __init__(self):
        self.modulos_disponiveis = {
            "rustscan": VarreduraRustScan(),
            "nmap": VarreduraNmap(),
            "nuclei": VarreduraNuclei(),
            "nikto": VarreduraNikto(),
            "feroxbuster": VarreduraFeroxbuster(),
            "whatweb": VarreduraWhatWeb(),
            "subfinder": VarreduraSubfinder(),
            "sublist3r": VarreduraSublist3r(),
            "sqlmap": VarreduraSQLMap(),
            "searchsploit": VarreduraSearchSploit(),
            "zap": VarreduraZAP()
        }
        
    def verificar_disponibilidade(self) -> Dict[str, bool]:
        """Verifica quais módulos estão instalados e funcionais"""
        
    def executar_modulo(self, nome_modulo: str, contexto: VarreduraContext, 
                       parametros: Dict) -> Dict[str, Any]:
        """Executa um módulo específico com os parâmetros fornecidos"""
        
    def obter_capacidades_modulo(self, nome_modulo: str) -> Dict[str, Any]:
        """Retorna informações sobre o que cada módulo pode fazer"""
```

### 3. Analisador de Decisões IA (DecisionAnalyzer)

Extensão do AnalisadorGemini para decisões de orquestração:

```python
class DecisionAnalyzer(AnalisadorGemini):
    def __init__(self):
        super().__init__()
        self.template_decisao = """
        Baseado no contexto atual da varredura, determine os próximos passos:
        
        CONTEXTO ATUAL:
        {contexto_formatado}
        
        MÓDULOS DISPONÍVEIS:
        {modulos_disponiveis}
        
        RESULTADOS ANTERIORES:
        {resultados_resumidos}
        
        Responda em JSON com:
        {{
            "proximos_modulos": ["modulo1", "modulo2"],
            "parametros": {{"modulo1": {{"param": "valor"}}}},
            "justificativa": "Explicação da decisão",
            "prioridade": "alta|media|baixa",
            "continuar_apos": true|false
        }}
        """
        
    def decidir_proximos_passos(self, contexto: VarreduraContext) -> Dict[str, Any]:
        """Consulta a IA para determinar próximos módulos a executar"""
        
    def avaliar_completude(self, contexto: VarreduraContext) -> bool:
        """Determina se a varredura está completa"""
```

## Data Models

### Estrutura de Armazenamento de Resultados

Cada módulo salva seus resultados em formato padronizado:

```json
{
  "modulo": "nmap",
  "timestamp_inicio": "2024-01-20T10:30:00",
  "timestamp_fim": "2024-01-20T10:35:00",
  "sucesso": true,
  "comando_executado": "nmap -sS -sV target.com",
  "dados_brutos": "...",
  "dados_processados": {
    "hosts": [...],
    "portas_abertas": [...],
    "servicos": [...],
    "vulnerabilidades": [...]
  },
  "metricas": {
    "tempo_execucao": 300,
    "hosts_encontrados": 1,
    "portas_descobertas": 5
  },
  "erro": null
}
```

### Estrutura de Decisões da IA

```json
{
  "timestamp": "2024-01-20T10:35:00",
  "fase": "descoberta_web",
  "contexto_analisado": {
    "servicos_web_detectados": ["http", "https"],
    "portas_abertas": [80, 443, 8080],
    "tecnologias_identificadas": []
  },
  "decisao": {
    "proximos_modulos": ["whatweb", "feroxbuster", "nikto"],
    "parametros": {
      "whatweb": {"agressividade": 3},
      "feroxbuster": {"wordlist": "common.txt", "extensoes": ["php", "html"]},
      "nikto": {"tuning": "1,2,3"}
    },
    "justificativa": "Serviços web detectados nas portas 80 e 443. Necessário identificar tecnologias e buscar diretórios/vulnerabilidades web.",
    "prioridade": "alta",
    "continuar_apos": true
  },
  "resultado_execucao": {
    "modulos_executados": ["whatweb", "feroxbuster"],
    "modulos_falharam": ["nikto"],
    "tempo_total": 450
  }
}
```

### Mapeamento de Capacidades dos Módulos

```python
CAPACIDADES_MODULOS = {
    "rustscan": {
        "tipo": "descoberta_portas",
        "velocidade": "muito_rapida",
        "uso_recomendado": "descoberta_inicial",
        "saidas": ["portas_abertas", "servicos_basicos"],
        "triggers": ["sempre"]
    },
    "nmap": {
        "tipo": "descoberta_servicos",
        "velocidade": "media",
        "uso_recomendado": "identificacao_servicos",
        "saidas": ["servicos_detalhados", "versoes", "os", "scripts_nse"],
        "triggers": ["portas_descobertas"]
    },
    "whatweb": {
        "tipo": "identificacao_web",
        "velocidade": "rapida",
        "uso_recomendado": "identificar_tecnologias_web",
        "saidas": ["tecnologias", "frameworks", "cms"],
        "triggers": ["servicos_web_detectados"]
    },
    "feroxbuster": {
        "tipo": "descoberta_diretorios",
        "velocidade": "media",
        "uso_recomendado": "enumerar_diretorios_web",
        "saidas": ["diretorios", "arquivos", "endpoints"],
        "triggers": ["servicos_web_detectados"]
    },
    "nikto": {
        "tipo": "vulnerabilidades_web",
        "velocidade": "lenta",
        "uso_recomendado": "buscar_vulnerabilidades_web",
        "saidas": ["vulnerabilidades", "configuracoes_incorretas"],
        "triggers": ["servicos_web_detectados"]
    },
    "nuclei": {
        "tipo": "vulnerabilidades_gerais",
        "velocidade": "media",
        "uso_recomendado": "buscar_vulnerabilidades_conhecidas",
        "saidas": ["cves", "vulnerabilidades", "exposicoes"],
        "triggers": ["servicos_identificados", "tecnologias_identificadas"]
    },
    "subfinder": {
        "tipo": "enumeracao_subdominios",
        "velocidade": "rapida",
        "uso_recomendado": "descobrir_subdominios",
        "saidas": ["subdominios"],
        "triggers": ["alvo_eh_dominio"]
    },
    "sublist3r": {
        "tipo": "enumeracao_subdominios",
        "velocidade": "media",
        "uso_recomendado": "descobrir_subdominios_bruteforce",
        "saidas": ["subdominios"],
        "triggers": ["alvo_eh_dominio", "poucos_subdominios_encontrados"]
    },
    "sqlmap": {
        "tipo": "teste_sql_injection",
        "velocidade": "lenta",
        "uso_recomendado": "testar_sql_injection",
        "saidas": ["vulnerabilidades_sql", "dados_extraidos"],
        "triggers": ["formularios_detectados", "parametros_url_detectados"]
    },
    "searchsploit": {
        "tipo": "busca_exploits",
        "velocidade": "rapida",
        "uso_recomendado": "buscar_exploits_conhecidos",
        "saidas": ["exploits_disponiveis"],
        "triggers": ["servicos_com_versao", "vulnerabilidades_encontradas"]
    },
    "zap": {
        "tipo": "proxy_interceptacao",
        "velocidade": "lenta",
        "uso_recomendado": "varredura_web_completa",
        "saidas": ["vulnerabilidades_web", "spider_results"],
        "triggers": ["aplicacoes_web_complexas"]
    }
}
```

## Error Handling

### Estratégias de Recuperação

1. **Falha de Módulo Individual**:
   - Registrar erro no contexto
   - Continuar com próximos módulos
   - Sugerir alternativas via IA

2. **Falha de Conexão IA**:
   - Usar regras de fallback pré-definidas
   - Continuar com módulos básicos
   - Tentar reconectar periodicamente

3. **Recursos Insuficientes**:
   - Ajustar paralelismo automaticamente
   - Priorizar módulos mais importantes
   - Pausar execução se necessário

4. **Interrupção do Usuário**:
   - Salvar estado atual
   - Permitir retomada posterior
   - Gerar relatório parcial

## Testing Strategy

### Testes Unitários
- Testar cada componente isoladamente
- Mock das dependências externas
- Validar estruturas de dados

### Testes de Integração
- Testar fluxo completo com alvos controlados
- Validar integração entre módulos
- Testar cenários de falha

### Testes de Performance
- Medir tempo de execução por módulo
- Testar com múltiplos alvos
- Validar uso de recursos

### Testes de IA
- Validar qualidade das decisões
- Testar com diferentes cenários
- Comparar com decisões manuais de especialistas

## Prompt Templates para IA

### Template Principal de Decisão

```
Você é um especialista em pentesting que coordena ferramentas de varredura automaticamente.

CONTEXTO ATUAL:
- Alvo: {alvo}
- Fase: {fase_atual}
- Tempo decorrido: {tempo_decorrido}
- Módulos já executados: {modulos_executados}

RESULTADOS ANTERIORES:
{resumo_resultados}

MÓDULOS DISPONÍVEIS:
{lista_modulos_com_capacidades}

REGRAS:
1. Priorize eficiência - não execute módulos redundantes
2. Considere o contexto - adapte baseado nos achados
3. Mantenha foco no objetivo - descobrir vulnerabilidades
4. Respeite limitações de tempo e recursos

RESPONDA EM JSON:
{
  "proximos_modulos": ["modulo1", "modulo2"],
  "parametros": {
    "modulo1": {"param": "valor"}
  },
  "justificativa": "Por que estes módulos foram escolhidos",
  "prioridade": "alta|media|baixa",
  "continuar_apos": true|false,
  "tempo_estimado": 300
}
```

### Template de Avaliação de Completude

```
Avalie se a varredura está completa baseado nos resultados obtidos:

OBJETIVOS INICIAIS:
- Descobrir todos os serviços expostos
- Identificar vulnerabilidades conhecidas
- Mapear superfície de ataque
- Encontrar vetores de entrada

RESULTADOS OBTIDOS:
{resumo_completo_resultados}

MÓDULOS EXECUTADOS:
{lista_modulos_executados}

TEMPO DECORRIDO: {tempo_total}

RESPONDA EM JSON:
{
  "varredura_completa": true|false,
  "cobertura_percentual": 85,
  "areas_faltantes": ["enumeracao_smb", "teste_ssl"],
  "recomendacoes_finais": ["Testar manualmente formulário de login"],
  "nivel_confianca": "alto|medio|baixo"
}
```

Este design fornece uma base sólida para implementar o orquestrador inteligente, mantendo flexibilidade e extensibilidade enquanto aproveita todos os módulos existentes.