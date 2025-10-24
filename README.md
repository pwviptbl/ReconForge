## ⚙️ Como criar e usar o venv (Linux / macOS / Windows)

Para isolar dependências recomendamos usar um virtual environment (venv). A seguir estão instruções para criar, ativar e instalar dependências em diferentes sistemas.
### Linux / macOS (bash)

1. Crie o venv:
```
python3 -m venv .venv
```
2. Ative o venv:

```
source .venv/bin/activate
```
3. (Opcional) Instale dependências:

```
pip install --upgrade pip
pip install -r requirements.txt
```
Você também pode usar o script auxiliar:

```
chmod +x scripts/create_venv.sh
./scripts/create_venv.sh --install
```
### Windows (PowerShell)

1. Crie o venv:
```
python -m venv .venv
```
2. Ative no PowerShell (pode precisar ajustar a execução de scripts):

```
.\.venv\Scripts\Activate.ps1
```
3. Instale dependências:

```
.venv\Scripts\pip.exe install --upgrade pip
.venv\Scripts\pip.exe install -r requirements.txt
```
Script auxiliar para PowerShell:

```
./scripts/create_venv.ps1 -Install
```
### Windows (cmd.exe)

Ative com:
```
.venv\Scripts\activate.bat
```
### Dicas e observações

- Use Python 3.8+ quando possível.
- Se estiver com problema de permissão ao executar scripts no PowerShell, execute: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` (considere as políticas de segurança do seu ambiente).
- Para sair do venv (qualquer plataforma): `deactivate`.
- Os scripts auxiliares adicionados ficam em `scripts/create_venv.sh` e `scripts/create_venv.ps1`.

```
# VarreduraIA - Sistema Simplificado

Este é o **VarreduraIA** reimplementado de forma simplificada, focando na arquitetura de plugins desacoplados e loop de decisão por IA.

## 🏗️ Arquitetura

O sistema foi redesenhado com uma arquitetura limpa e modular:

### Componentes Principais

1. **Orquestrador (`orchestrator.py`)**: Coordena todo o processo
2. **Agente de IA (`ai_agent.py`)**: Toma decisões sobre próximos passos
3. **Gerenciador de Plugins (`plugin_manager.py`)**: Carrega e executa plugins
4. **Plugins**: Módulos independentes para diferentes tipos de varredura

### Fluxo de Execução

```
Início → DNS Resolution → Loop de IA → Plugins Dinâmicos → Relatório Final
                         ↓
                   IA decide próximo plugin
                         ↓
                   Executa plugin escolhido
                         ↓
                   Atualiza contexto
                         ↓
                   Verifica critérios de parada
                         ↓
                   Continua ou Para
```

## 🔌 Sistema de Plugins

Os plugins são completamente desacoplados e seguem uma interface padrão:

### Tipos de Plugin Disponíveis

- **NetworkPlugin**: Varreduras de rede (portas, DNS)
- **WebPlugin**: Análise de aplicações web
- **VulnerabilityPlugin**: Detecção de vulnerabilidades

### Plugins Incluídos

1. **DNSResolverPlugin**: Resolução de DNS e descoberta de subdomínios
2. **PortScannerPlugin**: Scanner de portas TCP eficiente
3. **WebScannerPlugin**: Análise básica de aplicações web
4. **TechnologyDetectorPlugin**: Detecção de tecnologias web
5. **WebVulnScannerPlugin**: Detecção de vulnerabilidades web comuns

### Criando Novos Plugins

```python
from core.plugin_base import BasePlugin, PluginResult

class MeuPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.description = "Descrição do meu plugin"
        self.category = "network"  # ou "web", "vulnerability"
    
    def execute(self, target: str, context: dict, **kwargs) -> PluginResult:
        # Sua lógica aqui
        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=0.0,
            data={'descobertas': 'aqui'}
        )
```

## 🤖 Sistema de IA

### Integração com Gemini

O sistema usa Google Gemini para tomar decisões inteligentes sobre:

- Qual plugin executar a seguir
- Quando parar a varredura
- Priorização baseada nas descobertas

### Configuração da IA

```yaml
ai:
  gemini:
    enabled: true
    api_key: "sua_chave_api_aqui"
    model: "gemini-2.0-flash-exp"
    timeout: 30
```

### Fallback Inteligente

Se a IA não estiver disponível, o sistema usa lógica de fallback baseada em regras.

## 📊 Relatórios

O sistema gera relatórios detalhados em JSON com:

- Metadados da execução
- Descobertas por categoria
- Vulnerabilidades encontradas
- Resultados detalhados de cada plugin
- Estatísticas de execução

## ⚙️ Configuração

### Arquivo de Configuração (`config/default.yaml`)

```yaml
# IA
ai:
  gemini:
    api_key: "YOUR_GEMINI_API_KEY_HERE"
    
# Plugins
plugins:
  default_timeout: 300
  max_parallel: 3

# Loop de execução
loop:
  max_iterations: 20
  auto_stop:
    no_progress_limit: 3
    critical_vuln_limit: 5
```

## 🚀 Como Usar

### Instalação de Dependências

```bash
pip install requests google-generativeai pyyaml
```

### Configuração

1. Edite `config/default.yaml`
2. Configure sua chave API do Gemini
3. Ajuste outros parâmetros conforme necessário

### Execução

```bash
# Varredura automática
python main.py --target google.com

# Varredura de rede
python main.py --target 192.168.1.0/24 --mode network

# Varredura web
python main.py --target https://example.com --mode web

# Com mais iterações
python main.py --target example.com --max-iterations 30 --verbose
```

### Exemplos de Uso

```bash
# Scan básico de um domínio
python main.py --target example.com

# Scan de uma rede local
python main.py --target 192.168.1.0/24 --mode network

# Análise web detalhada
python main.py --target https://app.example.com --mode web --verbose

# Scan com limite customizado
python main.py --target target.com --max-iterations 15
```

## 📁 Estrutura do Projeto

```
nova/
├── main.py                 # Ponto de entrada
├── core/                   # Núcleo do sistema
│   ├── orchestrator.py     # Orquestrador principal
│   ├── ai_agent.py         # Agente de IA
│   ├── plugin_manager.py   # Gerenciador de plugins
│   ├── plugin_base.py      # Classes base para plugins
│   └── config.py           # Sistema de configuração
├── plugins/                # Plugins do sistema
│   ├── dns_resolver.py     # Resolução DNS
│   ├── port_scanner.py     # Scanner de portas
│   ├── web_scanner.py      # Scanner web básico
│   ├── technology_detector.py # Detecção de tecnologias
│   └── web_vuln_scanner.py # Scanner de vulnerabilidades web
├── config/
│   └── default.yaml        # Configuração padrão
├── utils/
│   └── logger.py           # Sistema de logging
└── data/                   # Diretório para resultados
```

## 🎯 Vantagens da Nova Arquitetura

1. **Simplicidade**: Código muito mais limpo e fácil de entender
2. **Modularidade**: Plugins completamente desacoplados
3. **Extensibilidade**: Fácil adicionar novos plugins
4. **IA Centralizada**: Decisões consistentes e inteligentes
5. **Configurabilidade**: Sistema flexível de configuração
6. **Manutenibilidade**: Arquitetura clara e bem definida

## 🛠️ Adicionando Novos Plugins

1. Crie um arquivo `.py` na pasta `plugins/`
2. Herde de `BasePlugin`, `NetworkPlugin`, `WebPlugin` ou `VulnerabilityPlugin`
3. Implemente o método `execute()`
4. O plugin será carregado automaticamente na próxima execução

## 🔒 Segurança

- Headers de User-Agent realistas
- Timeouts apropriados
- Verificação SSL opcional
- Rate limiting automático
- Logs detalhados para auditoria

## 📈 Melhorias Futuras

- [ ] Interface web para monitoramento
- [ ] Suporte a mais tipos de varredura
- [ ] Integração com outras APIs de IA
- [ ] Sistema de templates para relatórios
- [ ] Cache inteligente de resultados
- [ ] Métricas e dashboards

## 🤝 Contribuindo

Para adicionar um novo plugin:

1. Copie um plugin existente como template
2. Modifique a lógica de execução
3. Teste com `python main.py --target seu_teste`
4. O sistema carregará automaticamente o novo plugin

---

**VarreduraIA** - Sistema de Pentest Inteligente e Modular
