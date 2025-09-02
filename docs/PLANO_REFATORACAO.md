# 🚀 Plano de Refatoração - VarreduraIA
## Transformação para Arquitetura Enterprise-Grade

### 📋 Visão Geral
Este documento detalha o plano de refatoração do projeto VarreduraIA, transformando-o de uma arquitetura monolítica em uma plataforma modular, extensível e observável. A implementação será dividida em 5 fases sequenciais.

### 🎯 Objetivos Gerais
- ✅ Melhorar testabilidade e manutenibilidade
- ✅ Implementar arquitetura modular e extensível
- ✅ Adicionar observabilidade e métricas
- ✅ Criar sistema de plugins
- ✅ Manter compatibilidade durante transição

---

## 📝 **FASE 1: Container de DI e Refatoração do main.py**
**Status:** 🔴 Não Iniciado  
**Prioridade:** 🚨 Crítica  
**Estimativa:** 2-3 semanas  

### 🔍 Problemática Atual
- **Acoplamento Forte**: `main.py` instancia diretamente todas as dependências
- **Dificuldade de Testes**: Impossível mockar dependências facilmente
- **Configuração Hardcoded**: Parâmetros fixos na criação de objetos
- **Violação do Princípio SOLID**: Dependências são criadas, não injetadas
- **Escalabilidade Limitada**: Adicionar novos módulos requer modificar main.py

### 🎯 Justificativa
- **Testabilidade**: Permitir injeção de mocks durante testes
- **Flexibilidade**: Trocar implementações sem alterar código
- **Manutenibilidade**: Centraliziar configuração de dependências
- **Desacoplamento**: Reduzir dependências diretas entre módulos
- **Configurabilidade**: Permitir diferentes configurações por ambiente

### 📊 Tarefas Detalhadas

#### 1.1 Criar Container de Injeção de Dependência
- [ ] **Arquivo**: `core/dependency_container.py`
- [ ] **Implementar**:
  - [ ] Registro de serviços e suas factories
  - [ ] Gestão de ciclo de vida (singleton vs transient)
  - [ ] Resolução automática de dependências
  - [ ] Validação de dependências circulares
- [ ] **Testes**: Criar testes unitários para o container

#### 1.2 Definir Interfaces e Contratos
- [ ] **Diretório**: `interfaces/`
- [ ] **Criar interfaces**:
  - [ ] `IScannerModule`: Interface base para módulos de scan
  - [ ] `ILogger`: Interface para sistema de logging
  - [ ] `IReportGenerator`: Interface para geração de relatórios
  - [ ] `IPersistenceLayer`: Interface para persistência
  - [ ] `IOrchestrator`: Interface para orquestrador

#### 1.3 Refatorar main.py
- [ ] **Eliminar instanciação direta**:
  - [ ] Remover `resolver_dns = ResolucaoDNS()`
  - [ ] Remover `scanner_portas = VarreduraRustScan()`
  - [ ] Remover `scanner_nmap = VarreduraNmap()`
  - [ ] Remover `decisao_ia = DecisaoIA()`
- [ ] **Implementar configuração via container**
- [ ] **Separar responsabilidades CLI vs lógica de negócio**
- [ ] **Criar factory methods**

#### 1.4 Configuração Centralizada
- [ ] **Arquivo**: `config/services.yaml`
- [ ] **Implementar**:
  - [ ] Mapeamento de interfaces para implementações
  - [ ] Suporte a diferentes perfis (dev, test, prod)
  - [ ] Configuração de ciclo de vida dos serviços

#### 1.5 Migração Gradual
- [ ] **Manter compatibilidade com versão atual**
- [ ] **Criar wrapper para transição**
- [ ] **Testes de regressão**

### ✅ Critérios de Aceitação
- [ ] Container DI funcional com testes completos
- [ ] main.py refatorado sem instanciação direta
- [ ] Todas as funcionalidades atuais mantidas
- [ ] Configuração externa funcionando
- [ ] Cobertura de testes > 80%

---

## ⚡ **FASE 2: Padrão Strategy para Módulos**
**Status:** 🔴 Não Iniciado  
**Prioridade:** 🔥 Alta  
**Estimativa:** 3-4 semanas  
**Dependências:** Fase 1 completa

### 🔍 Problemática Atual
- **Lógica Condicional Complexa**: OrquestradorInteligente tem muitos `if/else`
- **Dificuldade de Extensão**: Adicionar novo módulo requer modificar orquestrador
- **Responsabilidade Única Violada**: Orquestrador conhece detalhes de cada módulo
- **Acoplamento Temporal**: Ordem de execução hardcoded
- **Reutilização Limitada**: Módulos não podem ser usados independentemente

### 🎯 Justificativa
- **Extensibilidade**: Novos módulos sem modificar código existente
- **Flexibilidade**: Diferentes estratégias para diferentes cenários
- **Manutenibilidade**: Cada módulo é responsável por sua lógica
- **Testabilidade**: Testar estratégias independentemente
- **Configurabilidade**: Definir estratégias via configuração

### 📊 Tarefas Detalhadas

#### 2.1 Definir Interface Strategy Base
- [ ] **Arquivo**: `interfaces/scanner_strategy.py`
- [ ] **Métodos a implementar**:
  - [ ] `can_execute(context)`: Verifica se pode executar
  - [ ] `execute(target, context)`: Executa a estratégia
  - [ ] `get_priority()`: Retorna prioridade de execução
  - [ ] `get_dependencies()`: Lista dependências necessárias
  - [ ] `estimate_time()`: Estima tempo de execução

#### 2.2 Converter Módulos Existentes
- [ ] **ResolucaoDNS** → `DNSResolutionStrategy`
  - [ ] Implementar interface Strategy
  - [ ] Manter funcionalidade existente
  - [ ] Adicionar contexto de execução
- [ ] **VarreduraRustScan** → `PortScanStrategy`
  - [ ] Converter para strategy
  - [ ] Implementar validações de contexto
- [ ] **VarreduraNmap** → `ServiceDetectionStrategy`
  - [ ] Migrar para novo padrão
  - [ ] Adicionar dependências
- [ ] **AnalisadorVulnerabilidades** → `VulnerabilityAnalysisStrategy`
  - [ ] Refatorar para strategy
  - [ ] Implementar estimativas de tempo

#### 2.3 Implementar Strategy Manager
- [ ] **Arquivo**: `core/strategy_manager.py`
- [ ] **Responsabilidades**:
  - [ ] Registro de estratégias disponíveis
  - [ ] Seleção baseada em contexto e prioridade
  - [ ] Execução ordenada e controle de fluxo
  - [ ] Gestão de dependências entre estratégias

#### 2.4 Context Object
- [ ] **Arquivo**: `core/scan_context.py`
- [ ] **Implementar**:
  - [ ] Dados compartilhados entre estratégias
  - [ ] Estado sobre o alvo e progresso
  - [ ] Configuração específica por execução
  - [ ] Métricas de tempo e recursos

#### 2.5 Integração com Container DI
- [ ] **Registrar strategies no container**
- [ ] **Configurar dependências**
- [ ] **Criar factory para strategy manager**

### ✅ Critérios de Aceitação
- [ ] Todos os módulos convertidos para Strategy
- [ ] Strategy Manager funcional
- [ ] Context Object implementado
- [ ] Execução dinâmica baseada em contexto
- [ ] Funcionalidade atual preservada

---

## 📡 **FASE 3: Sistema de Eventos**
**Status:** 🔴 Não Iniciado  
**Prioridade:** 🟡 Média  
**Estimativa:** 2-3 semanas  
**Dependências:** Pode ser paralela à Fase 2

### 🔍 Problemática Atual
- **Acoplamento Temporal**: Módulos executam sequencialmente
- **Falta de Reatividade**: Não há resposta a mudanças em tempo real
- **Monitoramento Limitado**: Difícil acompanhar progresso
- **Integração Complexa**: Módulos não se comunicam eficientemente
- **Auditoria Insuficiente**: Falta rastro de operações

### 🎯 Justificativa
- **Desacoplamento**: Módulos comunicam via eventos
- **Reatividade**: Resposta automática a descobertas
- **Observabilidade**: Rastro completo de operações
- **Extensibilidade**: Novos handlers sem modificar código
- **Paralelismo**: Execução assíncrona quando possível

### 📊 Tarefas Detalhadas

#### 3.1 Event Bus Architecture
- [ ] **Arquivo**: `core/event_system.py`
- [ ] **Componentes**:
  - [ ] `EventBus`: Central de distribuição de eventos
  - [ ] `Event`: Estrutura base para eventos
  - [ ] `EventHandler`: Interface para manipuladores
  - [ ] `EventStore`: Persistência de eventos para auditoria

#### 3.2 Definir Tipos de Eventos
- [ ] **Sistema**:
  - [ ] `SystemStarted`
  - [ ] `SystemShutdown`
  - [ ] `ConfigurationChanged`
- [ ] **Descoberta**:
  - [ ] `HostDiscovered`
  - [ ] `PortOpened`
  - [ ] `ServiceDetected`
- [ ] **Segurança**:
  - [ ] `VulnerabilityFound`
  - [ ] `SecurityHeaderMissing`
  - [ ] `WeakCredentialsDetected`
- [ ] **Progresso**:
  - [ ] `ScanStarted`
  - [ ] `ScanCompleted`
  - [ ] `ModuleExecuted`

#### 3.3 Implementar Event Handlers
- [ ] **LoggingHandler**: Registra todos os eventos
- [ ] **MetricsHandler**: Coleta métricas em tempo real
- [ ] **NotificationHandler**: Alertas para descobertas críticas
- [ ] **PersistenceHandler**: Salva resultados automaticamente

#### 3.4 Integração com Estratégias
- [ ] **Modificar strategies para publicar eventos**
- [ ] **Implementar subscrição a eventos**
- [ ] **Criar fluxo adaptativo baseado em eventos**

### ✅ Critérios de Aceitação
- [ ] EventBus funcional e testado
- [ ] Todos os tipos de eventos implementados
- [ ] Handlers básicos funcionando
- [ ] Integração com strategies
- [ ] Sistema de auditoria operacional

---

## 📊 **FASE 4: Métricas e Observabilidade**
**Status:** 🔴 Não Iniciado  
**Prioridade:** 🟡 Média  
**Estimativa:** 2-3 semanas  
**Dependências:** Fase 3 (eventos)

### 🔍 Problemática Atual
- **Visibilidade Limitada**: Não sabemos o que acontece internamente
- **Performance Desconhecida**: Sem dados sobre tempo/recursos
- **Debugging Difícil**: Falta informações para troubleshooting
- **Otimização Impossível**: Sem métricas para melhorar performance
- **SLA Indefinido**: Não há garantias de tempo de resposta

### 🎯 Justificativa
- **Monitoramento Proativo**: Detectar problemas antes que afetem usuários
- **Otimização Baseada em Dados**: Melhorar performance com métricas reais
- **Debugging Eficiente**: Logs estruturados e correlacionados
- **Capacity Planning**: Planejar recursos baseado em uso real
- **Compliance**: Atender requisitos de auditoria e observabilidade

### 📊 Tarefas Detalhadas

#### 4.1 Sistema de Métricas
- [ ] **Arquivo**: `core/metrics.py`
- [ ] **Tipos de métricas**:
  - [ ] **Contadores**: Número de scans, vulnerabilidades encontradas
  - [ ] **Gauges**: Recursos utilizados, tempo médio de execução
  - [ ] **Histogramas**: Distribuição de tempo de resposta
  - [ ] **Timers**: Duração de operações específicas

#### 4.2 Logging Estruturado
- [ ] **Melhorar logger existente**:
  - [ ] Formato JSON para facilitar parsing
  - [ ] Níveis: DEBUG, INFO, WARN, ERROR, FATAL
  - [ ] Contexto: Request ID, User ID, Target, Module
  - [ ] Correlação: Rastreamento através de múltiplos módulos

#### 4.3 Health Checks
- [ ] **Arquivo**: `core/health_checks.py`
- [ ] **Verificações**:
  - [ ] **Sistema**: CPU, memória, disco disponível
  - [ ] **Dependências**: Conectividade com serviços externos
  - [ ] **Funcionalidade**: Testes básicos de cada módulo
  - [ ] **Performance**: Latência e throughput

#### 4.4 Dashboards e Alertas
- [ ] **Métricas em tempo real**
- [ ] **Histórico e tendências**
- [ ] **Sistema de alertas**
- [ ] **Relatórios periódicos**

#### 4.5 Integração com Sistema de Eventos
- [ ] **MetricsHandler para coleta automática**
- [ ] **Correlação de eventos com métricas**
- [ ] **Alertas baseados em eventos**

### ✅ Critérios de Aceitação
- [ ] Sistema de métricas funcional
- [ ] Logging estruturado implementado
- [ ] Health checks operacionais
- [ ] Dashboards básicos disponíveis
- [ ] Integração com eventos completa

---

## 🔌 **FASE 5: Arquitetura de Plugins**
**Status:** 🔴 Não Iniciado  
**Prioridade:** 🟢 Baixa  
**Estimativa:** 4-5 semanas  
**Dependências:** Todas as fases anteriores

### 🔍 Problemática Atual
- **Extensibilidade Limitada**: Novos módulos requerem modificar código base
- **Distribuição Complexa**: Atualizações afetam sistema inteiro
- **Customização Difícil**: Adaptações específicas são invasivas
- **Manutenção Acoplada**: Bug em módulo afeta sistema todo
- **Inovação Restrita**: Apenas desenvolvedores core podem contribuir

### 🎯 Justificativa
- **Extensibilidade**: Comunidade pode criar módulos
- **Modularidade**: Componentes independentes e versioning separado
- **Customização**: Adaptações sem modificar core
- **Manutenção Isolada**: Problemas em plugins não afetam sistema
- **Ecossistema**: Marketplace de plugins especializados

### 📊 Tarefas Detalhadas

#### 5.1 Plugin Framework
- [ ] **Arquivo**: `core/plugin_framework.py`
- [ ] **Ciclo de vida**:
  - [ ] Load: Carregamento do plugin
  - [ ] Initialize: Inicialização e configuração
  - [ ] Execute: Execução das funcionalidades
  - [ ] Cleanup: Limpeza de recursos
  - [ ] Unload: Descarregamento seguro
- [ ] **Isolamento**: Namespace separado para cada plugin
- [ ] **Versionamento**: Compatibilidade e dependências
- [ ] **Configuração**: Schema específico por plugin

#### 5.2 Plugin Discovery
- [ ] **Auto-discovery**: Scan de diretórios específicos
- [ ] **Registry**: Catálogo central de plugins disponíveis
- [ ] **Metadata**: Descrição, versão, dependências, configuração
- [ ] **Validation**: Verificação de assinatura e integridade

#### 5.3 Plugin API
- [ ] **Interfaces Padronizadas**: Contratos claros para implementação
- [ ] **SDK**: Ferramentas para desenvolvimento de plugins
- [ ] **Utilities**: Bibliotecas comuns para plugins
- [ ] **Documentation**: Guias e exemplos para desenvolvedores

#### 5.4 Plugin Manager
- [ ] **Installation**: Download e instalação automática
- [ ] **Updates**: Verificação e aplicação de atualizações
- [ ] **Configuration**: Interface para configurar plugins
- [ ] **Monitoring**: Saúde e performance dos plugins

#### 5.5 Exemplos de Plugins
- [ ] **Plugin de exemplo**: Template básico
- [ ] **Plugin de teste**: Para validar framework
- [ ] **Migração de módulo existente**: Proof of concept

### ✅ Critérios de Aceitação
- [ ] Framework de plugins funcional
- [ ] Sistema de discovery operacional
- [ ] API e SDK documentados
- [ ] Plugin Manager implementado
- [ ] Pelo menos um plugin funcional como exemplo

---

## 📅 Cronograma e Dependências

### 🔄 Ordem de Implementação
```
Fase 1 (Container DI)
    ↓
Fase 2 (Strategy Pattern) ← Pode ser paralela → Fase 3 (Eventos)
    ↓                                              ↓
Fase 4 (Métricas) ← Depende das Fases 2 e 3
    ↓
Fase 5 (Plugins) ← Depende de todas as anteriores
```

### ⏱️ Estimativa Total
- **Fase 1**: 2-3 semanas (crítica)
- **Fase 2**: 3-4 semanas (alta complexidade)
- **Fase 3**: 2-3 semanas (pode ser paralela à Fase 2)
- **Fase 4**: 2-3 semanas (depende da Fase 3)
- **Fase 5**: 4-5 semanas (maior complexidade)

**Total Estimado**: 13-18 semanas (3-4.5 meses)

### ⚠️ Riscos e Mitigações

#### Riscos Técnicos
- **Quebra de Compatibilidade**
  - **Mitigação**: Manter APIs legadas durante transição
  - **Estratégia**: Implementar wrapper de compatibilidade
- **Degradação de Performance**
  - **Mitigação**: Benchmarks antes/depois de cada fase
  - **Estratégia**: Otimização incremental
- **Complexidade Excessiva**
  - **Mitigação**: Implementação incremental com rollback
  - **Estratégia**: Prova de conceito antes de implementação completa

#### Riscos de Projeto
- **Resistência à Mudança**
  - **Mitigação**: Documentação clara e treinamento
  - **Estratégia**: Demonstrar benefícios tangíveis
- **Escopo Creep**
  - **Mitigação**: Definir critérios de aceitação claros
  - **Estratégia**: Review semanal de progresso

### 📊 Métricas de Sucesso
- **Cobertura de Testes**: > 80% em cada fase
- **Performance**: Não degradar mais que 10%
- **Funcionalidade**: 100% das features atuais mantidas
- **Extensibilidade**: Capacidade de adicionar módulos sem modificar core
- **Observabilidade**: Visibilidade completa de operações

---

## 🚀 Próximos Passos

### Imediatos (Esta Semana)
1. [ ] **Revisar e aprovar este plano**
2. [ ] **Criar branch de desenvolvimento**: `feature/refactoring-phase1`
3. [ ] **Configurar ambiente de testes**
4. [ ] **Iniciar Fase 1**: Container de DI

### Preparação (Próxima Semana)
1. [ ] **Definir critérios de aceitação detalhados para Fase 1**
2. [ ] **Criar estrutura de testes para novo código**
3. [ ] **Documentar APIs atuais para manter compatibilidade**

### Acompanhamento
- **Reviews semanais**: Progresso e impedimentos
- **Demos quinzenais**: Demonstração de funcionalidades
- **Retrospectivas mensais**: Ajustes no processo

---

## 📚 Recursos e Referências

### Documentação Técnica
- [ ] Arquitetura atual do sistema
- [ ] APIs existentes e contratos
- [ ] Configurações e dependências

### Ferramentas
- [ ] Framework de testes: pytest
- [ ] Análise de código: pylint, black
- [ ] Documentação: Sphinx
- [ ] CI/CD: GitHub Actions

### Bibliografia
- Clean Architecture (Robert C. Martin)
- Design Patterns (Gang of Four)
- Building Microservices (Sam Newman)
- Site Reliability Engineering (Google)

---

**Última Atualização**: 2 de setembro de 2025  
**Responsável**: Equipe de Desenvolvimento VarreduraIA  
**Status Geral**: 🔴 Planejamento Concluído - Aguardando Início da Implementação
