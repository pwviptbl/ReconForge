# Requirements Document - Orquestrador Inteligente de Varreduras

## Introduction

O Orquestrador Inteligente é um sistema que coordena automaticamente múltiplos módulos de varredura de segurança baseado em decisões da IA. O sistema analisa resultados em tempo real e determina quais ferramentas executar próximo, otimizando o processo de pentest e garantindo cobertura completa sem redundância desnecessária.

## Requirements

### Requirement 1

**User Story:** Como um pentester, eu quero que o sistema execute varreduras de forma inteligente e automatizada, para que eu possa obter resultados completos sem ter que decidir manualmente quais ferramentas usar em cada etapa.

#### Acceptance Criteria

1. WHEN o usuário fornece um alvo (IP ou DNS) THEN o sistema SHALL resolver automaticamente o DNS se necessário
2. WHEN o sistema inicia uma varredura THEN SHALL executar descoberta inicial de portas usando RustScan
3. WHEN a descoberta inicial é concluída THEN o sistema SHALL consultar a IA para determinar próximos passos
4. WHEN a IA recomenda módulos específicos THEN o sistema SHALL executar os módulos recomendados com parâmetros otimizados
5. WHEN cada módulo completa sua execução THEN o sistema SHALL atualizar o contexto de varredura e consultar a IA novamente

### Requirement 2

**User Story:** Como um pentester, eu quero que a IA analise os resultados de cada etapa e tome decisões inteligentes sobre quais ferramentas usar próximo, para que o processo seja eficiente e direcionado.

#### Acceptance Criteria

1. WHEN serviços web são detectados (portas 80, 443, 8080, etc.) THEN a IA SHALL recomendar execução de WhatWeb, Feroxbuster e Nikto
2. WHEN um domínio é fornecido como alvo THEN a IA SHALL recomendar enumeração de subdomínios com Subfinder e Sublist3r
3. WHEN vulnerabilidades são encontradas THEN a IA SHALL recomendar busca de exploits com SearchSploit e varredura com Nuclei
4. WHEN formulários web ou parâmetros são detectados THEN a IA SHALL recomendar teste de SQL injection com SQLMap
5. WHEN serviços SMB são detectados THEN a IA SHALL recomendar varredura específica de SMB com Nmap
6. WHEN a IA determina que informações suficientes foram coletadas THEN SHALL finalizar o processo e gerar relatório

### Requirement 3

**User Story:** Como um pentester, eu quero que o sistema mantenha um contexto persistente de toda a varredura, para que eu possa acompanhar o progresso e entender as decisões tomadas.

#### Acceptance Criteria

1. WHEN uma varredura é iniciada THEN o sistema SHALL criar um contexto de varredura com timestamp e informações do alvo
2. WHEN cada módulo é executado THEN o sistema SHALL salvar os resultados no contexto persistente
3. WHEN a IA toma uma decisão THEN o sistema SHALL registrar a decisão, justificativa e próximos passos no contexto
4. WHEN o usuário solicita status THEN o sistema SHALL exibir progresso atual e fases completadas
5. WHEN uma varredura é interrompida THEN o sistema SHALL salvar o estado atual e permitir retomada posterior

### Requirement 4

**User Story:** Como um pentester, eu quero receber um relatório consolidado final que integre todos os resultados dos módulos executados, para que eu tenha uma visão completa da superfície de ataque.

#### Acceptance Criteria

1. WHEN todas as fases de varredura são concluídas THEN o sistema SHALL gerar relatório HTML consolidado
2. WHEN o relatório é gerado THEN SHALL incluir resumo executivo com nível de risco geral
3. WHEN o relatório é gerado THEN SHALL incluir seção detalhada para cada módulo executado
4. WHEN vulnerabilidades são encontradas THEN o relatório SHALL priorizá-las por criticidade
5. WHEN o relatório é gerado THEN SHALL incluir recomendações específicas da IA para próximos passos manuais
6. WHEN o relatório é gerado THEN SHALL incluir timeline das decisões da IA durante o processo

### Requirement 5

**User Story:** Como um pentester, eu quero poder configurar o comportamento do orquestrador, para que eu possa adaptar o processo às minhas necessidades específicas.

#### Acceptance Criteria

1. WHEN o usuário configura modo de agressividade THEN o sistema SHALL ajustar parâmetros dos módulos accordingly
2. WHEN o usuário especifica módulos a evitar THEN o sistema SHALL excluir esses módulos das recomendações da IA
3. WHEN o usuário define timeout máximo THEN o sistema SHALL respeitar esse limite para cada módulo
4. WHEN o usuário configura modo stealth THEN o sistema SHALL usar parâmetros menos detectáveis
5. WHEN o usuário especifica profundidade máxima THEN o sistema SHALL limitar recursão de descoberta

### Requirement 6

**User Story:** Como um pentester, eu quero que o sistema seja resiliente a falhas e continue operando mesmo quando alguns módulos falham, para que eu não perca todo o progresso por causa de um erro isolado.

#### Acceptance Criteria

1. WHEN um módulo falha durante execução THEN o sistema SHALL registrar o erro e continuar com próximos módulos
2. WHEN a conexão com a IA é perdida THEN o sistema SHALL usar fallback com regras pré-definidas
3. WHEN um módulo não está instalado THEN o sistema SHALL pular esse módulo e informar ao usuário
4. WHEN recursos do sistema são limitados THEN o sistema SHALL ajustar paralelismo automaticamente
5. WHEN o sistema é interrompido THEN SHALL salvar estado atual e permitir retomada

### Requirement 7

**User Story:** Como um pentester, eu quero poder executar o orquestrador em diferentes modos (interativo, automático, batch), para que eu possa adaptar o uso aos diferentes cenários de trabalho.

#### Acceptance Criteria

1. WHEN modo interativo é selecionado THEN o sistema SHALL solicitar confirmação antes de executar cada fase
2. WHEN modo automático é selecionado THEN o sistema SHALL executar todas as fases sem intervenção
3. WHEN modo batch é selecionado THEN o sistema SHALL processar múltiplos alvos sequencialmente
4. WHEN modo verbose é habilitado THEN o sistema SHALL exibir logs detalhados em tempo real
5. WHEN modo silencioso é habilitado THEN o sistema SHALL exibir apenas resultados finais

### Requirement 8

**User Story:** Como um pentester, eu quero que o sistema integre perfeitamente com os módulos existentes, para que eu possa aproveitar toda a funcionalidade já implementada.

#### Acceptance Criteria

1. WHEN o orquestrador executa um módulo THEN SHALL usar as classes e métodos existentes sem modificação
2. WHEN resultados são processados THEN o sistema SHALL manter compatibilidade com formatos JSON existentes
3. WHEN configurações são necessárias THEN o sistema SHALL usar o sistema de configuração YAML existente
4. WHEN logs são gerados THEN o sistema SHALL usar o sistema de logging existente
5. WHEN relatórios são gerados THEN o sistema SHALL integrar com sistema de relatórios existente