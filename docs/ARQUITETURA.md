# Arquitetura e Fluxo de Execução — ReconForge

Este documento descreve o funcionamento interno do ReconForge, detalhando como os dados fluem desde o alvo inicial até o relatório final.

## Diagrama de Fluxo (Mermaid)

```mermaid
graph TD
    %% Fase 1: Reconhecimento
    subgraph "Fase 1: Reconhecimento (Discovery)"
        Target[Alvo: URL/IP/Domínio] --> Recon[StageRecon]
        Recon --> P1[WebFlowMapper / Katana / Gau]
        Recon --> P2[PortScanner / Nmap]
        P1 --> Nodes[RequestNodes, Endpoints e Formulários]
        P2 --> Assets[Hosts e Portas Abertas]
    end

    %% Fase 2: Detecção e Triagem
    subgraph "Fase 2: Detecção e Inteligência"
        Nodes --> Detect[StageDetect]
        Detect --> Actv[Scanners Ativos: Nuclei, XSS, etc.]
        Detect --> Passv[PassiveScannerPlugin]
        
        Actv --> Findings[Findings Brutos]
        Passv --> Findings
        
        Findings --> Validate[StageValidate / ValidationGate]
        Validate --> CleanFindings[Findings Validados e Filtrados]
    end

    %% Fase 3: Preparação do Ataque
    subgraph "Fase 3: Orquestração de Exploit"
        CleanFindings --> QBuild[StageQueueBuild]
        QBuild --> Expand[Expansão de Passive Findings em Categorias: XSS, SQLi, LFI...]
        Expand --> Queue[(Exploit Queue: Itens Ordenados)]
    end

    %% Fase 4: Execução e Prova
    subgraph "Fase 4: Exploração Ativa"
        Queue --> Exploit[StageExploit]
        Exploit --> Executor[ExploitExecutor]
        Executor --> Pipe[Pipelines por Categoria: XssPipeline, SqliPipeline...]
        Pipe --> Attempt[ExploitAttempt: Snapshot de Request/Response]
    end

    %% Fase 5: Evidência e Relatório
    subgraph "Fase 5: Resultados"
        Attempt --> Evidence[StageEvidence / EvidenceCollector]
        Evidence --> Classify{Classificação: Impact Proven / Partial / None}
        
        Classify --> Report[StageReport]
        Report --> FinalMD[Relatório Final .md]
        Report --> RawLogs[Resultados Brutos por Plugin .json/.md]
        Report --> AI[IA: Resumo Executivo]
    end

    %% Conexão Global
    State[(WorkflowState)] -.-> Recon
    State -.-> Detect
    State -.-> QBuild
    State -.-> Exploit
    State -.-> Report
```

## Descrição dos Estágios

### 1. StageRecon (Descoberta)
Mapeia a superfície de ataque. Utiliza browsers reais (Playwright) e coletores históricos (Gau/Katana) para identificar todos os endpoints, formulários e requisições de rede.

### 2. StageDetect (Inteligência)
Os scanners ativos procuram por assinaturas conhecidas. O **PassiveScannerPlugin** converte cada endpoint com parâmetros em um "achado em potencial" para garantir cobertura total.

### 3. StageValidate (Triagem)
O **ValidationGate** filtra ruídos, remove duplicatas e garante que apenas alvos com pontuação de confiança suficiente avancem para a fila de ataque.

### 4. StageQueueBuild (Orquestração)
Transforma os achados em tarefas concretas na `ExploitQueue`. Se um endpoint é marcado como "passivo", ele é expandido em múltiplas categorias de teste (XSS, SQLi, LFI, SSRF, IDOR).

### 5. StageExploit (Ataque Ativo)
Executa os payloads de exploração reais. Cada tentativa gera um snapshot completo (Request/Response) para auditoria.

### 6. StageReport (Documentação)
Compila as evidências. Gera o relatório principal em Markdown e exporta os resultados brutos de cada plugin para a pasta `plugins_raw/`, incluindo os comandos exatos executados.
