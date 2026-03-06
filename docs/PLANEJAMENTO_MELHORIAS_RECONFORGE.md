# Planejamento de Melhoria - ReconForge (Essencial)

## 1) Objetivo

Evoluir o ReconForge de "scanner + plugins soltos" para um orquestrador orientado a prova de impacto, com pipeline claro:

`Recon -> Detectar -> Validar -> Explorar -> Evidencia -> Relatorio`

Regra central:

- Nao reportar como vulnerabilidade critica sem tentativa real de exploracao e evidencia objetiva.

---

## 2) Diagnostico rapido do estado atual

Pontos fortes atuais:

- Arquitetura de plugins ja madura (`core/plugin_manager.py`, `core/plugin_base.py`).
- Orquestracao funcional em modo interativo e nao interativo (`core/minimal_orchestrator.py`).
- Ecosistema de scanners ja amplo em `plugins/` e `src/scanners/`.

Gaps para o proximo nivel:

- Nao existe pipeline de estagios com gates de decisao (detectou -> valida -> explora).
- Nao existe `exploitation_queue` padronizada por categoria.
- Evidencias ainda nao sao tratadas como artefato de primeira classe.
- Deteccao e exploracao ainda estao pouco separadas em nivel de framework.
- Falta mecanismo nativo de "proof-of-impact" para reduzir falso positivo.

---

## 3) Escopo essencial (o que realmente importa agora)

Prioridade alta:

1. Workflow por estagios com transicoes explicitas.
2. Exploitation Queue por categoria de vulnerabilidade.
3. Modulo de validacao pre-exploit (filtro de sinais fracos).
4. Modulo de execucao de exploit com coleta de evidencia.
5. Modelo de dados unificado para findings, tentativas e evidencias.
6. Geracao de relatorio orientada a evidencia.

Prioridade media:

1. Engine de payload contextual (HTML, ATTRIBUTE, JS, URL etc).
2. Browser attack engine para fluxos autenticados e DOM.
3. Integracao opcional com AnalysisSecCode e ProxyHunter.

---

## 4) Arquitetura alvo (essencial)

Fluxo proposto:

1. `stage_recon`
2. `stage_detect`
3. `stage_validate`
4. `stage_queue_build`
5. `stage_exploit`
6. `stage_evidence`
7. `stage_report`

Contrato de cada estagio:

- Entrada: estado acumulado da execucao.
- Saida: artefatos padronizados + status.
- Gate: criterio objetivo para seguir ou abortar.

---

## 5) Componentes novos (sugestao de estrutura)

### 5.1 Orquestrador de workflow

Arquivo sugerido:

- `core/workflow_orchestrator.py`

Responsabilidades:

- Executar estagios em ordem fixa.
- Permitir paralelismo por categoria (`injection`, `xss`, `auth`, `ssrf`, `authz`).
- Manter estado de execucao e checkpoints.

### 5.2 Exploitation Queue

Arquivos sugeridos:

- `core/exploit_queue.py`
- `data/queues/<run_id>/<categoria>_exploitation_queue.json`

Responsabilidades:

- Padronizar itens de exploit.
- Permitir reprocessamento e distribuicao.
- Garantir rastreabilidade de cada item.

### 5.3 Validation Gate

Arquivo sugerido:

- `core/validation_gate.py`

Responsabilidades:

- Receber achados da deteccao.
- Atribuir score de confianca minimo para virar item de queue.
- Remover ruido antes da exploracao.

### 5.4 Exploit Executor

Arquivos sugeridos:

- `core/exploit_executor.py`
- `plugins/pipelines/<categoria>_pipeline.py`

Responsabilidades:

- Executar tentativas de exploit por item de queue.
- Aplicar mutacoes de payload.
- Registrar tentativas, resultado e contexto.

### 5.5 Evidence Collector

Arquivo sugerido:

- `core/evidence_collector.py`

Responsabilidades:

- Salvar request/response, prints, logs, callbacks, hashes e timestamps.
- Classificar nivel de prova (`none`, `partial`, `impact_proven`).

### 5.6 Report Builder orientado a prova

Arquivo sugerido:

- evoluir `plugins/report_generator.py`

Regra:

- Findings sem evidencia forte vao para "potencial", nao para "confirmado".

---

## 6) Modelo de dados minimo recomendado

### 6.1 Item de exploitation queue

```json
{
  "id": "XSS-001",
  "category": "xss",
  "target": "https://app.exemplo.com",
  "endpoint": "/search",
  "method": "GET",
  "parameter": "q",
  "context": "HTML_BODY",
  "candidate_payload": "<script>alert(1)</script>",
  "detection_source": "xss_scanner_plugin",
  "confidence": "high",
  "externally_exploitable": true
}
```

### 6.2 Evidencia de exploit

```json
{
  "queue_item_id": "XSS-001",
  "attempt": 3,
  "status": "impact_proven",
  "timestamp": "2026-03-05T18:00:00Z",
  "request_snapshot": "...",
  "response_snapshot": "...",
  "artifacts": [
    "dados/evidencias/run_42/xss_001_step3.png",
    "dados/evidencias/run_42/xss_001_network.log"
  ],
  "impact_summary": "Execucao JS confirmada em sessao autenticada"
}
```

---

## 7) Roadmap de implementacao (planejamento)

## Fase 1 - Fundacao do workflow

Entregas:

- `workflow_orchestrator` com estagios e gates.
- Persistencia de estado por run.
- Estrutura de queue por categoria.

Criterio de aceite:

- Uma execucao completa gera estagios e status rastreaveis.
- Queue gerada de forma reprodutivel.

## Fase 2 - Deteccao -> validacao -> queue

Entregas:

- `validation_gate` com score minimo.
- Adaptadores para plugins existentes enviarem achados no formato comum.

Criterio de aceite:

- Achados fracos nao entram na queue.
- Cada item da queue possui origem e contexto.

## Fase 3 - Exploracao e evidencia

Entregas:

- `exploit_executor` por categoria.
- `evidence_collector`.
- Classificacao de prova (`none`, `partial`, `impact_proven`).

Criterio de aceite:

- Cada item processado gera trilha de tentativas.
- Relatorio diferencia claramente potencial vs confirmado.

## Fase 4 - Browser + payload contextual

Entregas:

- `browser_attack_engine` para fluxos login/session.
- `payload_engine` contextual + `payload_mutator`.

Criterio de aceite:

- Casos DOM/autenticados passam a ser testaveis de ponta a ponta.

---
