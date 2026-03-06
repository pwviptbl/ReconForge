# ReconForge — Análise Arquitetural e Roadmap Detalhado

> Nota: este documento e historico. O `MinimalOrchestrator` citado abaixo ja foi removido; o estado atual do projeto e o pipeline unico baseado em `WorkflowOrchestrator`.

## 1. Estado Atual da Arquitetura

O ReconForge hoje é uma **aplicação monolítica com plugin architecture plana**:

- Um `MinimalOrchestrator` que funciona como **menu interativo** — o usuário escolhe qual plugin rodar, um de cada vez, sem conceito de sequência.
- 35 plugins que compartilham a mesma interface `execute(target, context)` sem distinção entre **detecção**, **validação** e **exploração**.
- Persistência em SQLite local com schema simples (tabelas `runs` e `plugin_cache`).
- 10+ binários externos necessários no sistema operacional (nmap, nuclei, katana, subfinder, gau, whatweb, searchsploit, chromium...).
- ~40 dependências Python incluindo ML, browser automation e LLM.
- Contexto de execução como `Dict[str, Any]` livre, sem contratos tipados entre plugins.

---

## 2. Por que só adicionar os novos módulos não basta

O planejamento propõe um **pipeline com estágios e gates de decisão**:

```
Recon → Detect → Validate → Queue → Exploit → Evidence → Report
```

O orquestrador atual não tem conceito de estágios — é um loop de menu. Adicionar
`exploit_executor.py` e `evidence_collector.py` como plugins normais seria encaixar
peça quadrada em buraco redondo.

| Gap arquitetural | Por que só adicionar arquivo não resolve |
|---|---|
| **Sem pipeline de estágios** | O `MinimalOrchestrator` não sabe que detecção vem antes de validação. Roda qualquer plugin em qualquer ordem. |
| **Sem contrato entre estágios** | O `context` é dicionário livre. Não existe schema para "achado validado" vs "achado bruto". |
| **`PluginResult` genérico demais** | O resultado de um exploit (tentativas, snapshots, evidências) é estruturalmente diferente de um port scan. Usar o mesmo modelo gera ambiguidade e perda de rastreabilidade. |
| **Sem estado por item de finding** | A `exploitation_queue` exige tracking individual por finding. O `Storage` atual só persiste o contexto completo do run. |
| **Sem paralelismo por categoria** | O planejamento pede exploração paralela por categoria (XSS, SQLi, SSRF separadas). O orquestrador atual é puramente sequencial. |

### O que precisa mudar

1. **Novo orquestrador** (`workflow_orchestrator.py`) — envolve o `MinimalOrchestrator` com conceito de stages e gates de decisão.
2. **Modelo de dados estendido** em `core/models.py` — novos dataclasses: `Finding`, `ExploitAttempt`, `Evidence`, `QueueItem` com state machine.
3. **Storage estendido** — novas tabelas SQLite para queue items, tentativas de exploit e evidências.
4. **Contratos tipados** entre estágios — em lugar de `Dict[str, Any]` livre, modelos que garantam compatibilidade de saída/entrada entre stages.

### O que **não** precisa mudar

- Interface `BasePlugin` e plugins existentes continuam funcionando — tornam-se plugins de `stage_detect`.
- `PluginManager` continua carregando plugins normalmente.
- `config.py` e estrutura YAML continuam intactos.
- Aproximadamente **70% do código existente é preservado** — a mudança é uma camada por cima, não uma reescrita.

---

## 3. Docker — Vale a Pena?

### O que projetos como Shannon fazem

Projetos de pentest que usam Docker costumam ter arquitetura **orientada a serviços**:

- Frontend/CLI separado do backend de scanning.
- Workers que processam filas de exploração (exatamente o que o planejamento propõe).
- Banco de dados centralizado (PostgreSQL em vez de SQLite local).
- API REST para submeter alvos e consultar resultados.

Isso mapeia naturalmente para Docker Compose:

```
services:
  api:        # FastAPI — recebe alvos, retorna resultados
  worker:     # Processa exploitation_queue em paralelo
  scanner:    # Roda plugins de detecção (nmap, nuclei, katana...)
  browser:    # Chromium headless para fluxos DOM/autenticados
  db:         # PostgreSQL
  redis:      # Fila de mensagens entre stages
```

### Vantagens reais para o ReconForge

| Vantagem | Impacto prático |
|---|---|
| **Gerenciamento de dependências** | Setup hoje exige instalar manualmente 10+ binários. Docker resolve com um `docker build`. |
| **Reprodutibilidade** | `run.sh` assume Debian/Kali e torce para tudo estar instalado. Com Docker, funciona igual em qualquer máquina. |
| **Distribuição** | `docker pull reconforge` é incomparavelmente mais acessível que clonar + instalar 10 binários Go. |
| **Isolamento** | Ferramentas de pentest rodando isoladas do host é boa prática de segurança. |
| **CI/CD** | Testar o pipeline completo em CI fica trivial. |

### Problemas reais com Docker para pentest

| Problema | Gravidade | Solução |
|---|---|---|
| **Acesso à rede** | Alta | Requer `--net=host` para scans reais. Reduz isolamento de rede. |
| **Privilégios** | Alta | nmap SYN scan, scapy, pyshark precisam de `CAP_NET_RAW`. Exige `--cap-add` ou `--privileged`. |
| **Tamanho da imagem** | Média | nmap + nuclei + katana + subfinder + chromium + Python ML deps = facilmente 2–3 GB. |
| **Chromium headless** | Média | Funciona em Docker, mas exige `--no-sandbox` e configuração de shared memory (`/dev/shm`). |
| **Orquestrador interativo** | Média | O orquestrador atual é menu CLI. Docker + terminal interativo funciona com `-it`, mas frameworks orientados a fila são headless por natureza. |

### Conclusão sobre Docker

Docker é vantajoso para o ReconForge principalmente pela quantidade de dependências externas.
Mas **dockerizar uma arquitetura de menu interativo monolítico** traz pouco valor além de facilitar
instalação. O valor real aparece quando existirem workers processando filas e serviços separados — o
que só acontece após o pipeline estar implementado.

**Decisão recomendada**: Docker entra na Fase 3, não antes.

---

## 4. Roadmap Detalhado por Fase

---

### FASE 1 — Fundação do Workflow

**Objetivo**: Transformar o orquestrador de menu interativo em orquestrador orientado a pipeline,
com stages explícitos, contratos tipados e persistência de estado por item.

**Quando está concluída**: Uma execução completa gera stages com status rastreável, a queue é
persistida por run e é reprodutível.

#### 4.1.1 `core/workflow_orchestrator.py`

Substituir/envolver o `MinimalOrchestrator` com um orquestrador que conhece stages:

```python
class WorkflowOrchestrator:
    stages = [
        stage_recon,
        stage_detect,
        stage_validate,
        stage_queue_build,
        stage_exploit,
        stage_evidence,
        stage_report,
    ]

    def run(self, target: str) -> WorkflowResult:
        state = WorkflowState(target=target, run_id=self._new_run_id())
        for stage in self.stages:
            state = stage.execute(state)
            if not stage.gate_passes(state):
                break  # Gate falhou: abortar ou pular estágio
            self.storage.checkpoint(state)
        return state.to_result()
```

Propriedades necessárias:
- Cada stage recebe e retorna `WorkflowState` (imutável ou com versionamento).
- Gate de decisão configurable por stage (ex.: "não ir para exploit se validate retornou zero itens confirmados").
- Checkpoint automático após cada stage — permite retomar de onde parou.
- Suporte a paralelismo **por categoria** dentro de `stage_exploit` (XSS, SSRF, SQLi em workers separados).

#### 4.1.2 Modelos de dados novos em `core/models.py`

```python
@dataclass
class Finding:
    id: str                      # UUID gerado na detecção
    category: str                # "xss", "sqli", "ssrf", "lfi", "idor", "auth"
    target: str
    endpoint: str
    method: str
    parameter: str
    context: str                 # "HTML_BODY", "ATTRIBUTE", "JS", "URL", "HEADER"
    candidate_payload: str
    detection_source: str        # Nome do plugin que gerou
    raw_evidence: str            # Snippet de resposta que disparou a detecção
    confidence_score: float      # 0.0 a 1.0
    externally_exploitable: bool
    stage: str                   # "detected", "validated", "queued", "exploited", "false_positive"
    created_at: str

@dataclass
class QueueItem:
    id: str                      # "XSS-001", "SQLI-007"
    finding_id: str              # Referência ao Finding original
    category: str
    priority: int                # 1 (crítico) a 5 (info)
    status: str                  # "pending", "in_progress", "done", "skipped"
    assigned_executor: str       # Plugin ou executor responsável
    created_at: str
    updated_at: str

@dataclass
class ExploitAttempt:
    id: str
    queue_item_id: str
    attempt_number: int
    payload_used: str
    request_snapshot: str
    response_snapshot: str
    status: str                  # "failed", "partial", "impact_proven"
    timestamp: str
    executor: str

@dataclass
class Evidence:
    id: str
    queue_item_id: str
    attempt_id: str
    proof_level: str             # "none", "partial", "impact_proven"
    artifacts: List[str]         # Caminhos de arquivos (prints, logs, pcaps)
    impact_summary: str
    timestamp: str
```

#### 4.1.3 Storage estendido em `core/storage.py`

Novas tabelas sem quebrar as existentes:

```sql
-- Findings brutos da detecção
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    run_id INTEGER REFERENCES runs(id),
    category TEXT, target TEXT, endpoint TEXT,
    method TEXT, parameter TEXT, context TEXT,
    candidate_payload TEXT, detection_source TEXT,
    confidence_score REAL, externally_exploitable INTEGER,
    stage TEXT, created_at TEXT
);

-- Queue de exploração por categoria
CREATE TABLE queue_items (
    id TEXT PRIMARY KEY,
    finding_id TEXT REFERENCES findings(id),
    run_id INTEGER REFERENCES runs(id),
    category TEXT, priority INTEGER,
    status TEXT, assigned_executor TEXT,
    created_at TEXT, updated_at TEXT
);

-- Tentativas individuais de exploit
CREATE TABLE exploit_attempts (
    id TEXT PRIMARY KEY,
    queue_item_id TEXT REFERENCES queue_items(id),
    attempt_number INTEGER,
    payload_used TEXT,
    request_snapshot TEXT,
    response_snapshot TEXT,
    status TEXT, timestamp TEXT, executor TEXT
);

-- Evidências coletadas
CREATE TABLE evidences (
    id TEXT PRIMARY KEY,
    queue_item_id TEXT REFERENCES queue_items(id),
    attempt_id TEXT REFERENCES exploit_attempts(id),
    proof_level TEXT,
    artifacts_json TEXT,
    impact_summary TEXT,
    timestamp TEXT
);
```

#### 4.1.4 Interface de stage

```python
class StageBase(ABC):
    name: str
    timeout_seconds: int = 300

    @abstractmethod
    def execute(self, state: WorkflowState) -> WorkflowState:
        pass

    def gate_passes(self, state: WorkflowState) -> bool:
        return True  # Gate padrão — sempre passa
```

**Entregáveis da Fase 1:**
- `core/workflow_orchestrator.py`
- `core/stage_base.py`
- `core/workflow_state.py`
- Modelos novos em `core/models.py`
- Schema estendido em `core/storage.py`
- `stage_recon.py` e `stage_detect.py` como primeiros stages (adaptadores dos plugins existentes)

---

### FASE 2 — Detecção → Validação → Queue

**Objetivo**: Qualidade antes de quantidade. Achados fracos não chegam à exploração.
Cada item da queue deve ter origem, contexto e score mínimo de confiança.

**Quando está concluída**: Achados com confidence abaixo do threshold não entram na queue.
Cada item da queue possui finding_id com origem rastreável.

#### 4.2.1 `core/validation_gate.py`

O ValidationGate recebe findings brutos da detecção e aplica filtros antes de criar QueueItems:

```python
class ValidationGate:
    # Thresholds configuráveis por categoria
    MIN_CONFIDENCE = {
        "xss":   0.7,
        "sqli":  0.75,
        "ssrf":  0.65,
        "lfi":   0.70,
        "idor":  0.60,
        "auth":  0.80,
    }

    def validate(self, findings: List[Finding]) -> ValidationResult:
        accepted = []
        rejected = []
        for f in findings:
            threshold = self.MIN_CONFIDENCE.get(f.category, 0.65)
            if f.confidence_score >= threshold:
                f.stage = "validated"
                accepted.append(f)
            else:
                f.stage = "false_positive"
                rejected.append(f)
        return ValidationResult(accepted=accepted, rejected=rejected)
```

Regras adicionais do gate:
- Finding sem `parameter` identificado → rejeitar automaticamente.
- Finding de scanner que reporta apenas por status code sem snippet de resposta → score penalizado.
- Finding duplicado (mesmo endpoint + parâmetro + categoria) → manter só o de maior score.
- Finding com `externally_exploitable=False` → abaixar prioridade, não rejeitar.

#### 4.2.2 `core/exploit_queue.py`

Gerencia a fila por categoria, persiste em banco e suporta reprocessamento:

```python
class ExploitQueue:
    CATEGORY_PRIORITY = {
        "sqli":   1,
        "ssrf":   1,
        "rce":    1,
        "auth":   2,
        "xss":    2,
        "idor":   3,
        "lfi":    3,
        "open_redirect": 4,
        "header_injection": 5,
    }

    def enqueue(self, findings: List[Finding]) -> List[QueueItem]:
        items = []
        for f in findings:
            item = QueueItem(
                id=self._generate_id(f.category),
                finding_id=f.id,
                category=f.category,
                priority=self.CATEGORY_PRIORITY.get(f.category, 5),
                status="pending",
                ...
            )
            self.storage.save_queue_item(item)
            items.append(item)
        return sorted(items, key=lambda x: x.priority)

    def get_pending(self, category: Optional[str] = None) -> List[QueueItem]:
        """Retorna itens pendentes, filtrado por categoria se especificado."""

    def mark_done(self, item_id: str, status: str):
        """Atualiza status: 'done', 'skipped', 'failed'."""

    def reprocess(self, run_id: int, category: str):
        """Recoloca itens 'failed' de uma categoria de volta para 'pending'."""
```

#### 4.2.3 Adaptadores para plugins existentes

Os plugins atuais retornam `PluginResult` com dados em `Dict[str, Any]`. É necessário um
adaptador que transforma esse output em `Finding` padronizado:

```python
class PluginFindingAdapter:
    """Converte saída legada de plugins para Finding padronizado."""

    ADAPTERS = {
        "XssScannerPlugin":       XssAdapter,
        "LfiScannerPlugin":       LfiAdapter,
        "SsrfScannerPlugin":      SsrfAdapter,
        "IdorScannerPlugin":      IdorAdapter,
        "NucleiScannerPlugin":    NucleiAdapter,
        "HeaderAnalyzerPlugin":   HeaderAdapter,
    }

    def adapt(self, plugin_result: PluginResult) -> List[Finding]:
        adapter_class = self.ADAPTERS.get(plugin_result.plugin_name)
        if not adapter_class:
            return self._generic_adapt(plugin_result)
        return adapter_class().convert(plugin_result)
```

Cada adapter extrai do dicionário livre do `PluginResult` os campos necessários para `Finding`
(endpoint, parâmetro, contexto, payload candidato, snippet de evidência) e calcula um
`confidence_score` inicial baseado em heurísticas do plugin.

#### 4.2.4 `stage_validate.py` e `stage_queue_build.py`

```python
class StageValidate(StageBase):
    name = "stage_validate"

    def execute(self, state: WorkflowState) -> WorkflowState:
        gate = ValidationGate(config=state.config.validation)
        result = gate.validate(state.findings)
        state.findings = result.accepted
        state.rejected_findings = result.rejected
        return state

    def gate_passes(self, state: WorkflowState) -> bool:
        return len(state.findings) > 0  # Abortar se zero findings válidos

class StageQueueBuild(StageBase):
    name = "stage_queue_build"

    def execute(self, state: WorkflowState) -> WorkflowState:
        queue = ExploitQueue(storage=state.storage)
        state.queue_items = queue.enqueue(state.findings)
        return state
```

**Entregáveis da Fase 2:**
- `core/validation_gate.py`
- `core/exploit_queue.py`
- `core/adapters/` — um adapter por plugin de vulnerabilidade existente
- `core/stages/stage_validate.py`
- `core/stages/stage_queue_build.py`
- Testes unitários dos adapters (mocks de `PluginResult` → verificar `Finding` gerado)

---

### FASE 3 — Exploração, Evidência e Docker

**Objetivo**: Cada finding validado recebe tentativas reais de exploração com coleta de evidência
objetiva. O relatório passa a diferenciar claramente "potencial" de "confirmado".
Docker entra aqui para facilitar o setup do ambiente completo.

**Quando está concluída**: Cada item processado gera trilha de tentativas com evidência classificada.
Relatório diferencia confirmado vs potencial. `docker build` funciona end-to-end.

#### 4.3.1 `core/exploit_executor.py`

Executor central que despacha para pipelines específicos por categoria:

```python
class ExploitExecutor:
    MAX_ATTEMPTS_PER_ITEM = 5
    TIMEOUT_PER_ATTEMPT = 30  # segundos

    PIPELINES = {
        "xss":            XssPipeline,
        "sqli":           SqliPipeline,
        "ssrf":           SsrfPipeline,
        "lfi":            LfiPipeline,
        "idor":           IdorPipeline,
        "open_redirect":  OpenRedirectPipeline,
        "header_injection": HeaderInjectionPipeline,
    }

    def execute(self, item: QueueItem, context: WorkflowState) -> List[ExploitAttempt]:
        pipeline_class = self.PIPELINES.get(item.category)
        if not pipeline_class:
            return self._generic_execute(item, context)

        pipeline = pipeline_class(config=context.config, http_client=self.http)
        attempts = []

        for attempt_num in range(1, self.MAX_ATTEMPTS_PER_ITEM + 1):
            attempt = pipeline.run_attempt(item, attempt_num)
            attempts.append(attempt)
            self.storage.save_attempt(attempt)

            if attempt.status == "impact_proven":
                break  # Prova obtida, não continuar tentativas

        return attempts
```

#### 4.3.2 `plugins/pipelines/` — Pipelines por categoria

Cada pipeline encapsula:
1. Seleção/mutação de payload para o contexto específico.
2. Execução da requisição HTTP (com headers, cookies, sessão).
3. Análise da resposta para confirmar impacto.
4. Retorno do `ExploitAttempt` com snapshot completo.

Exemplo para XSS:

```python
class XssPipeline:
    PAYLOADS = [
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
    ]

    def run_attempt(self, item: QueueItem, attempt_num: int) -> ExploitAttempt:
        payload = self._select_payload(item, attempt_num)
        request, response = self.http.send(
            url=item.endpoint,
            method=item.method,
            param=item.parameter,
            payload=payload,
        )
        confirmed = self._verify_reflection(response, payload, item.context)
        return ExploitAttempt(
            payload_used=payload,
            request_snapshot=request.to_raw(),
            response_snapshot=response.to_raw(),
            status="impact_proven" if confirmed else "failed",
            ...
        )

    def _verify_reflection(self, response, payload, context) -> bool:
        """Verifica se o payload foi refletido no contexto correto (não apenas no HTML)."""
        if context == "HTML_BODY":
            return payload in response.text
        if context == "ATTRIBUTE":
            return re.search(rf'=\s*["\']?{re.escape(payload)}', response.text)
        # etc.
```

#### 4.3.3 `core/evidence_collector.py`

Classifica o nível de prova e persiste artefatos:

```python
class EvidenceCollector:
    PROOF_RULES = {
        "impact_proven": [
            "Ao menos 1 attempt com status impact_proven",
        ],
        "partial": [
            "Payload refletido mas execução não confirmada",
            "Parâmetro vulnerável identificado sem exploração completa",
        ],
        "none": [
            "Zero attempts bem-sucedidos",
            "Apenas indicadores indiretos",
        ],
    }

    def collect(self, item: QueueItem, attempts: List[ExploitAttempt]) -> Evidence:
        proof_level = self._classify(attempts)
        artifacts = self._save_artifacts(item, attempts, proof_level)
        return Evidence(
            proof_level=proof_level,
            artifacts=artifacts,
            impact_summary=self._summarize(item, attempts, proof_level),
            ...
        )

    def _save_artifacts(self, item, attempts, proof_level) -> List[str]:
        """Salva request/response, screenshots e logs em dados/evidencias/<run_id>/"""
        artifacts = []
        base_path = self.evidence_dir / f"run_{item.run_id}"
        base_path.mkdir(parents=True, exist_ok=True)

        for attempt in attempts:
            if attempt.status in ("impact_proven", "partial"):
                log_path = base_path / f"{item.id}_attempt{attempt.attempt_number}.log"
                log_path.write_text(
                    f"REQUEST:\n{attempt.request_snapshot}\n\nRESPONSE:\n{attempt.response_snapshot}"
                )
                artifacts.append(str(log_path))

        return artifacts
```

#### 4.3.4 Report Builder orientado a evidência

Evolução do `plugins/report_generator.py`:

```
Seção: VULNERABILIDADES CONFIRMADAS (proof_level = impact_proven)
  → Detalhes completos, evidências linkadas, CVSS estimado

Seção: VULNERABILIDADES POTENCIAIS (proof_level = partial)
  → Sumário, confiança, contexto, recomenda verificação manual

Seção: INDICADORES SEM CONFIRMAÇÃO (proof_level = none)
  → Lista compacta apenas para triagem

Seção: FINDINGS DESCARTADOS
  → Itens rejeitados pelo ValidationGate com motivo
```

#### 4.3.5 Dockerfile (Fase 3)

Imagem base recomendada: `kalilinux/kali-rolling` (já tem nmap, whatweb, searchsploit).
Go toolchain para compilar nuclei, katana, subfinder, gau.

```dockerfile
FROM kalilinux/kali-rolling

# Binários do sistema
RUN apt-get update && apt-get install -y \
    nmap whatweb exploitdb traceroute \
    golang-go chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Ferramentas Go (projectdiscovery)
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

ENV PATH="/root/go/bin:$PATH"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "scripts/main.py"]
```

Ponto de atenção: para scans reais, o container precisará de:
```
docker run -it --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN reconforge
```

**Entregáveis da Fase 3:**
- `core/exploit_executor.py`
- `core/evidence_collector.py`
- `plugins/pipelines/xss_pipeline.py`
- `plugins/pipelines/sqli_pipeline.py`
- `plugins/pipelines/ssrf_pipeline.py`
- `plugins/pipelines/lfi_pipeline.py`
- `plugins/pipelines/idor_pipeline.py`
- `plugins/pipelines/open_redirect_pipeline.py`
- `core/stages/stage_exploit.py`
- `core/stages/stage_evidence.py`
- Evolução do `plugins/report_generator.py`
- `data/evidencias/` como diretório de artefatos
- `Dockerfile`

---

### FASE 4 — Browser Engine, Payload Contextual e Docker Compose

**Objetivo**: Cobrir casos que HTTP puro não consegue testar: fluxos autenticados, DOM XSS,
SPAs, CSRF em sessão ativa. Adicionar mutação inteligente de payloads por contexto de injeção.
Migrar para arquitetura de serviços com Docker Compose para suportar paralelismo real.

**Quando está concluída**: Casos DOM e autenticados são testáveis end-to-end. `docker compose up`
sobe o ambiente completo. Workers processam a exploitation_queue em paralelo por categoria.

#### 4.4.1 `core/browser_attack_engine.py`

Motor de ataque usando Playwright (já no requirements.txt):

```python
class BrowserAttackEngine:
    """
    Orquestra ataques que exigem sessão de browser:
    - DOM XSS (payload não refletido no HTML, executado via JS)
    - CSRF em fluxos autenticados
    - Stored XSS dentro de SPA que renderiza via fetch
    - Sessões com autenticação (login form → cookie session)
    """

    def __init__(self, config: BrowserConfig):
        self.headless = config.headless          # False para debug, True para CI
        self.record_video = config.record_video  # Grava MP4 como evidência
        self.credentials = config.credentials    # {"username": "x", "password": "y"}

    async def run_attack(self, item: QueueItem) -> ExploitAttempt:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self.headless)
            context = await browser.new_context(record_video_dir="data/evidencias/")
            page = await context.new_page()

            if self.credentials:
                await self._authenticate(page, item)

            result = await self._inject_and_verify(page, item)
            await context.close()
            return result

    async def _inject_and_verify(self, page, item: QueueItem) -> ExploitAttempt:
        """Injeta payload e monitora execução via console events do browser."""
        triggered = asyncio.Event()
        page.on("console", lambda msg: triggered.set() if item.marker in msg.text else None)

        await page.goto(self._build_url(item))
        try:
            await asyncio.wait_for(triggered.wait(), timeout=5.0)
            status = "impact_proven"
        except asyncio.TimeoutError:
            status = "failed"

        return ExploitAttempt(status=status, ...)
```

#### 4.4.2 `core/payload_engine.py` — Payload contextual

Payloads selecionados com base no contexto de injeção detectado na Fase 1:

```python
class PayloadEngine:
    """
    Seleciona e gera payloads com base no contexto de injeção.

    Contextos suportados:
    - HTML_BODY:   tags completas (script, img, svg, details)
    - ATTRIBUTE:   event handlers (onerror, onload, onfocus)
    - JS_STRING:   quebrar string + código ('; alert(1); //)
    - JS_TEMPLATE: template literal injection (${alert(1)})
    - URL:         protocol-based (javascript:, data:text/html)
    - CSS:         expression() para IE, url() para data exfil
    - JSON:        escape de aspas + injection
    """

    CONTEXT_PAYLOADS = {
        "HTML_BODY": [
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
        ],
        "ATTRIBUTE": [
            "\" onmouseover=\"alert(1)",
            "' onfocus='alert(1)' autofocus='",
            "\" autofocus onfocus=\"alert(1)",
        ],
        "JS_STRING": [
            "'; alert(document.domain); //",
            "\"; alert(document.domain); //",
            "`${alert(1)}`",
        ],
        # ...
    }

    def get_payloads(self, context: str, category: str) -> List[str]:
        base = self.CONTEXT_PAYLOADS.get(context, self.CONTEXT_PAYLOADS["HTML_BODY"])
        return self.mutator.mutate(base, category)
```

#### 4.4.3 `core/payload_mutator.py` — Mutações de evasão de WAF

```python
class PayloadMutator:
    """
    Aplica transformações para evasão de filtros e WAF:
    - Encoding: URL, HTML entities, Unicode
    - Case variation: <ScRiPt>
    - Null byte insertion: <scr\x00ipt>
    - Double encoding: %253C
    - Comment injection: <s/**/cript>
    - SVG obfuscation
    """

    def mutate(self, payloads: List[str], category: str) -> List[str]:
        mutated = list(payloads)  # Originais sempre inclusos
        for payload in payloads:
            mutated.extend([
                self._url_encode(payload),
                self._html_entities(payload),
                self._case_variation(payload),
                self._double_encode(payload),
            ])
        return mutated
```

#### 4.4.4 Docker Compose para arquitetura de serviços

```yaml
# docker-compose.yml
version: "3.9"

services:
  api:
    build: .
    command: python scripts/api_server.py
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
      - ./config:/app/config
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
    depends_on:
      - db
      - redis

  worker_xss:
    build: .
    command: python scripts/worker.py --category xss
    cap_add:
      - NET_RAW
    network_mode: host
    volumes:
      - ./data:/app/data
    depends_on:
      - redis

  worker_sqli:
    build: .
    command: python scripts/worker.py --category sqli
    cap_add:
      - NET_RAW
    network_mode: host
    volumes:
      - ./data:/app/data
    depends_on:
      - redis

  browser:
    build: .
    command: python scripts/browser_worker.py
    shm_size: "2gb"           # Necessário para Chromium
    volumes:
      - ./data:/app/data
    depends_on:
      - redis

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=reconforge
      - POSTGRES_USER=reconforge
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  pgdata:
```

Nessa arquitetura, `SQLite` migra para `PostgreSQL` por ser multi-processo e multi-container.
`Redis` serve como broker da exploitation_queue entre stages e workers.

**Entregáveis da Fase 4:**
- `core/browser_attack_engine.py`
- `core/payload_engine.py`
- `core/payload_mutator.py`
- `plugins/pipelines/dom_xss_pipeline.py`
- `plugins/pipelines/csrf_pipeline.py`
- `scripts/api_server.py` — API REST para submissão de alvos
- `scripts/worker.py` — worker CLI por categoria
- `scripts/browser_worker.py` — worker headless para browser attacks
- `docker-compose.yml`
- Migração de `Storage` para suportar PostgreSQL (driver alternativo)

---

### FASE 5 — Plataforma Distribuída (Docker Compose completo)

**Objetivo**: Transformar o ReconForge de ferramenta pessoal local em plataforma distribuída,
com workers assíncronos por categoria, API REST, observabilidade e deploy em servidor remoto.
Esta fase **só faz sentido após as Fases 1-4 estarem estáveis** — containerizar arquitetura
em movimento gera retrabalho desnecessário.

**Quando está concluída**: `docker compose up` sobe o ambiente completo. Workers escalam
horizontalmente. API Rest expõe o pipeline para uso remoto. Logs centralizados.

**Condição para iniciar**: Uso real mostrando gargalo de paralelismo, necessidade de deploy
remoto ou múltiplos usuários simultâneos. Se o uso continuar sendo local/pessoal, um
`Dockerfile` single-container da Fase 3 já resolve 80% dos problemas sem a complexidade
do Compose.

#### 4.5.1 Arquitetura de serviços

```
Docker Compose
  ├── api             → FastAPI — recebe alvos, expõe resultados via REST
  ├── orchestrator    → WorkflowOrchestrator gerenciando stages
  ├── worker-xss      → consome ExploitQueue categoria XSS via Redis
  ├── worker-sqli     → consome ExploitQueue categoria SQLi via Redis
  ├── worker-ssrf     → consome ExploitQueue categoria SSRF via Redis
  ├── worker-auth     → consome ExploitQueue categoria Auth via Redis
  ├── scanner         → nmap, nuclei, katana, subfinder (stage_detect)
  ├── browser         → Chromium headless isolado (BrowserAttackEngine)
  ├── postgresql      → substitui SQLite (multi-processo, sem lock contention)
  └── redis           → broker de mensagens entre stages e workers
```

#### 4.5.2 Por que PostgreSQL substitui SQLite nesta fase

| Aspecto | SQLite (Fases 1-4) | PostgreSQL (Fase 5) |
|---|---|---|
| **Concorrência** | Write lock global — workers paralelos colidem | Transações concorrentes nativas |
| **Multi-container** | Arquivo local, não compartilhável entre containers | Serviço de rede acessível por todos |
| **Escala de dados** | Adequado para uso local | Adequado para múltiplos runs simultâneos |
| **Complexidade** | Zero configuração | Requer serviço dedicado |

A migração é incremental: `Storage` recebe driver alternativo (psycopg2) com a mesma interface,
sem quebrar os módulos das Fases 1-4.

#### 4.5.3 Workers assíncronos via Redis

Cada worker é stateless e consome itens da `ExploitQueue` como mensagens Redis:

```python
# scripts/worker.py
class CategoryWorker:
    def __init__(self, category: str):
        self.category = category
        self.redis = Redis.from_url(os.environ["REDIS_URL"])
        self.executor = ExploitExecutor(...)
        self.evidence = EvidenceCollector(...)

    def run(self):
        while True:
            raw = self.redis.blpop(f"queue:{self.category}", timeout=5)
            if not raw:
                continue
            item = QueueItem.from_json(raw[1])
            attempts = self.executor.execute(item)
            self.evidence.collect(item, attempts)
```

Escalabilidade horizontal simples:
```bash
docker compose scale worker-xss=3 worker-sqli=2
```

#### 4.5.4 API REST (`scripts/api_server.py`)

Substitui o menu CLI para uso remoto:

| Endpoint | Método | Descrição |
|---|---|---|
| `/scan` | POST | Submete novo alvo, retorna `run_id` |
| `/run/{id}` | GET | Status do run + progresso por stage |
| `/run/{id}/queue` | GET | Itens da exploitation_queue com status |
| `/run/{id}/evidence` | GET | Evidências coletadas com proof_level |
| `/run/{id}/report` | GET | Relatório final (JSON ou HTML) |
| `/run/{id}/report.pdf` | GET | Relatório em PDF |

#### 4.5.5 Observabilidade

- **Logs centralizados**: todos os containers enviam para stdout estruturado (JSON), coletável por Loki ou ELK.
- **Health checks**: cada serviço expõe `/health` para o Compose detectar falhas e reiniciar automaticamente.
- **Métricas por run**: tempo por stage, itens na queue, taxa de `impact_proven` vs `partial` vs `none`.
- **Alertas**: notificação quando `proof_level=impact_proven` é atingido (webhook, Slack, email).

#### 4.5.6 Problemas que persistem mesmo na Fase 5

| Problema | Gravidade | Mitigação |
|---|---|---|
| **`--net=host` obrigatório para scans** | Alta | nmap SYN scan e raw sockets precisam da rede do host. Documentar explicitamente. |
| **`CAP_NET_RAW` no scanner container** | Alta | Privilégio elevado necessário. Container de scanner roda com mínimo de capacidades além dessa. |
| **Imagem grande** | Média | Scanner (~800MB) + browser (~1.2GB) + Python deps = 4-5GB total. Multi-stage builds reduzem. |
| **Chromium `--no-sandbox`** | Média | Exigido em Docker. Mitigado pelo isolamento do container dedicado de browser. |
| **Complexidade operacional** | Média | 8+ serviços, logs distribuídos, volumes. Justificado apenas se há necessidade real de escala. |

#### 4.5.7 Quando NÃO migrar para Fase 5

- **Uso pessoal/local isolado**: `Dockerfile` single-container da Fase 3 resolve sem overhead.
- **Ambiente sem Docker**: alguns engagements têm restrições no ambiente de execução.
- **Fases 1-4 ainda instáveis**: não containerizar arquitetura em movimento.

**Entregáveis da Fase 5:**
- `docker-compose.yml` completo com todos os serviços
- `scripts/api_server.py` — FastAPI REST
- `scripts/worker.py` — worker CLI por categoria
- `scripts/browser_worker.py` — worker headless
- Migração `Storage` → driver PostgreSQL opcional (mesma interface)
- `scripts/migrate_sqlite_to_pg.py` — migração de dados históricos
- `Dockerfile` multi-stage por serviço (api, scanner, browser, worker)
- `.env.example` com todas as variáveis de ambiente necessárias
- Documentação de deploy (`docs/DEPLOY.md`)

---

## 5. Visão geral do roadmap

```
Fase 1  ──────────────────────────────────────────────►  Fundação
        workflow_orchestrator + modelos + storage         (sem Docker)

Fase 2  ──────────────────────────────────────────────►  Qualidade de signal
        validation_gate + exploit_queue + adapters        (sem Docker)

Fase 3  ──────────────────────────────────────────────►  Exploração + Evidência
        exploit_executor + pipelines + evidence           (Dockerfile básico)
        + report orientado a prova

Fase 4  ──────────────────────────────────────────────►  Browser + Escala
        browser_engine + payload_engine + mutator         (Docker Compose inicial)
        + API + workers + PostgreSQL + Redis

Fase 5  ──────────────────────────────────────────────►  Plataforma Distribuída
        workers assíncronos + API REST + observabilidade  (Docker Compose completo)
        + PostgreSQL + Redis + deploy remoto              (somente se necessário)
```

### Preservação do código existente por fase

| Componente atual | Fase 1 | Fase 2 | Fase 3 | Fase 4 | Fase 5 |
|---|---|---|---|---|---|
| `BasePlugin` + plugins | Intacto | Intacto | Intacto | Intacto | Intacto |
| `PluginManager` | Intacto | Intacto | Intacto | Intacto | Intacto |
| `MinimalOrchestrator` | Envolvido | Envolvido | Envolvido | Opcional | Substituído por API |
| `config.py` + YAML | Intacto | Intacto | Intacto | Estendido | Estendido + env vars |
| `storage.py` (SQLite) | Estendido | Estendido | Estendido | Estendido | Driver PG opcional |
| `models.py` | Estendido | Estendido | Estendido | Estendido | Intacto |
| `report_generator.py` | Intacto | Intacto | Evoluído | Evoluído | + endpoint REST |
