"""
StageReport — Fase 3

Gera o relatório final orientado a evidências, diferenciando claramente:

    CONFIRMADAS    (proof_level = impact_proven)
    POTENCIAIS     (proof_level = partial)
    SEM PROVA      (proof_level = none)
    DESCARTADAS    (rejected_findings do ValidationGate)

Gera arquivo Markdown em data/relatorios/run_<id>/<alvo>_<timestamp>.md
e atualiza state.report_path.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import Evidence, Finding, QueueItem
from core.stage_base import StageBase
from core.workflow_state import WorkflowState
from utils.ai_reporter import AIReportGenerator, AIReportResult
from utils.web_map import build_web_map_payload


class StageReport(StageBase):
    """
    Estágio 7: Geração do relatório final.

    Gera Markdown com seções estruturadas por nível de prova e
    persiste em data/relatorios/run_<id>/.
    """

    name = "stage_report"

    def __init__(self, output_dir: Optional[Path] = None, storage=None):
        super().__init__()
        self._output_dir = output_dir or Path("data") / "relatorios"
        self._storage = storage

    def execute(self, state: WorkflowState) -> WorkflowState:
        self._output_dir.mkdir(parents=True, exist_ok=True)

        ai_report = self._build_ai_report(state)
        report_md = self._build_report(state, ai_report)

        # Salvar arquivo
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_target = state.target.replace("/", "_").replace(":", "_").replace(".", "_")
        run_dir = self._output_dir / f"run_{state.run_id}"
        run_dir.mkdir(parents=True, exist_ok=True)

        md_path = run_dir / f"{safe_target}_{ts}.md"
        md_path.write_text(report_md, encoding="utf-8")

        state.report_path = str(md_path.resolve())
        state.plugin_states["ai_report"] = {
            "generated": ai_report.generated,
            "provider": ai_report.provider,
            "model": ai_report.model,
            "skipped_reason": ai_report.skipped_reason,
            "error": ai_report.error,
        }
        self.logger.info(f"Relatório gerado: {state.report_path}")

        # Também salvar JSON estruturado
        json_path = run_dir / f"{safe_target}_{ts}.json"
        self._save_json_report(state, json_path)

        return state

    def gate_passes(self, state: WorkflowState) -> bool:
        return True  # Relatório sempre roda

    # -----------------------------------------------------------------------
    # Construção do relatório Markdown
    # -----------------------------------------------------------------------

    def _build_ai_report(self, state: WorkflowState) -> AIReportResult:
        result = AIReportGenerator().generate_for_state(state)
        if result.generated:
            self.logger.info(
                "Relatório IA gerado com sucesso "
                f"| provider={result.provider} | model={result.model}"
            )
        elif result.error:
            self.logger.warning(
                "Falha ao gerar relatório IA; mantendo relatório técnico atual "
                f"| provider={result.provider} | model={result.model} | erro={result.error}"
            )
        return result

    def _build_report(self, state: WorkflowState, ai_report: AIReportResult) -> str:
        sections: List[str] = []

        sections.append(self._section_header(state))

        sections.append("---\n\n# 💼 PARTE EXECUTIVA\n")
        sections.append(self._section_ai(ai_report))
        sections.append(self._section_summary(state))

        sections.append("---\n\n# 🛠️ PARTE TÉCNICA E DADOS BRUTOS\n")
        sections.append(self._section_confirmed(state))
        sections.append(self._section_partial(state))
        sections.append(self._section_queued(state))
        sections.append(self._section_no_proof(state))
        sections.append(self._section_rejected(state))
        sections.append(self._section_recon(state))
        sections.append(self._section_web_mapping(state))
        sections.append(self._section_stages(state))

        return "\n\n".join(s for s in sections if s)

    def _section_ai(self, ai_report: AIReportResult) -> str:
        if not ai_report.generated or not ai_report.text:
            return ""
        return ai_report.text.strip()

    def _section_header(self, state: WorkflowState) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return (
            f"# Relatório de Segurança — ReconForge\n\n"
            f"**Alvo:** `{state.target}`  \n"
            f"**Run ID:** `{state.run_id}`  \n"
            f"**Data:** {now}  \n"
            f"**Modo:** Pipeline (Fase 3)  \n"
        )

    def _section_summary(self, state: WorkflowState) -> str:
        confirmed = [e for e in state.evidences if e.proof_level == "impact_proven"]
        partial_evs = [e for e in state.evidences if e.proof_level == "partial"]
        none_evs = [e for e in state.evidences if e.proof_level == "none"]
        discoveries = state.discoveries

        risk_level = (
            "🔴 CRÍTICO" if confirmed else
            "🟠 ALTO" if partial_evs else
            "🟡 MÉDIO" if state.findings else
            "🟢 BAIXO"
        )

        lines = [
            "## Resumo Executivo\n",
            f"| Campo | Valor |",
            f"|-------|-------|",
            f"| Nível de Risco | **{risk_level}** |",
            f"| Findings detectados | {len(state.findings) + len(state.rejected_findings)} |",
            f"| Findings validados | {len(state.findings)} |",
            f"| Findings descartados | {len(state.rejected_findings)} |",
            f"| Items na queue | {len(state.queue_items)} |",
            f"| Tentativas de exploit | {len(state.attempts)} |",
            f"| Vulnerabilidades confirmadas | **{len(confirmed)}** |",
            f"| Vulnerabilidades potenciais | {len(partial_evs)} |",
            f"| Sem confirmação | {len(none_evs)} |",
            f"| Hosts descobertos | {len(discoveries.get('hosts', []))} |",
            f"| Portas abertas | {len(discoveries.get('open_ports', []))} |",
            f"| Endpoints mapeados | {len(discoveries.get('endpoints', []))} |",
            f"| Formulários mapeados | {len(discoveries.get('forms', []))} |",
            f"| Requests observadas | {len(discoveries.get('request_nodes', []))} |",
            f"| Interações UI | {len(discoveries.get('interactions', []))} |",
        ]
        return "\n".join(lines)

    def _section_confirmed(self, state: WorkflowState) -> str:
        confirmed_evs = [e for e in state.evidences if e.proof_level == "impact_proven"]
        if not confirmed_evs:
            return ""

        items_by_id = {i.id: i for i in state.queue_items}
        findings_by_id = {f.id: f for f in state.findings + state.rejected_findings}

        lines = [
            "## ✅ Vulnerabilidades Confirmadas (Impacto Provado)\n",
            "> Estas vulnerabilidades foram exploradas com sucesso — **ação imediata recomendada**.\n",
        ]

        for ev in confirmed_evs:
            item = items_by_id.get(ev.queue_item_id)
            if not item:
                continue
            finding = findings_by_id.get(item.finding_id)

            lines.append(f"### [{item.category.upper()}] {item.endpoint}")
            lines.append(f"- **Parâmetro:** `{item.parameter}`")
            if item.candidate_payload:
                lines.append(f"- **Payload:** `{item.candidate_payload}`")
            lines.append(f"- **Método:** `{item.method}`")
            lines.append(f"- **Contexto:** `{item.context}`")
            lines.append(f"- **Pipeline:** `{item.assigned_executor}`")
            if finding:
                lines.append(f"- **Plugin origem:** `{finding.detection_source}`")
                lines.append(f"- **Confidence:** `{finding.confidence_score:.0%}`")
            lines.append(f"\n**Impacto:** {ev.impact_summary}")

            if ev.artifacts:
                lines.append(f"\n**Artefatos:**")
                for art in ev.artifacts:
                    lines.append(f"  - `{art}`")
            lines.append("")

        return "\n".join(lines)

    def _section_partial(self, state: WorkflowState) -> str:
        partial_evs = [e for e in state.evidences if e.proof_level == "partial"]
        if not partial_evs:
            return ""

        items_by_id = {i.id: i for i in state.queue_items}

        lines = [
            "## 🟡 Vulnerabilidades Potenciais (Confirmação Manual Necessária)\n",
            "> Payload refletido / comportamento anômalo detectado mas impacto não foi provado automaticamente.\n",
        ]

        for ev in partial_evs:
            item = items_by_id.get(ev.queue_item_id)
            if not item:
                continue
            lines.append(f"### [{item.category.upper()}] {item.endpoint}")
            lines.append(f"- **Parâmetro:** `{item.parameter}`  |  **Método:** `{item.method}`")
            if item.candidate_payload:
                lines.append(f"- **Payload:** `{item.candidate_payload}`")
            lines.append(f"- **Sumário/Resultado:** {ev.impact_summary}")
            if ev.artifacts:
                lines.append(f"- **Log:** `{ev.artifacts[0]}`")
            lines.append("")

        return "\n".join(lines)

    def _section_queued(self, state: WorkflowState) -> str:
        ev_queue_ids = {e.queue_item_id for e in state.evidences}
        queued_items = [i for i in state.queue_items if i.id not in ev_queue_ids]
        
        if not queued_items:
            return ""

        lines = [
            "## 🔵 Findings Validados (Aguardando Teste / Sem Exploit Bem-Sucedido)\n",
            "Estes findings passaram pela triagem, mas ainda não tiveram impacto provado.\n",
            "| Categoria | Endpoint | Parâmetro | Payload | Prioridade |",
            "|-----------|----------|-----------|---------|------------|",
        ]

        for item in queued_items:
            payload = item.candidate_payload.replace('|', '&#124;') if item.candidate_payload else "-"
            lines.append(f"| {item.category} | `{item.endpoint}` | `{item.parameter}` | `{payload}` | {item.priority} |")

        return "\n".join(lines)

    def _section_no_proof(self, state: WorkflowState) -> str:
        none_evs = [e for e in state.evidences if e.proof_level == "none"]
        if not none_evs:
            return ""

        items_by_id = {i.id: i for i in state.queue_items}
        lines = [
            "## ⚪ Findings Sem Confirmação\n",
            "| Categoria | Endpoint | Parâmetro | Payload | Resultado |",
            "|-----------|----------|-----------|---------|-----------|",
        ]

        for ev in none_evs:
            item = items_by_id.get(ev.queue_item_id)
            if not item:
                continue
            payload = item.candidate_payload.replace('|', '&#124;') if item.candidate_payload else "-"
            summary = ev.impact_summary.replace("|", "/")
            lines.append(f"| {item.category} | `{item.endpoint}` | `{item.parameter}` | `{payload}` | {summary} |")

        return "\n".join(lines)

    def _section_rejected(self, state: WorkflowState) -> str:
        rejected = state.rejected_findings
        if not rejected:
            return ""

        lines = [
            "## 🔴 Findings Descartados (ValidationGate)\n",
            "| Categoria | Endpoint | Parâmetro | Payload | Motivo |",
            "|-----------|----------|-----------|---------|--------|",
        ]

        for f in rejected:
            payload = f.candidate_payload.replace('|', '&#124;') if f.candidate_payload else "-"
            motivo = f.raw_evidence.replace('|', '/') if f.raw_evidence else "threshold"
            lines.append(
                f"| {f.category} | `{f.endpoint}` | `{f.parameter}` | `{payload}` | {motivo} |"
            )

        return "\n".join(lines)

    def _section_recon(self, state: WorkflowState) -> str:
        d = state.discoveries
        hosts = d.get("hosts", [])
        ports = d.get("open_ports", [])
        techs = d.get("technologies", [])
        subdomains = d.get("subdomains", [])
        forms = d.get("forms", [])
        endpoints = d.get("endpoints", [])
        request_nodes = d.get("request_nodes", [])
        interactions = d.get("interactions", [])

        if not (hosts or ports or techs or subdomains or forms or request_nodes or interactions or endpoints):
            return ""

        lines = ["## 🔍 Descobertas de Reconhecimento\n"]

        if hosts:
            lines.append(f"**Hosts:** {', '.join(str(h) for h in hosts)}")

        if ports:
            ports_str = ", ".join(str(p) for p in sorted(set(int(p) for p in ports if str(p).isdigit())))
            lines.append(f"\n**Portas abertas:** {ports_str}")

        if techs:
            tech_names = []
            for t in techs:
                name = t.get("name") if isinstance(t, dict) else str(t)
                if name and name not in tech_names:
                    tech_names.append(name)
            lines.append(f"\n**Tecnologias:** {', '.join(tech_names)}")

        if subdomains:
            lines.append(f"\n**Subdomínios:** {', '.join(str(s) for s in subdomains)}")

        if forms or request_nodes or interactions:
            lines.append(
                "\n**Entradas Web Mapeadas:** "
                f"forms={len(forms)}, requests={len(request_nodes)}, interactions={len(interactions)}"
            )

        if endpoints:
            lines.append(f"\n**Endpoints Mapeados ({len(endpoints)}):**")
            for ep in endpoints:
                url = ep["url"] if isinstance(ep, dict) and "url" in ep else str(ep)
                lines.append(f"- `{url}`")

        return "\n".join(lines)

    def _section_stages(self, state: WorkflowState) -> str:
        if not state.stage_statuses:
            return ""

        lines = [
            "## 📋 Status dos Estágios\n",
            "| Estágio | Status | Métricas |",
            "|---------|--------|----------|",
        ]

        for stage_name, st in state.stage_statuses.items():
            status = st.status
            metrics = dict(st.metrics or {})
            if stage_name == self.name and status == "running":
                status = "done"
                metrics = self._collect_metrics(state)
            icon = {"done": "✅", "error": "❌", "skipped": "⏭"}.get(status, "•")
            metrics_str = json.dumps(metrics, ensure_ascii=False)[:80] if metrics else "{}"
            lines.append(f"| {stage_name} | {icon} {status} | {metrics_str} |")

        return "\n".join(lines)

    def _section_web_mapping(self, state: WorkflowState) -> str:
        web_map = build_web_map_payload(state.discoveries)
        parameter_buckets = web_map.get("parameter_buckets", {})
        forms = web_map.get("forms", [])
        requests = web_map.get("requests", [])

        if not any(parameter_buckets.values()) and not forms and not requests:
            return ""

        lines = ["## 🌐 Rotas e Parâmetros Mapeados\n"]

        if any(parameter_buckets.values()):
            lines.extend([
                "| Bucket | Parâmetros |",
                "|--------|------------|",
            ])
            for bucket, names in parameter_buckets.items():
                if not names:
                    continue
                lines.append(f"| {bucket} | {', '.join(names)} |")

        if forms:
            lines.extend([
                "\n**Formulários detectados**",
                "",
                "| Método | Página | Action | Campos |",
                "|--------|--------|--------|--------|",
            ])
            for form in forms:
                lines.append(
                    f"| {form['method']} | `{form['page']}` | `{form['action']}` | {', '.join(form['fields']) or '-'} |"
                )

        if requests:
            lines.extend([
                "\n**Requests observadas com parâmetros**",
                "",
                "| Método | URL | Parâmetros | Ação UI |",
                "|--------|-----|------------|---------|",
            ])
            for request in requests:
                action = request["action"] or "-"
                params = ", ".join(request["parameter_names"]) or "-"
                lines.append(
                    f"| {request['method']} | `{request['url']}` | {params} | {action} |"
                )

        return "\n".join(lines)

    # -----------------------------------------------------------------------
    # Relatório JSON estruturado
    # -----------------------------------------------------------------------

    def _save_json_report(self, state: WorkflowState, json_path: Path) -> None:
        confirmed = [e for e in state.evidences if e.proof_level == "impact_proven"]
        partial_evs = [e for e in state.evidences if e.proof_level == "partial"]
        discoveries = state.discoveries
        web_map = build_web_map_payload(discoveries)
        parameter_buckets = web_map.get("parameter_buckets", {})
        parameter_summary = {bucket: len(values) for bucket, values in parameter_buckets.items()}
        forms = web_map.get("forms", [])
        requests = web_map.get("requests", [])
        stage_statuses = {k: v.to_dict() for k, v in state.stage_statuses.items()}
        report_stage = stage_statuses.get(self.name)
        if report_stage and report_stage.get("status") == "running":
            report_stage = dict(report_stage)
            report_stage["status"] = "done"
            report_stage["finished_at"] = datetime.now(timezone.utc).isoformat()
            report_stage["metrics"] = self._collect_metrics(state)
            stage_statuses[self.name] = report_stage

        report_data = {
            "run_id": state.run_id,
            "target": state.target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "executed_plugins": list(state.executed_plugins),
            "ai_report": dict(state.plugin_states.get("ai_report", {})),
            "summary": {
                "findings_total": len(state.findings) + len(state.rejected_findings),
                "findings_validated": len(state.findings),
                "findings_rejected": len(state.rejected_findings),
                "queue_items": len(state.queue_items),
                "attempts": len(state.attempts),
                "confirmed": len(confirmed),
                "partial": len(partial_evs),
            },
            "discovery_summary": {
                "hosts": len(discoveries.get("hosts", [])),
                "open_ports": len(discoveries.get("open_ports", [])),
                "endpoints": len(discoveries.get("endpoints", [])),
                "forms": len(forms),
                "request_nodes": len(discoveries.get("request_nodes", [])),
                "interesting_requests": len(requests),
                "interactions": len(discoveries.get("interactions", [])),
                "parameter_buckets": parameter_summary,
            },
            "web_mapping": {
                "parameter_buckets": parameter_buckets,
                "forms": forms,
                "requests": requests,
            },
            "confirmed_evidences": [
                {
                    **e.to_dict(),
                    "queue_item": next(
                        (i.to_dict() for i in state.queue_items if i.id == e.queue_item_id), {}
                    ),
                }
                for e in confirmed
            ],
            "partial_evidences": [e.to_dict() for e in partial_evs],
            "stage_statuses": stage_statuses,
        }

        try:
            json_path.write_text(
                json.dumps(report_data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            self.logger.info(f"JSON report: {json_path}")
        except Exception as exc:
            self.logger.warning(f"Falha ao salvar JSON report: {exc}")

    def _collect_metrics(self, state: WorkflowState) -> Dict[str, Any]:
        ai_meta = dict(state.plugin_states.get("ai_report", {}))
        return {
            "report_path": state.report_path or "",
            "confirmed": sum(1 for e in state.evidences if e.proof_level == "impact_proven"),
            "partial": sum(1 for e in state.evidences if e.proof_level == "partial"),
            "ai_report_generated": bool(ai_meta.get("generated", False)),
        }
