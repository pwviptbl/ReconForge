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

        # Salvar resultados brutos de cada plugin para análise manual
        self._save_plugin_raw_outputs(state, run_dir)

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

    # -----------------------------------------------------------------------
    # Exportação de resultados brutos por plugin
    # -----------------------------------------------------------------------

    def _save_plugin_raw_outputs(self, state: WorkflowState, run_dir: Path) -> None:
        """
        Persiste o resultado bruto de cada plugin executado em arquivos
        individuais dentro de run_N/plugins_raw/.

        Para cada plugin são gerados dois arquivos:
          - <plugin_name>.json  →  dados completos em JSON
          - <plugin_name>.md    →  versão legível por humanos para análise manual
        """
        if not state.plugin_results:
            self.logger.info("Nenhum plugin_result disponível para exportar")
            return

        raw_dir = run_dir / "plugins_raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        # Índice de todos os plugins exportados
        index_lines: List[str] = [
            f"# Resultados Brutos dos Plugins — Run {state.run_id}\n",
            f"**Alvo:** `{state.target}`  \n",
            f"**Plugins executados:** {len(state.plugin_results)}  \n",
            f"**Gerado em:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  \n",
            "\n---\n",
            "| Plugin | Status | Arquivo JSON | Arquivo MD |",
            "|--------|--------|--------------|------------|",
        ]

        for plugin_name, raw_result in state.plugin_results.items():
            try:
                # Garantir que temos um dicionário
                if hasattr(raw_result, "to_dict"):
                    result_dict = raw_result.to_dict()
                elif isinstance(raw_result, dict):
                    result_dict = raw_result
                else:
                    result_dict = {"raw": str(raw_result)}

                # --- JSON bruto completo ---
                json_file = raw_dir / f"{plugin_name}.json"
                json_file.write_text(
                    json.dumps(result_dict, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )

                # --- Markdown legível para análise manual ---
                md_file = raw_dir / f"{plugin_name}.md"
                md_content = self._build_plugin_md(plugin_name, result_dict, state.target)
                md_file.write_text(md_content, encoding="utf-8")

                success = result_dict.get("success", True)
                status_icon = "✅" if success else "❌"
                index_lines.append(
                    f"| {plugin_name} | {status_icon} | "
                    f"`plugins_raw/{plugin_name}.json` | "
                    f"`plugins_raw/{plugin_name}.md` |"
                )

            except Exception as exc:
                self.logger.warning(f"Falha ao exportar raw output de {plugin_name}: {exc}")
                index_lines.append(f"| {plugin_name} | ⚠️ erro | - | - |")

        # Salvar índice
        index_path = raw_dir / "_index.md"
        index_path.write_text("\n".join(index_lines), encoding="utf-8")
        self.logger.info(
            f"Resultados brutos de {len(state.plugin_results)} plugins "
            f"salvos em: {raw_dir}"
        )

    def _build_plugin_md(self, plugin_name: str, data: Dict[str, Any], target: str) -> str:
        """
        Constrói um documento Markdown legível com os dados brutos de um plugin.
        Formata campos comuns de forma estruturada e preserva saídas textuais
        (ex: saída CLI do nmap, nuclei, etc.) em blocos de código.
        """
        lines: List[str] = [
            f"# Resultado Bruto — {plugin_name}\n",
            f"**Alvo:** `{target}`  \n",
            f"**Plugin:** `{plugin_name}`  \n",
            f"**Gerado em:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  \n",
        ]

        # Status e tempo de execução
        success = data.get("success")
        exec_time = data.get("execution_time")
        error = data.get("error")
        if success is not None:
            lines.append(f"**Status:** {'✅ Sucesso' if success else '❌ Falhou'}  \n")
        if exec_time is not None:
            lines.append(f"**Tempo de execução:** {exec_time:.2f}s  \n")
        if error:
            lines.append(f"\n> ⚠️ **Erro:** {error}\n")

        lines.append("\n---\n")

        # Conteúdo principal — vem em data['data'] se vier de PluginResult.to_dict()
        payload: Dict[str, Any] = data.get("data", data)

        # --- Saídas textuais de ferramentas CLI ---
        raw_output = payload.get("raw_output") or payload.get("stdout") or payload.get("output")
        if raw_output and str(raw_output).strip():
            lines.append("## 📄 Saída Bruta (CLI / Ferramenta)\n")
            lines.append("```text")
            lines.append(str(raw_output).strip())
            lines.append("```\n")

        # Stderr / erros da ferramenta
        stderr = payload.get("stderr") or payload.get("errors")
        if stderr and str(stderr).strip():
            lines.append("## ⚠️ Stderr / Erros da Ferramenta\n")
            lines.append("```text")
            lines.append(str(stderr).strip())
            lines.append("```\n")

        # --- Hosts / Portas (nmap, port_scanner, etc.) ---
        hosts = payload.get("hosts", [])
        if hosts:
            lines.append(f"## 🖥️ Hosts Detectados ({len(hosts)})\n")
            for host in hosts:
                if isinstance(host, dict):
                    ip = host.get("ip", "?")
                    status = host.get("status", "?")
                    hostnames = ", ".join(host.get("hostnames", []))
                    os_info = host.get("os_detection", {})
                    lines.append(f"### {ip} ({status})")
                    if hostnames:
                        lines.append(f"- **Hostnames:** {hostnames}")
                    if os_info:
                        os_name = os_info.get("name", "?")
                        os_acc = os_info.get("accuracy", "?")
                        lines.append(f"- **OS detectado:** {os_name} (accuracy: {os_acc}%)")
                    # Portas do host
                    ports = host.get("ports", [])
                    if ports:
                        lines.append("")
                        lines.append("| Porta | Proto | Estado | Serviço | Versão |")
                        lines.append("|-------|-------|--------|---------|--------|") 
                        for p in ports:
                            state_p = p.get("state", "?")
                            svc = p.get("service", "?")
                            ver = p.get("version", "") or p.get("product", "")
                            proto = p.get("protocol", "tcp")
                            lines.append(
                                f"| {p.get('port', '?')} | {proto} | {state_p} | {svc} | {ver} |"
                            )
                        # Scripts NSE
                        for p in ports:
                            scripts = p.get("scripts", [])
                            if scripts:
                                lines.append(f"\n**Scripts NSE — porta {p.get('port')}:**")
                                for script in scripts:
                                    sid = script.get("id", "?")
                                    sout = script.get("output", "").strip()
                                    lines.append(f"\n*{sid}:*")
                                    if sout:
                                        lines.append("```")
                                        lines.append(sout)
                                        lines.append("```")
                else:
                    lines.append(f"- {host}")
            lines.append("")

        # --- Portas abertas (lista plana) ---
        open_ports = payload.get("open_ports", [])
        if open_ports:
            ports_str = ", ".join(str(p) for p in sorted(
                set(int(p) for p in open_ports if str(p).isdigit())
            ))
            lines.append(f"## 🔓 Portas Abertas\n\n`{ports_str}`\n")

        # --- Serviços ---
        services = payload.get("services", [])
        if services:
            lines.append(f"## 🔧 Serviços Detectados ({len(services)})\n")
            lines.append("| Host | Porta | Proto | Serviço | Versão |")
            lines.append("|------|-------|-------|---------|--------|") 
            for svc in services:
                if isinstance(svc, dict):
                    lines.append(
                        f"| {svc.get('host','?')} | {svc.get('port','?')} "
                        f"| {svc.get('protocol','tcp')} | {svc.get('service','?')} "
                        f"| {svc.get('version','') or svc.get('product','')} |"
                    )
            lines.append("")

        # --- Vulnerabilidades encontradas pelo plugin ---
        vulns = payload.get("vulnerabilities", [])
        if vulns:
            lines.append(f"## 🔴 Vulnerabilidades Reportadas pelo Plugin ({len(vulns)})\n")
            for v in vulns:
                if isinstance(v, dict):
                    title = v.get("title") or v.get("name") or v.get("id", "?")
                    sev = v.get("severity", "?")
                    cvss = v.get("cvss") or v.get("score", "")
                    cve = v.get("cve", "")
                    host_v = v.get("host", "")
                    port_v = v.get("port", "")
                    desc = v.get("description") or v.get("output", "")
                    url_v = v.get("url", "")
                    exploit_flag = v.get("exploit", False)
                    lines.append(f"### {title}")
                    lines.append(f"- **Severidade:** {sev}")
                    if cvss:
                        lines.append(f"- **CVSS:** {cvss}")
                    if cve:
                        lines.append(f"- **CVE:** [{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
                    if host_v:
                        lines.append(f"- **Host:** {host_v}:{port_v}")
                    if url_v:
                        lines.append(f"- **Referência:** {url_v}")
                    if exploit_flag:
                        lines.append("- **⚠️ Exploit público disponível**")
                    if desc:
                        lines.append(f"- **Detalhe:** {str(desc)[:500]}")
                    lines.append("")

        # --- Findings (plugins de detecção web) ---
        findings = payload.get("findings", [])
        if findings:
            lines.append(f"## 🎯 Findings do Plugin ({len(findings)})\n")
            lines.append("| Severidade | Nome | URL | Parâmetro | Payload |")
            lines.append("|------------|------|-----|-----------|---------|")
            for f in findings:
                if isinstance(f, dict):
                    sev = f.get("severity", "-")
                    name = f.get("name") or f.get("title", "-")
                    url_f = f.get("url") or f.get("endpoint", "-")
                    param = f.get("parameter") or f.get("param", "-")
                    payload_f = str(f.get("payload") or f.get("evidence", "-"))[:80]
                    lines.append(f"| {sev} | {name} | `{url_f}` | `{param}` | `{payload_f}` |")
            lines.append("")

        # --- Subdomínios ---
        subdomains = payload.get("subdomains", [])
        if subdomains:
            lines.append(f"## 🌐 Subdomínios ({len(subdomains)})\n")
            for sub in subdomains:
                lines.append(f"- `{sub}`")
            lines.append("")

        # --- Endpoints / URLs ---
        endpoints = payload.get("endpoints", []) or payload.get("urls", [])
        if endpoints:
            lines.append(f"## 🔗 Endpoints/URLs ({len(endpoints)})\n")
            for ep in endpoints[:200]:  # Limitar a 200 para não gerar arquivo gigante
                url_ep = ep.get("url") if isinstance(ep, dict) else str(ep)
                lines.append(f"- `{url_ep}`")
            if len(endpoints) > 200:
                lines.append(f"\n*... e mais {len(endpoints) - 200} endpoints (ver arquivo JSON)*")
            lines.append("")

        # --- Tecnologias ---
        technologies = payload.get("technologies", [])
        if technologies:
            lines.append(f"## 💻 Tecnologias Detectadas ({len(technologies)})\n")
            for tech in technologies:
                if isinstance(tech, dict):
                    name_t = tech.get("name", "?")
                    ver_t = tech.get("version", "")
                    cat_t = tech.get("category", "")
                    lines.append(f"- **{name_t}** {ver_t} _{cat_t}_")
                else:
                    lines.append(f"- {tech}")
            lines.append("")

        # --- Headers HTTP (HeaderAnalyzerPlugin) ---
        headers = payload.get("headers") or payload.get("response_headers", {})
        if headers and isinstance(headers, dict):
            lines.append("## 📋 Headers HTTP Analisados\n")
            lines.append("| Header | Valor |")
            lines.append("|--------|-------|") 
            for k, v in headers.items():
                v_str = str(v).replace("|", "/")[:120]
                lines.append(f"| `{k}` | {v_str} |")
            lines.append("")

        # --- Probe Log (tentativas de ataque detalhadas) ---
        probe_log = payload.get("probe_log", [])
        probe_summary = payload.get("probe_summary", {})
        if probe_log:
            total_p = probe_summary.get("total", len(probe_log))
            hits_p = probe_summary.get("hits", sum(1 for p in probe_log if p.get("hit")))
            lines.append(f"## 🧪 Log de Tentativas (Probe Log) — {total_p} requests | {hits_p} hits\n")

            # Separar hits dos demais
            hits = [p for p in probe_log if p.get("hit")]
            misses = [p for p in probe_log if not p.get("hit")]

            if hits:
                lines.append(f"### ✅ Hits Encontrados ({len(hits)})\n")
                for p in hits:
                    status = p.get("status_code", "?")
                    rlen = p.get("response_length", "?")
                    lines.append(f"**{p.get('method','?')} {p.get('url','')}**")
                    lines.append(f"- **Parâmetro:** `{p.get('param','')}` | **Localização:** `{p.get('location','')}`")
                    lines.append(f"- **Payload:** `{p.get('payload','')}`")
                    lines.append(f"- **Status:** `{status}` | **Tamanho resposta:** {rlen} bytes")
                    rh = p.get("response_headers", {})
                    if rh:
                        rh_str = " | ".join(f"`{k}: {v}`" for k, v in list(rh.items())[:5])
                        lines.append(f"- **Headers resposta:** {rh_str}")
                    snippet = p.get("response_snippet", "")
                    if snippet:
                        lines.append("- **Snippet da resposta (contexto do hit):**")
                        lines.append("```html")
                        lines.append(snippet[:800])
                        lines.append("```")
                    lines.append("")

            # Tabela resumo de todos os probes (hits + misses)
            lines.append(f"### 📋 Todas as Tentativas ({len(probe_log)} probes)\n")
            lines.append("| Método | URL | Parâmetro | Payload | Status | Bytes | Hit |")
            lines.append("|--------|-----|-----------|---------|--------|-------|-----|")
            for p in probe_log:
                url_short = p.get("url", "")
                if len(url_short) > 80:
                    url_short = url_short[:77] + "..."
                payload_short = str(p.get("payload", ""))
                if len(payload_short) > 50:
                    payload_short = payload_short[:47] + "..."
                hit_icon = "✅" if p.get("hit") else "—"
                status = p.get("status_code", "err")
                rlen = p.get("response_length", "?")
                lines.append(
                    f"| `{p.get('method','?')}` | `{url_short}` "
                    f"| `{p.get('param','')}` | `{payload_short}` "
                    f"| {status} | {rlen} | {hit_icon} |"
                )
            lines.append("")

        # --- Dados adicionais não cobertos acima ---
        # Campos que não foram tratados explicitamente — dump resumido
        campos_tratados = {
            "success", "execution_time", "error", "data", "plugin_name", "timestamp",
            "summary", "raw_output", "stdout", "stderr", "output", "errors",
            "hosts", "open_ports", "services", "vulnerabilities", "findings",
            "subdomains", "endpoints", "urls", "technologies", "headers",
            "response_headers", "target", "scan_type",
            "probe_log", "probe_summary", "tested_count",
        }
        extras = {k: v for k, v in payload.items() if k not in campos_tratados and v}
        if extras:
            lines.append("## 📦 Dados Adicionais\n")
            for k, v in extras.items():
                if isinstance(v, (list, dict)):
                    lines.append(f"**{k}** ({type(v).__name__}, {len(v)} itens):")
                    lines.append("```json")
                    try:
                        snippet = json.dumps(v, ensure_ascii=False, default=str, indent=2)
                        # Limitar a 2000 chars por campo
                        if len(snippet) > 2000:
                            snippet = snippet[:2000] + "\n... (truncado — ver JSON completo)"
                        lines.append(snippet)
                    except Exception:
                        lines.append(str(v)[:500])
                    lines.append("```")
                else:
                    lines.append(f"**{k}:** {str(v)[:300]}")
            lines.append("")

        return "\n".join(lines)
