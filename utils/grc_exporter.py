"""
Exportador de resultados do ReconForge para o Bastion Cyber / GRC Intelligence System.

Transforma o WorkflowState do ReconForge em um formato JSON estruturado
que é diretamente ingerido pelo parser nativo do GRC, alimentando:
- Achados (Findings) desduplicados
- Postura de Segurança e cálculo de Score
- Rastreamento de SLA de Correção e Regressões
- Evidências perimétricas (Portas abertas e Tecnologias)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.workflow_state import WorkflowState


def map_category_to_cwe(category: str) -> Optional[str]:
    """Mapeia categoria do ReconForge para ID CWE padrão."""
    cat = (category or "").lower().strip()
    mapping = {
        "sqli": "CWE-89",
        "xss": "CWE-79",
        "ssrf": "CWE-918",
        "lfi": "CWE-22",
        "rfi": "CWE-98",
        "rce": "CWE-78",
        "command_injection": "CWE-78",
        "idor": "CWE-639",
        "auth": "CWE-287",
        "csrf": "CWE-352",
        "open_redirect": "CWE-601",
        "file_upload": "CWE-434",
        "traversal": "CWE-22",
        "cors": "CWE-942",
        "ssl": "CWE-295",
        "disclosure": "CWE-200",
    }
    return mapping.get(cat)


def map_category_to_severity(category: str, proof_level: str) -> str:
    """Calcula a severidade baseada na categoria e nível de prova obtido."""
    cat = (category or "").lower().strip()
    
    # Se teve exploração comprovada (impact_proven)
    if proof_level == "impact_proven":
        if cat in ("sqli", "rce", "command_injection", "ssrf", "lfi", "file_upload", "auth"):
            return "critico"
        elif cat in ("idor", "xss", "csrf"):
            return "alto"
        return "medio"
    
    # Se é potencial / parcial
    if cat in ("sqli", "rce", "ssrf"):
        return "alto"
    elif cat in ("xss", "lfi", "idor", "auth"):
        return "medio"
    
    return "baixo"


def map_category_to_cvss(category: str, severity: str) -> float:
    """Sugere score CVSS base aproximado."""
    sev_map = {
        "critico": 9.5,
        "alto": 7.8,
        "medio": 5.4,
        "baixo": 3.1,
        "informativo": 0.0,
    }
    return sev_map.get(severity, 5.0)


def build_grc_payload(state: WorkflowState, ai_summary: str = "") -> Dict[str, Any]:
    """
    Constrói o dicionário estruturado para consumo no GRC / Bastion Cyber.
    """
    items_by_id = {item.id: item for item in state.queue_items}
    findings_by_id = {f.id: f for f in state.findings + state.rejected_findings}
    
    grc_findings: List[Dict[str, Any]] = []
    
    # 1. Processa Evidências Confirmadas e Parciais (Mais importantes)
    processed_queue_ids = set()
    for ev in state.evidences:
        if ev.proof_level not in ("impact_proven", "partial"):
            continue
            
        item = items_by_id.get(ev.queue_item_id)
        if not item:
            continue
            
        processed_queue_ids.add(item.id)
        raw_finding = findings_by_id.get(item.finding_id)
        
        category = (item.category or "vulnerability").upper()
        severity = map_category_to_severity(item.category, ev.proof_level)
        cwe_id = map_category_to_cwe(item.category)
        cvss = map_category_to_cvss(item.category, severity)
        
        titulo = f"[{category}] Vulnerabilidade em {item.endpoint or state.target}"
        if item.parameter:
            titulo += f" (parâmetro: {item.parameter})"
            
        status_text = "Confirmada com prova de impacto" if ev.proof_level == "impact_proven" else "Potencial / Parcial"
        desc = (
            f"Vulnerabilidade do tipo {category} identificada pelo ReconForge durante varredura automatizada.\n\n"
            f"Status de Validação: {status_text}\n"
            f"Impacto Observado: {ev.impact_summary or 'Comportamento anômalo detectado.'}\n"
            f"Contexto: {item.context or 'N/A'}"
        )
        
        poc_parts = []
        if item.candidate_payload:
            poc_parts.append(f"Payload utilizado:\n{item.candidate_payload}")
        if raw_finding and raw_finding.raw_evidence:
            poc_parts.append(f"Evidência de resposta:\n{raw_finding.raw_evidence[:800]}")
        if ev.artifacts:
            poc_parts.append("Artefatos / Logs:\n" + "\n".join(f"- {a}" for a in ev.artifacts))
            
        poc = "\n\n".join(poc_parts) if poc_parts else None
        
        remediation = (
            f"Aplicar validação e sanitização estrita no parâmetro '{item.parameter}' e codificação de saída apropriada.\n"
            f"Consultar diretrizes OWASP e referências {cwe_id or 'de desenvolvimento seguro'}."
        )
        
        grc_findings.append({
            "titulo": titulo,
            "descricao": desc,
            "severidade": severity,
            "cvss_score": cvss,
            "cve_id": None,
            "cwe_id": cwe_id,
            "endpoint": item.endpoint or state.target,
            "parametro": item.parameter or None,
            "metodo_http": item.method or "GET",
            "prova_conceito": poc,
            "remediacao_sugerida": remediation,
            "proof_level": ev.proof_level,
            "confidence": getattr(raw_finding, "confidence_score", 0.9),
        })

    # 2. Processa Findings validados que não foram pra fila de exploit (ou aguardando)
    for f in state.findings:
        # Se já foi processado via evidência, pula
        matching_items = [i for i in state.queue_items if i.finding_id == f.id]
        if any(i.id in processed_queue_ids for i in matching_items):
            continue
            
        category = (f.category or "Achado").upper()
        severity = "medio" if f.category in ("sqli", "rce", "ssrf") else "baixo"
        cwe_id = map_category_to_cwe(f.category)
        
        titulo = f"[{category}] Detecção de {category} em {f.endpoint or state.target}"
        if f.parameter:
            titulo += f" (parâmetro: {f.parameter})"
            
        desc = (
            f"Achado identificado pelo plugin {f.detection_source}.\n"
            f"Contexto: {f.context}\n"
            f"Confiança da detecção: {f.confidence_score:.0%}"
        )
        
        poc = f"Payload candidato: {f.candidate_payload}\nEvidência: {f.raw_evidence[:500]}" if f.candidate_payload else None
        
        grc_findings.append({
            "titulo": titulo,
            "descricao": desc,
            "severidade": severity,
            "cvss_score": map_category_to_cvss(f.category, severity),
            "cve_id": None,
            "cwe_id": cwe_id,
            "endpoint": f.endpoint or state.target,
            "parametro": f.parameter or None,
            "metodo_http": f.method or "GET",
            "prova_conceito": poc,
            "remediacao_sugerida": f"Revisar implementação do endpoint {f.endpoint} em relação a {cwe_id or category}.",
            "proof_level": "none",
            "confidence": f.confidence_score,
        })

    # 3. Portas e Superfície
    open_ports = state.discoveries.get("open_ports", [])
    technologies = state.discoveries.get("technologies", [])
    
    return {
        "tool": "ReconForge",
        "scanner_version": "2.0",
        "format": "grc_intelligence_v1",
        "run_id": state.run_id,
        "target": state.target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_findings": len(grc_findings),
            "critical": sum(1 for f in grc_findings if f["severidade"] == "critico"),
            "high": sum(1 for f in grc_findings if f["severidade"] == "alto"),
            "medium": sum(1 for f in grc_findings if f["severidade"] == "medio"),
            "low": sum(1 for f in grc_findings if f["severidade"] == "baixo"),
            "open_ports_count": len(open_ports),
        },
        "ai_executive_summary": ai_summary,
        "findings": grc_findings,
        "surface": {
            "hosts": state.discoveries.get("hosts", []),
            "open_ports": open_ports,
            "technologies": technologies,
            "endpoints": state.discoveries.get("endpoints", [])[:50],
        },
    }


def save_grc_report(state: WorkflowState, path: Path, ai_summary: str = "") -> None:
    """Salva o arquivo .grc.json no caminho especificado."""
    data = build_grc_payload(state, ai_summary=ai_summary)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
