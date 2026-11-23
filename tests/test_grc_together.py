import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Adiciona raiz ao sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.models import Evidence, Finding, QueueItem
from core.workflow_state import WorkflowState
from utils.ai_reporter import AIReportGenerator, AIReportResult
from utils.grc_exporter import build_grc_payload, save_grc_report


class TestGrcAndTogether(unittest.TestCase):
    def test_ai_reporter_together_missing_key(self):
        with patch.dict(os.environ, {}, clear=True):
            gen = AIReportGenerator()
            gen.provider = "together"
            state = WorkflowState(target="https://example.com", run_id=1)
            res = gen.generate_for_state(state)
            self.assertFalse(res.generated)
            self.assertEqual(res.skipped_reason, "api_key_missing")

    def test_ai_reporter_together_success(self):
        with patch.dict(os.environ, {"TOGETHER_API_KEY": "fake_test_key"}):
            gen = AIReportGenerator()
            gen.provider = "together"
            state = WorkflowState(target="https://example.com", run_id=1)

            fake_response = MagicMock()
            fake_response.status_code = 200
            fake_response.json.return_value = {
                "choices": [
                    {
                        "message": {
                            "content": "## 🤖 Resumo Executivo e Postura de Risco\nTudo seguro."
                        }
                    }
                ]
            }

            with patch("requests.post", return_value=fake_response) as mock_post:
                res = gen.generate_for_state(state)
                self.assertTrue(res.generated)
                self.assertEqual(res.provider, "together")
                self.assertIn("Resumo Executivo", res.text)
                mock_post.assert_called_once()

    def test_grc_exporter_payload(self):
        state = WorkflowState(target="https://api.niteroi.rj.gov.br", run_id=42)
        
        # Cria um finding e uma evidência confirmada
        finding = Finding(
            category="sqli",
            target=state.target,
            endpoint="https://api.niteroi.rj.gov.br/users",
            method="POST",
            parameter="id",
            candidate_payload="' OR 1=1 --",
            detection_source="SqliScannerPlugin",
            confidence_score=0.95
        )
        item = QueueItem.from_finding(finding, priority=1)
        item.assigned_executor = "sqli_executor"
        evidence = Evidence(
            queue_item_id=item.id,
            attempt_id="att-01",
            proof_level="impact_proven",
            impact_summary="Extração de banner de banco de dados PostgreSQL confirmada.",
            artifacts=["log_sql_01.txt"]
        )

        state.queue_items.append(item)
        state.findings.append(finding)
        state.evidences.append(evidence)
        state.discoveries["open_ports"] = [80, 443]

        payload = build_grc_payload(state, ai_summary="Resumo de IA gerado")

        self.assertEqual(payload["tool"], "ReconForge")
        self.assertEqual(payload["format"], "grc_intelligence_v1")
        self.assertEqual(payload["target"], "https://api.niteroi.rj.gov.br")
        self.assertEqual(len(payload["findings"]), 1)

        f0 = payload["findings"][0]
        self.assertIn("[SQLI]", f0["titulo"])
        self.assertEqual(f0["severidade"], "critico")
        self.assertEqual(f0["cwe_id"], "CWE-89")
        self.assertEqual(f0["parametro"], "id")
        self.assertEqual(f0["metodo_http"], "POST")
        self.assertIn("Extração de banner", f0["descricao"])
        self.assertIn("' OR 1=1 --", f0["prova_conceito"])


if __name__ == "__main__":
    unittest.main()
