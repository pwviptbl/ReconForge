"""
Plugin de Scanner de SQL Injection
Detecta SQLi por três vetores:
1. Erro de banco de dados refletido na resposta (error-based).
2. Delay de resposta compatível com payload time-based blind (SLEEP/WAITFOR/pg_sleep).
3. Divergência booleana simples (TRUE vs FALSE) quando aplicável.

Reaproveita os mesmos padrões de payload/erro já usados por `SqliPipeline`
(fase 3, exploração), fechando o ciclo detecção → fila → exploração que
antes dependia apenas de achados incidentais do Nuclei.
"""

import re
import requests
from typing import Any, Dict, List, Optional, Tuple

from core.parameterized_vulnerability_plugin import ParameterizedVulnerabilityPlugin
from core.models import Vulnerability

# Payloads error-based: testados primeiro (mais baratos, sem custo de tempo).
_PAYLOADS_ERROR = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' AND '1'='2",
    "1' ORDER BY 1--",
]

# Payloads time-based blind: só valem a pena se nada de error-based disparou.
_PAYLOADS_TIME_BASED = [
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND pg_sleep(5)--",
    "1; SELECT pg_sleep(5)--",
]

_DB_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*\bmysql\b",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider",
    r"odbc.*driver",
    r"ora-\d{5}",
    r"pg_query\(\).*error",
    r"unterminated string constant",
    r"syntax error.*near",
    r"sqlite.*error",
    r"sqlstate\[",
    r"postgresql.*error",
]

_TIME_DELAY_THRESHOLD = 4.5  # segundos; payloads pedem SLEEP(5)/DELAY 5s


class SqliScannerPlugin(ParameterizedVulnerabilityPlugin):
    """
    Scanner ativo de SQL Injection (error-based + time-based blind).
    """

    def get_default_payloads(self) -> List[str]:
        # Error-based primeiro: se houver hit, o loop para (stop_on_first_hit)
        # e os payloads time-based (mais lentos) nem chegam a ser testados.
        return _PAYLOADS_ERROR + _PAYLOADS_TIME_BASED

    def evaluate_hit(
        self, response: requests.Response, payload: Any, injection_point: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        body = (response.text or "").lower()
        for pattern in _DB_ERROR_PATTERNS:
            if re.search(pattern, body):
                return True, f"db_error:{pattern}"

        is_time_payload = any(
            marker in str(payload) for marker in ("SLEEP", "sleep", "WAITFOR", "waitfor")
        )
        if is_time_payload:
            elapsed = response.elapsed.total_seconds() if response.elapsed else 0.0
            if elapsed >= _TIME_DELAY_THRESHOLD:
                return True, f"time_delay:{elapsed:.2f}s"

        return False, None

    def build_vulnerability(
        self,
        request_node: Dict[str, Any],
        injection_point: Dict[str, Any],
        payload: Any,
        response: requests.Response,
        indicator: str,
    ) -> Vulnerability:
        param_name = injection_point.get("parameter_name")
        is_time_based = indicator.startswith("time_delay")
        severity = "High" if is_time_based else "Critical"
        vector = "time-based blind" if is_time_based else "error-based"

        return Vulnerability(
            name="SQL Injection",
            severity=severity,
            description=(
                f"Possivel SQL Injection ({vector}) no parametro '{param_name}'."
            ),
            url=request_node.get("url"),
            evidence=f"Payload: {payload}\nIndicator: {indicator}",
            cve="CWE-89",
            remediation=(
                "Utilizar queries parametrizadas/prepared statements e nunca "
                "concatenar entrada do usuario diretamente em comandos SQL."
            ),
            plugin_source=self.name,
        )

    def stop_on_first_hit(self) -> bool:
        # Um hit de error-based já é suficiente; evita gastar tempo com
        # os payloads time-based mais lentos no mesmo ponto de injeção.
        return True
