"""
Runner de confirmação de SQL Injection via sqlmap.

Usado pelo SQLiScannerPlugin como etapa de confirmação profunda: a triagem
rápida (error-based / time-based) encontra um ponto suspeito e, se habilitado,
o sqlmap é disparado APENAS contra aquele ponto específico para confirmar.

Mantém a filosofia de não gerar ruído: nada roda sem um hit prévio e sem
`use_sqlmap` habilitado na config do plugin.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

from utils.logger import get_logger

_logger = get_logger("SqlmapRunner")

# Frases que o sqlmap imprime quando confirma injeção.
_CONFIRM_MARKERS = (
    "is vulnerable",
    "the following injection point",
    "sqlmap identified the following",
)
_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)", re.IGNORECASE)
_TECH_RE = re.compile(r"Type:\s*(.+)")


def sqlmap_available() -> bool:
    return shutil.which("sqlmap") is not None


def _build_get_url(url: str, params: Dict[str, Any]) -> str:
    """Mescla os params do request_node na query string da URL."""
    parsed = urlparse(url)
    existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for k, v in (params or {}).items():
        existing[str(k)] = "" if v is None else str(v)
    new_query = urlencode(existing)
    return urlunparse(parsed._replace(query=new_query))


def confirm_sqli(
    *,
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    parameter: str = "",
    timeout: int = 180,
    extra_args: Optional[List[str]] = None,
    cookies: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Executa `sqlmap --batch` contra um único ponto de injeção.

    Retorna {confirmed, dbms, technique, command, raw} — nunca levanta
    exceção (falhas viram confirmed=False), para não derrubar o scanner.
    """
    result: Dict[str, Any] = {
        "confirmed": False,
        "dbms": "",
        "technique": "",
        "command": "",
        "raw": "",
    }

    sqlmap = shutil.which("sqlmap")
    if not sqlmap:
        result["raw"] = "sqlmap não encontrado no PATH"
        return result

    method = (method or "GET").upper()
    cmd: List[str] = [
        sqlmap,
        "--batch",
        "--disable-coloring",
        "--level", "1",
        "--risk", "1",
        "-v", "1",
    ]

    if method == "GET":
        cmd += ["-u", _build_get_url(url, params or {})]
    else:
        # POST/PUT/...: URL base + corpo em --data
        cmd += ["-u", url, "--method", method]
        if data:
            cmd += ["--data", urlencode({str(k): "" if v is None else str(v) for k, v in data.items()})]

    if parameter:
        cmd += ["-p", parameter]
    if cookies:
        cmd += ["--cookie", "; ".join(f"{k}={v}" for k, v in cookies.items())]
    if extra_args:
        cmd += [str(a) for a in extra_args]

    result["command"] = " ".join(cmd)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        result["raw"] = f"sqlmap timeout após {timeout}s"
        _logger.warning(result["raw"])
        return result
    except Exception as e:  # pragma: no cover - defensivo
        result["raw"] = f"Falha ao executar sqlmap: {e}"
        _logger.warning(result["raw"])
        return result

    low = out.lower()
    result["confirmed"] = any(marker in low for marker in _CONFIRM_MARKERS)

    dbms_match = _DBMS_RE.search(out)
    if dbms_match:
        result["dbms"] = dbms_match.group(1).strip()
    tech_match = _TECH_RE.search(out)
    if tech_match:
        result["technique"] = tech_match.group(1).strip()

    # Guarda apenas um trecho do output para evidência (evita relatório gigante).
    result["raw"] = out[-1500:]
    return result
