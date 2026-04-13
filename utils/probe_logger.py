"""
ProbeLogger — Registra cada tentativa de ataque (probe) para análise manual.

Usado pelos plugins de varredura de vulnerabilidades (XSS, LFI, SSRF, etc.)
para capturar: URL, método, parâmetro, payload enviado, status HTTP,
trecho da resposta e se o indicador foi encontrado.

Os dados ficam em plugin_result.data['probe_log'] e são exportados
pelo StageReport para análise manual em plugins_raw/<Plugin>.md.
"""

from typing import Any, Dict, List, Optional
import requests


# Número máximo de probes a registrar por plugin
# (evita explodir o JSON com sites que têm milhares de parâmetros)
MAX_PROBES = 2000
# Tamanho máximo do snippet de resposta por probe (chars)
RESPONSE_SNIPPET_LEN = 500


class ProbeLogger:
    """
    Registra tentativas de ataque individuais.

    Uso nos plugins:
        logger = ProbeLogger()

        prepared_req = rebuild_attack_request(...)
        response = session.send(prepared_req, ...)

        logger.record(
            url=prepared_req.url,
            method=prepared_req.method,
            param=param_name,
            location=location,
            payload=payload,
            response=response,
            indicator=payload,          # ou a string que indica sucesso
            hit=payload in response.text,
        )

        # No retorno do plugin:
        return PluginResult(data={..., 'probe_log': logger.to_list()})
    """

    def __init__(self, max_probes: int = MAX_PROBES):
        self._probes: List[Dict[str, Any]] = []
        self._max = max_probes

    def record(
        self,
        url: str,
        method: str,
        param: str,
        location: str,
        payload: str,
        response: Optional[requests.Response],
        indicator: str = "",
        hit: bool = False,
    ) -> None:
        """Registra uma tentativa de ataque."""
        if len(self._probes) >= self._max:
            return  # Truncar silenciosamente para não estourar memória

        probe: Dict[str, Any] = {
            "url": url,
            "method": method,
            "param": param,
            "location": location,
            "payload": payload,
            "hit": hit,
        }

        if response is not None:
            probe["status_code"] = response.status_code
            probe["response_length"] = len(response.content)
            # Snippet da resposta — útil para ver se algo foi refletido
            text = response.text or ""
            if hit and indicator:
                # Mostrar contexto ao redor do indicador
                idx = text.find(indicator)
                if idx >= 0:
                    start = max(0, idx - 100)
                    end = min(len(text), idx + len(indicator) + 200)
                    probe["response_snippet"] = f"...{text[start:end]}..."
                else:
                    probe["response_snippet"] = text[:RESPONSE_SNIPPET_LEN]
            else:
                # Sem hit: mostrar só o início da resposta
                probe["response_snippet"] = text[:200] if text else ""
            # Headers relevantes da resposta
            probe["response_headers"] = {
                k: v for k, v in response.headers.items()
                if k.lower() in {
                    "content-type", "server", "x-frame-options",
                    "content-security-policy", "location", "set-cookie",
                    "x-powered-by", "x-xss-protection",
                }
            }
        else:
            probe["status_code"] = None
            probe["response_length"] = None
            probe["response_snippet"] = ""
            probe["response_headers"] = {}

        self._probes.append(probe)

    def record_error(
        self,
        url: str,
        method: str,
        param: str,
        location: str,
        payload: str,
        error: str,
    ) -> None:
        """Registra uma tentativa que resultou em exceção."""
        if len(self._probes) >= self._max:
            return
        self._probes.append({
            "url": url,
            "method": method,
            "param": param,
            "location": location,
            "payload": payload,
            "hit": False,
            "status_code": None,
            "response_length": None,
            "response_snippet": f"[ERRO: {error[:200]}]",
            "response_headers": {},
        })

    def to_list(self) -> List[Dict[str, Any]]:
        """Retorna lista de probes registrados."""
        return list(self._probes)

    @property
    def total(self) -> int:
        return len(self._probes)

    @property
    def hits(self) -> List[Dict[str, Any]]:
        """Retorna apenas os probes com hit=True."""
        return [p for p in self._probes if p.get("hit")]
