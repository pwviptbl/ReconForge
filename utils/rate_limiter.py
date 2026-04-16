"""
Rate limiter simples para scans HTTP.

Garante um delay minimo entre requests e faz backoff exponencial ao receber
429 (Too Many Requests) ou 503 (Service Unavailable).
"""
from __future__ import annotations

import time
from typing import Optional


class RateLimiter:
    """Aplica delay entre requests e backoff em 429/503."""

    def __init__(self, min_delay: float = 0.05, max_backoff: float = 60.0, max_retries: int = 3) -> None:
        self.min_delay = min_delay
        self.max_backoff = max_backoff
        self.max_retries = max_retries
        self._last_request = 0.0
        self._backoff_until = 0.0
        self._retry_count = 0

    def wait(self) -> None:
        """Aguarda o delay necessario desde o ultimo request."""
        now = time.monotonic()
        # Se estamos em periodo de backoff
        if now < self._backoff_until:
            sleep_time = min(self._backoff_until - now, self.max_backoff)
            time.sleep(sleep_time)
            return
        # Delay normal entre requests
        elapsed = now - self._last_request
        if elapsed < self.min_delay:
            time.sleep(self.min_delay - elapsed)

    def record_request(self) -> None:
        """Registra que um request foi enviado."""
        self._last_request = time.monotonic()

    def handle_rate_limit(self, status_code: int) -> bool:
        """
        Retorna True se o caller deve RETENTAR o request.
        Aplica backoff exponencial quando status_code indica rate limiting.
        """
        if status_code not in (429, 503):
            self._retry_count = 0  # Reset quando OK
            return False

        self._retry_count += 1
        if self._retry_count > self.max_retries:
            # Desiste apos max_retries consecutivas
            self._retry_count = 0
            return False

        # Backoff exponencial: 1s, 2s, 4s, 8s...
        backoff = min(2 ** (self._retry_count - 1), self.max_backoff)
        self._backoff_until = time.monotonic() + backoff
        return True

    @classmethod
    def from_config(cls, config: dict) -> "RateLimiter":
        delay = float(config.get("rate_delay", 0.05))
        max_backoff = float(config.get("rate_max_backoff", 60.0))
        max_retries = int(config.get("rate_max_retries", 3))
        return cls(min_delay=delay, max_backoff=max_backoff, max_retries=max_retries)
