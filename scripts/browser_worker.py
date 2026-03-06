#!/usr/bin/env python3
"""
Browser worker — Fase 4

Processa categorias que dependem de browser real, como DOM XSS e CSRF.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

from core.config import get_config
from core.storage import Storage
from scripts.worker import _process_batch
from utils.logger import setup_logger


DEFAULT_CATEGORIES = ["dom_xss", "csrf", "xss"]


def main() -> int:
    parser = argparse.ArgumentParser(description="ReconForge browser worker")
    parser.add_argument(
        "--categories",
        default=",".join(DEFAULT_CATEGORIES),
        help="Categorias separadas por vírgula",
    )
    parser.add_argument("--run-id", type=int, help="Restringe a um run específico")
    parser.add_argument("--max-items", type=int, default=10, help="Máximo de itens por batch/categoria")
    parser.add_argument("--max-attempts", type=int, default=5, help="Máximo de tentativas por item")
    parser.add_argument("--poll-interval", type=float, default=5.0, help="Intervalo entre polls em segundos")
    parser.add_argument("--loop", action="store_true", help="Mantém o worker executando em loop")
    parser.add_argument("--data-dir", default=get_config("output.data_dir", "data"), help="Diretório base de dados")
    args = parser.parse_args()

    setup_logger("ReconForgeBrowserWorker", verbose=True)

    categories = [cat.strip() for cat in args.categories.split(",") if cat.strip()]
    data_dir = Path(args.data_dir)
    storage = Storage(data_dir / "reconforge.db")

    while True:
        for category in categories:
            _process_batch(
                storage=storage,
                category=category,
                run_id=args.run_id,
                max_items=args.max_items,
                max_attempts=args.max_attempts,
                data_dir=data_dir,
            )

        if not args.loop:
            break
        time.sleep(max(args.poll_interval, 0.5))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
