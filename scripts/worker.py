#!/usr/bin/env python3
"""
Worker CLI por categoria — Fase 4

Consome itens pendentes da queue por categoria e executa exploração/evidência
sem depender do menu interativo.
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
from core.exploit_queue import ExploitQueue
from core.storage import Storage
from core.stages.stage_evidence import StageEvidence
from core.stages.stage_exploit import StageExploit
from core.workflow_state import WorkflowState
from utils.logger import setup_logger


def _process_batch(
    storage: Storage,
    category: str,
    run_id: int | None,
    max_items: int,
    max_attempts: int,
    data_dir: Path,
) -> int:
    queue = ExploitQueue(storage=storage)
    items = queue.get_pending(category=category, run_id=run_id)
    if max_items > 0:
        items = items[:max_items]

    if not items:
        return 0

    state = WorkflowState(
        target=items[0].target or "worker",
        run_id=items[0].run_id or run_id or -1,
        config={"plugins": {"max_parallel": 1}},
        queue_items=items,
    )

    StageExploit(
        storage=storage,
        max_attempts_per_item=max_attempts,
        categories=[category],
    ).execute(state)
    StageEvidence(
        storage=storage,
        evidence_dir=data_dir / "evidencias",
    ).execute(state)
    storage.checkpoint_workflow(state)

    confirmed = sum(1 for evidence in state.evidences if evidence.proof_level == "impact_proven")
    partial = sum(1 for evidence in state.evidences if evidence.proof_level == "partial")
    print(
        f"[worker:{category}] processados={len(items)} "
        f"attempts={len(state.attempts)} confirmed={confirmed} partial={partial}"
    )
    return len(items)


def main() -> int:
    parser = argparse.ArgumentParser(description="ReconForge category worker")
    parser.add_argument("--category", required=True, help="Categoria da queue a processar")
    parser.add_argument("--run-id", type=int, help="Restringe a um run específico")
    parser.add_argument("--max-items", type=int, default=10, help="Máximo de itens por batch")
    parser.add_argument("--max-attempts", type=int, default=5, help="Máximo de tentativas por item")
    parser.add_argument("--poll-interval", type=float, default=5.0, help="Intervalo entre polls em segundos")
    parser.add_argument("--loop", action="store_true", help="Mantém o worker executando em loop")
    parser.add_argument("--data-dir", default=get_config("output.data_dir", "data"), help="Diretório base de dados")
    args = parser.parse_args()

    setup_logger("ReconForgeWorker", verbose=True)

    data_dir = Path(args.data_dir)
    storage = Storage(data_dir / "reconforge.db")

    while True:
        _process_batch(
            storage=storage,
            category=args.category,
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
