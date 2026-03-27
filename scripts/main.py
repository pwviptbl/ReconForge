#!/usr/bin/env python3
"""
ReconForge CLI orientada ao pipeline.
"""

import argparse
import logging
import os
import sys
import textwrap
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

from core.config import get_config
from core.plugin_manager import PluginManager
from core.storage import Storage
from core.workflow_orchestrator import run_pipeline
from utils.auth_session import load_session_profile
from utils.logger import setup_logger
from utils.runtime_health import collect_runtime_health, format_runtime_health_text
from utils.runtime_profiles import list_profiles, profile_choices, resolve_profile_plugins
from utils.tor import collect_tor_status
from utils.web_map import build_web_map_payload, format_web_map_text


DEFAULT_PROFILE = "web-test"


def _format_profile_help() -> str:
    lines = ["Perfis disponiveis:"]
    for profile in list_profiles():
        lines.append(f"  - {profile['name']}: {profile.get('description', '')}")
    lines.extend(
        [
            "",
            "Exemplos:",
            "  ./run.sh alvo",
            "  ./run.sh alvo --profile web-map",
            "  ./run.sh alvo --profile infra",
            "  ./run.sh https://app.exemplo.local/dashboard --session-file sessions/app.yaml",
            "  ./run.sh alvo --pipeline --recon-plugins PortScannerPlugin,WebFlowMapperPlugin",
            "  ./run.sh --healthcheck",
            "  ./run.sh --show-web-map 50",
            "",
            f"Sem --profile, ./run.sh alvo usa o perfil padrao: {DEFAULT_PROFILE}",
        ]
    )
    return "\n".join(lines)


def _resolve_profile_selection(
    profile_name: str,
    plugin_manager: PluginManager,
) -> tuple[dict | None, str | None]:
    resolved = resolve_profile_plugins(
        profile_name,
        list(plugin_manager.plugins.keys()),
    )
    missing_required = resolved.get("missing_required", [])
    if not missing_required:
        return resolved, None

    disabled = plugin_manager.disabled_plugins
    details = []
    for plugin_name in missing_required:
        info = disabled.get(plugin_name, {})
        detail = info.get("detail")
        if detail:
            details.append(f"{plugin_name}: {detail}")
        else:
            details.append(plugin_name)

    return None, (
        f"Perfil '{profile_name}' indisponivel. Dependencias ausentes: "
        + "; ".join(details)
    )


def _show_web_map(run_id: int, storage: Storage) -> int:
    loaded = storage.load_run_by_id(run_id)
    if not loaded:
        print(f"Run {run_id} nao encontrado.")
        return 1

    _, context, _, target = loaded
    web_map = build_web_map_payload(context.get("discoveries", {}))
    print(format_web_map_text(run_id, target, web_map))
    return 0


def _parse_csv(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    items = [item.strip() for item in raw.split(",") if item.strip()]
    return items or None


def _print_pipeline_summary(state) -> None:
    summary = state.summary()
    detected_findings = summary.get(
        "findings_detected",
        len(state.findings) + len(state.rejected_findings),
    )
    validated_findings = summary.get("findings_validated", len(state.findings))
    confirmed = sum(1 for evidence in state.evidences if evidence.proof_level == "impact_proven")
    partial = sum(1 for evidence in state.evidences if evidence.proof_level == "partial")

    print(f"\n{'=' * 55}")
    print(f"Pipeline concluido | run_id={summary['run_id']}")
    print(f"  Estagios executados   : {summary['stages_done']}")
    print(f"  Findings detectados   : {detected_findings}")
    print(f"  Findings validados    : {validated_findings}")
    print(f"  Findings descartados  : {len(state.rejected_findings)}")
    print(f"  Items na queue        : {len(state.queue_items)}")
    print(f"  Tentativas de exploit : {len(state.attempts)}")
    print(f"  Confirmadas           : {confirmed}")
    print(f"  Parciais              : {partial}")
    if state.report_path:
        print(f"  Relatorio             : {state.report_path}")

    web_map = build_web_map_payload(state.discoveries)
    if web_map.get("summary", {}).get("requests_interesting", 0):
        print(
            "  Web map               : "
            f"forms={web_map['summary']['forms']} "
            f"requests={web_map['summary']['requests_interesting']}"
        )
        print(f"  Ver rotas             : ./run.sh --show-web-map {summary['run_id']}")

    if summary.get("errors"):
        print(f"  Erros                 : {summary['errors']}")
    print(f"{'=' * 55}")


def main() -> int:
    try:
        logging.disable(logging.CRITICAL)
        plugin_manager = PluginManager()
        logging.disable(logging.NOTSET)
        profile_help = _format_profile_help()

        parser = argparse.ArgumentParser(
            description="ReconForge - pipeline unico de descoberta, teste e relatorio",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent(profile_help),
        )
        parser.add_argument("target", nargs="?", help="Alvo (IP, dominio, URL ou CIDR)")
        parser.add_argument("--list-profiles", action="store_true", help="Lista perfis simples de execucao e sai")
        parser.add_argument("--profile", choices=profile_choices(), help="Perfil simples de execucao")
        parser.add_argument("--healthcheck", action="store_true", help="Mostra estado do runtime e dependencias")
        parser.add_argument("--show-web-map", type=int, metavar="RUN_ID", help="Exibe rotas e parametros mapeados de um run")
        parser.add_argument(
            "--session-file",
            type=str,
            metavar="ARQUIVO",
            help="Arquivo YAML/JSON com cookies/headers/token para acessar areas autenticadas",
        )
        parser.add_argument(
            "--pipeline",
            action="store_true",
            help="Executa o pipeline com selecao avancada de plugins por estagio",
        )
        parser.add_argument(
            "--recon-plugins",
            type=str,
            metavar="PLUGINS",
            help="Plugins de reconhecimento para o pipeline (separados por virgula).",
        )
        parser.add_argument(
            "--detect-plugins",
            type=str,
            metavar="PLUGINS",
            help="Plugins de deteccao para o pipeline (separados por virgula).",
        )
        parser.add_argument(
            "--exploit-categories",
            type=str,
            metavar="CATS",
            help="Categorias de exploit a executar (ex: xss,sqli,ssrf).",
        )
        parser.add_argument(
            "--max-exploit-attempts",
            type=int,
            default=5,
            metavar="N",
            help="Maximo de tentativas de exploit por item da queue (padrao: 5).",
        )

        args = parser.parse_args()

        if args.list_profiles:
            print(profile_help)
            return 0

        if args.healthcheck:
            health = collect_runtime_health(plugin_manager)
            print(format_runtime_health_text(health))
            return 0

        if args.show_web_map is not None:
            data_dir = Path(get_config("output.data_dir", "data"))
            storage = Storage(data_dir / "reconforge.db")
            return _show_web_map(args.show_web_map, storage)

        tor_status = collect_tor_status()
        if tor_status.get("enabled") and not tor_status.get("ready"):
            print("Modo Tor habilitado, mas o proxy local nao esta pronto.")
            for issue in tor_status.get("issues", []):
                print(f"  - {issue}")
            print("Corrija o ambiente ou desabilite network.tor.enabled antes de executar o pipeline.")
            return 2

        if not args.target:
            parser.print_help()
            return 2

        session_file = None
        if args.session_file:
            try:
                profile = load_session_profile(args.session_file)
                session_file = str(Path(args.session_file).expanduser().resolve())
                auth_bits = []
                if profile.get("headers"):
                    auth_bits.append(f"headers={len(profile['headers'])}")
                if profile.get("cookies"):
                    auth_bits.append(f"cookies={len(profile['cookies'])}")
                if profile.get("local_storage"):
                    auth_bits.append(f"local_storage={len(profile['local_storage'])}")
                print("Sessao autenticada ativa: " + (", ".join(auth_bits) if auth_bits else session_file))
            except Exception as exc:
                print(f"Falha ao carregar --session-file: {exc}")
                return 2

        if args.profile and (args.recon_plugins or args.detect_plugins):
            print("Use --profile ou ajuste manual com --recon-plugins/--detect-plugins, nao os dois.")
            return 2

        if (
            not args.profile
            and not args.pipeline
            and not args.recon_plugins
            and not args.detect_plugins
            and not args.exploit_categories
        ):
            args.profile = DEFAULT_PROFILE
            print(f"Perfil padrao ativo: {DEFAULT_PROFILE}")

        if args.recon_plugins or args.detect_plugins or args.exploit_categories:
            args.pipeline = True

        profile_selection = None
        if args.profile:
            profile_selection, profile_error = _resolve_profile_selection(args.profile, plugin_manager)
            if profile_error:
                print(profile_error)
                print("Rode --healthcheck para ver o estado do ambiente.")
                return 2
            args.pipeline = True
            print(f"Perfil ativo: {args.profile}")
            print(f"  {profile_selection.get('description', '')}")

        setup_logger("ReconForge", verbose=True)

        recon_plugins = None
        detect_plugins = None
        if profile_selection:
            recon_plugins = profile_selection.get("recon_plugins") or None
            detect_plugins = profile_selection.get("detect_plugins") or None

        manual_recon = _parse_csv(args.recon_plugins)
        manual_detect = _parse_csv(args.detect_plugins)
        if manual_recon:
            recon_plugins = manual_recon
        if manual_detect:
            detect_plugins = manual_detect

        exploit_categories = _parse_csv(args.exploit_categories)

        state = run_pipeline(
            target=args.target,
            verbose=True,
            quiet=False,
            recon_plugins=recon_plugins,
            detect_plugins=detect_plugins,
            max_exploit_attempts=args.max_exploit_attempts,
            exploit_categories=exploit_categories,
            auth_session_file=session_file,
        )
        _print_pipeline_summary(state)
        return 0 if not state.aborted else 1

    except KeyboardInterrupt:
        print("\nOperacao cancelada pelo usuario")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
