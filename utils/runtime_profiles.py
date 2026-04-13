from __future__ import annotations

from typing import Any, Dict, List, Optional


PROFILE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "web-map": {
        "description": "Mapeamento gentil de rotas, formulários e parâmetros web.",
        "required_plugins": ["WebFlowMapperPlugin"],
        "recon_plugins": [
            "PortScannerPlugin",
            "WhatWebScannerPlugin",
            "GauCollectorPlugin",
            "KatanaCrawlerPlugin",
            "WebFlowMapperPlugin",
        ],
        "detect_plugins": ["PassiveScannerPlugin"],
        "classic_plugins": [
            "PortScannerPlugin",
            "WhatWebScannerPlugin",
            "GauCollectorPlugin",
            "KatanaCrawlerPlugin",
            "WebFlowMapperPlugin",
            "HeaderAnalyzerPlugin",
            "PassiveScannerPlugin",
        ],
    },
    "web-test": {
        "description": "Mapeamento web seguido dos scanners HTTP request-based.",
        "required_plugins": ["WebFlowMapperPlugin"],
        "recon_plugins": [
            "PortScannerPlugin",
            "WhatWebScannerPlugin",
            "GauCollectorPlugin",
            "KatanaCrawlerPlugin",
            "WebFlowMapperPlugin",
        ],
        "detect_plugins": [
            "XSSScannerPlugin",
            "LFIScannerPlugin",
            "SSRFScannerPlugin",
            "IDORScannerPlugin",
            "HeaderInjectionScannerPlugin",
            "OpenRedirectScannerPlugin",
            "SSTIScannerPlugin",
            "HeaderAnalyzerPlugin",
            "NucleiScannerPlugin",
            "PassiveScannerPlugin",
        ],
        "classic_plugins": [
            "PortScannerPlugin",
            "WhatWebScannerPlugin",
            "GauCollectorPlugin",
            "KatanaCrawlerPlugin",
            "WebFlowMapperPlugin",
            "XSSScannerPlugin",
            "LFIScannerPlugin",
            "SSRFScannerPlugin",
            "IDORScannerPlugin",
            "HeaderInjectionScannerPlugin",
            "OpenRedirectScannerPlugin",
            "SSTIScannerPlugin",
            "HeaderAnalyzerPlugin",
            "NucleiScannerPlugin",
            "PassiveScannerPlugin",
        ],
    },
    "infra": {
        "description": "Mapeamento de portas, serviços, SSL e exposição de infraestrutura.",
        "required_plugins": [],
        "recon_plugins": [
            "PortScannerPlugin",
            "NmapScannerPlugin",
            "DNSResolverPlugin",
            "SubfinderPlugin",
            "NetworkMapperPlugin",
            "FirewallDetectorPlugin",
            "TrafficAnalyzerPlugin",
            "PortExposureAudit",
            "SSHPolicyCheck",
        ],
        "detect_plugins": [
            "SSLAnalyzerPlugin",
            "NucleiScannerPlugin",
        ],
        "classic_plugins": [
            "PortScannerPlugin",
            "NmapScannerPlugin",
            "DNSResolverPlugin",
            "SubfinderPlugin",
            "NetworkMapperPlugin",
            "FirewallDetectorPlugin",
            "TrafficAnalyzerPlugin",
            "PortExposureAudit",
            "SSHPolicyCheck",
            "SSLAnalyzerPlugin",
            "NucleiScannerPlugin",
        ],
    },
}


def get_profile(name: str) -> Optional[Dict[str, Any]]:
    return PROFILE_DEFINITIONS.get(name)


def list_profiles() -> List[Dict[str, Any]]:
    return [
        {"name": name, **definition}
        for name, definition in PROFILE_DEFINITIONS.items()
    ]


def profile_choices() -> List[str]:
    return sorted(PROFILE_DEFINITIONS.keys())


def resolve_profile_plugins(
    profile_name: str,
    available_plugins: List[str],
) -> Dict[str, Any]:
    profile = get_profile(profile_name)
    if not profile:
        raise ValueError(f"perfil desconhecido: {profile_name}")

    available = set(available_plugins)

    def _pick(names: List[str]) -> List[str]:
        return [name for name in names if name in available]

    required = list(profile.get("required_plugins", []))
    missing_required = [name for name in required if name not in available]

    return {
        "name": profile_name,
        "description": profile.get("description", ""),
        "required_plugins": required,
        "missing_required": missing_required,
        "recon_plugins": _pick(list(profile.get("recon_plugins", []))),
        "detect_plugins": _pick(list(profile.get("detect_plugins", []))),
        "classic_plugins": _pick(list(profile.get("classic_plugins", []))),
    }
