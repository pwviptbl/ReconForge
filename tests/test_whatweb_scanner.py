import json
import subprocess
from types import SimpleNamespace

from plugins.whatweb_scanner import WhatWebScannerPlugin


def test_whatweb_retries_with_lower_aggression_after_timeout(monkeypatch):
    calls = []

    def fake_run(cmd, capture_output, text, env, timeout):
        calls.append(list(cmd))
        output_file = cmd[cmd.index("--log-json") + 1]
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(cmd, timeout)

        with open(output_file, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"plugins": {"Apache": {}, "PHP": {}}}) + "\n")

        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr("plugins.whatweb_scanner.subprocess.run", fake_run)

    plugin = WhatWebScannerPlugin()
    result = plugin._run_whatweb("https://example.test", 3, 30)

    assert {technology for technology in result["technologies"]} == {"Apache", "PHP"}
    assert calls[0][calls[0].index("-a") + 1] == "3"
    assert calls[1][calls[1].index("-a") + 1] == "1"
