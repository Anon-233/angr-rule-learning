import json
from pathlib import Path

from angr_rule_learning import cli


class _FakeAnalyzer:
    def analyze(self, config):
        return {
            "source": str(config.source),
            "optimization": config.compile_options.optimization,
            "window_limits": {
                "guest_max": config.window_limits.guest_max,
                "host_max": config.window_limits.host_max,
            },
            "totals": {"windows_enumerated": 1, "selected_skips": 1},
            "details": {
                "unparsed_memory_access": {
                    "total": 1,
                    "by_arch_mnemonic": {"aarch64:ldp": 1},
                    "top_instruction_patterns": [],
                }
            },
        }


def test_diagnose_skips_cli_writes_json_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int f(void) { return 0; }\n", encoding="utf-8")
    output = tmp_path / "skip_report.json"
    monkeypatch.setattr(cli, "SkipPatternAnalyzer", lambda: _FakeAnalyzer())

    cli.main(
        [
            "diagnose-skips",
            str(source),
            "--work-dir",
            str(tmp_path / "work"),
            "--output",
            str(output),
            "--optimization",
            "0",
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["source"] == str(source)
    assert payload["totals"]["selected_skips"] == 1
