import json

import pytest

from angr_rule_learning.cli import main
from angr_rule_learning.io.readers import read_candidates
from angr_rule_learning.verification.batch import BatchVerifier
from angr_rule_learning.verification.report import CheckResult, VerificationReport


def _candidate_payload(candidate_id: str) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "guest": {
            "arch": "aarch64",
            "address": 0x10000,
            "code_hex": "20 00 02 8b",
            "instruction_count": 1,
        },
        "host": {
            "arch": "x86-64",
            "address": 0x8048000,
            "code_hex": "48 8d 04 11",
            "instruction_count": 1,
        },
        "inputs": {"registers": [["x1", "rcx"], ["x2", "rdx"]]},
        "outputs": {"registers": [["x0", "rax"]], "flags": []},
        "memory": {"slots": [], "bindings": [], "accesses": [], "alias": []},
        "preconditions": [],
        "clobbers": {"guest": [], "host": []},
    }


def test_read_candidates_supports_jsonl_with_two_candidates(tmp_path) -> None:
    path = tmp_path / "candidates.jsonl"
    path.write_text(
        "\n".join(
            json.dumps(_candidate_payload(candidate_id))
            for candidate_id in ("add0", "add1")
        )
        + "\n",
        encoding="utf-8",
    )

    candidates = list(read_candidates(path))

    assert [candidate.candidate_id for candidate in candidates] == ["add0", "add1"]


def test_read_candidates_adds_jsonl_line_context_to_validation_errors(
    tmp_path,
) -> None:
    path = tmp_path / "candidates.jsonl"
    invalid = _candidate_payload("bad")
    del invalid["guest"]
    path.write_text(
        json.dumps(_candidate_payload("good")) + "\n" + json.dumps(invalid) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match=rf"{path}:2: missing top-level field: guest",
    ):
        list(read_candidates(path))


def test_read_candidates_adds_jsonl_line_context_to_type_errors(tmp_path) -> None:
    path = tmp_path / "candidates.jsonl"
    path.write_text("null\n", encoding="utf-8")

    with pytest.raises(ValueError, match=rf"{path}:1:"):
        list(read_candidates(path))


def test_read_candidates_reads_directory_json_files_in_sorted_order(tmp_path) -> None:
    (tmp_path / "b.json").write_text(
        json.dumps(_candidate_payload("second")), encoding="utf-8"
    )
    (tmp_path / "a.json").write_text(
        json.dumps(_candidate_payload("first")), encoding="utf-8"
    )

    candidates = list(read_candidates(tmp_path))

    assert [candidate.candidate_id for candidate in candidates] == ["first", "second"]


def test_read_candidates_reads_single_json_file(tmp_path) -> None:
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(_candidate_payload("single")), encoding="utf-8")

    candidates = list(read_candidates(path))

    assert [candidate.candidate_id for candidate in candidates] == ["single"]


def test_read_candidates_adds_single_json_file_context_to_errors(tmp_path) -> None:
    path = tmp_path / "candidate.json"
    path.write_text("null\n", encoding="utf-8")

    with pytest.raises(ValueError, match=rf"{path}:"):
        list(read_candidates(path))


def test_read_candidates_adds_directory_child_context_to_errors(tmp_path) -> None:
    path = tmp_path / "candidate.json"
    path.write_text("not json\n", encoding="utf-8")

    with pytest.raises(ValueError, match=rf"{path}:"):
        list(read_candidates(tmp_path))


def test_batch_verifier_summarizes_statuses_and_failure_reasons() -> None:
    reports = [
        VerificationReport("pass0", "pass"),
        VerificationReport(
            "fail0",
            "fail",
            checks=(
                CheckResult(
                    kind="register",
                    status="fail",
                    guest="x0",
                    host="rax",
                    reason="register_mismatch",
                ),
            ),
        ),
        VerificationReport(
            "unsupported0",
            "unsupported",
            checks=(
                CheckResult("memory", "unsupported", "mem", "mem", reason="memory"),
            ),
            unsupported_features=("memory",),
        ),
    ]

    summary = BatchVerifier.summarize(reports)

    assert summary.to_json() == {
        "total": 3,
        "statuses": {"fail": 1, "pass": 1, "unsupported": 1},
        "failure_reasons": {"memory": 1, "register_mismatch": 1},
        "by_kind": {"memory": {"unsupported": 1}, "register": {"fail": 1}},
        "top_reasons": {"memory": 1, "register_mismatch": 1},
    }


def test_cli_writes_report_jsonl_and_summary_json(tmp_path) -> None:
    input_path = tmp_path / "candidate.json"
    report_path = tmp_path / "reports.jsonl"
    summary_path = tmp_path / "summary.json"
    input_path.write_text(json.dumps(_candidate_payload("cli0")), encoding="utf-8")

    main(
        [
            "verify",
            str(input_path),
            "--output",
            str(report_path),
            "--summary",
            str(summary_path),
        ]
    )

    report_lines = report_path.read_text(encoding="utf-8").splitlines()
    assert len(report_lines) == 1
    report = json.loads(report_lines[0])
    assert report["candidate_id"] == "cli0"
    assert report["status"] == "pass"

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["total"] == 1
    assert summary["statuses"] == {"pass": 1}
    assert summary["by_kind"]["register"] == {"pass": 1}


def test_extract_cli_rejects_rules_output_without_verify(tmp_path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "extract",
                str(source),
                "--work-dir",
                str(tmp_path / "work"),
                "--output",
                str(tmp_path / "candidates.jsonl"),
                "--diagnostics",
                str(tmp_path / "diagnostics.json"),
                "--rules-output",
                str(tmp_path / "rules.txt"),
            ]
        )

    assert excinfo.value.code == 2


def test_extract_cli_rejects_rules_debug_diagnostics_without_verify(tmp_path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "extract",
                str(source),
                "--work-dir",
                str(tmp_path / "work"),
                "--output",
                str(tmp_path / "candidates.jsonl"),
                "--diagnostics",
                str(tmp_path / "diagnostics.json"),
                "--rules-debug-diagnostics",
                str(tmp_path / "rules_debug_diagnostics.json"),
            ]
        )

    assert excinfo.value.code == 2


def test_extract_cli_rejects_rules_diagnostics_without_verify(tmp_path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "extract",
                str(source),
                "--work-dir",
                str(tmp_path / "work"),
                "--output",
                str(tmp_path / "candidates.jsonl"),
                "--diagnostics",
                str(tmp_path / "diagnostics.json"),
                "--rules-diagnostics",
                str(tmp_path / "rules_diagnostics.json"),
            ]
        )

    assert excinfo.value.code == 2


def test_extract_cli_propagates_architecture_direction(tmp_path, monkeypatch) -> None:
    captured = {}

    def fake_run(self, config, **kwargs) -> None:
        captured["config"] = config

    monkeypatch.setattr("angr_rule_learning.cli.ExtractionPipeline.run", fake_run)
    source = tmp_path / "sample.c"
    source.write_text("int f(void) { return 1; }\n", encoding="utf-8")

    main(
        [
            "extract",
            str(source),
            "--work-dir",
            str(tmp_path / "work"),
            "--output",
            str(tmp_path / "candidates.jsonl"),
            "--diagnostics",
            str(tmp_path / "diagnostics.json"),
            "--guest-arch",
            "x86_64",
            "--host-arch",
            "arm64",
        ]
    )

    assert captured["config"].guest_arch == "x86-64"
    assert captured["config"].host_arch == "aarch64"


def test_diagnose_cli_propagates_architecture_direction(tmp_path, monkeypatch) -> None:
    captured = {}

    def fake_analyze(self, config):
        captured["config"] = config
        return {}

    monkeypatch.setattr(
        "angr_rule_learning.cli.SkipPatternAnalyzer.analyze", fake_analyze
    )
    source = tmp_path / "sample.c"
    source.write_text("int f(void) { return 1; }\n", encoding="utf-8")

    main(
        [
            "diagnose-skips",
            str(source),
            "--work-dir",
            str(tmp_path / "work"),
            "--output",
            str(tmp_path / "patterns.json"),
            "--guest-arch",
            "x86-64",
            "--host-arch",
            "aarch64",
        ]
    )

    assert captured["config"].guest_arch == "x86-64"
    assert captured["config"].host_arch == "aarch64"


def test_extract_cli_propagates_register_binding_strategy(
    tmp_path, monkeypatch
) -> None:
    captured = {}

    def fake_run(self, config, **kwargs) -> None:
        captured["config"] = config

    monkeypatch.setattr("angr_rule_learning.cli.ExtractionPipeline.run", fake_run)
    source = tmp_path / "sample.c"
    source.write_text("int f(void) { return 1; }\n", encoding="utf-8")

    main(
        [
            "extract",
            str(source),
            "--work-dir",
            str(tmp_path / "work"),
            "--output",
            str(tmp_path / "candidates.jsonl"),
            "--diagnostics",
            str(tmp_path / "diagnostics.json"),
            "--register-binding",
            "cegis",
        ]
    )

    assert captured["config"].register_binding == "cegis"
