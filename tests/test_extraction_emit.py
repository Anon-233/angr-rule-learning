import json
from pathlib import Path

from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.emit import (
    write_candidates_jsonl,
    write_diagnostics_json,
)
from angr_rule_learning.io.readers import read_candidates
from angr_rule_learning.verification.candidate import (
    CodeFragment,
    VerificationCandidate,
)


def test_write_candidates_jsonl_round_trips_through_schema(
    tmp_path: Path,
) -> None:
    candidate = VerificationCandidate(
        candidate_id="sample:add:3:0:g0:h0",
        guest=CodeFragment("aarch64", 0x1000, "20 00 02 8b", 1),
        host=CodeFragment("x86-64", 0x2000, "48 8d 04 11", 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("x0", "rax"),),
    )
    output = tmp_path / "candidates.jsonl"

    write_candidates_jsonl(output, (candidate,))

    assert list(read_candidates(output)) == [candidate]
    assert (
        json.loads(output.read_text(encoding="utf-8"))["candidate_id"]
        == candidate.candidate_id
    )


def test_write_diagnostics_json(tmp_path: Path) -> None:
    diagnostics = MiningDiagnostics()
    diagnostics.record_window_skipped("no_verifiable_surface")
    output = tmp_path / "diagnostics.json"

    write_diagnostics_json(output, diagnostics)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["skip_reasons"] == {"no_verifiable_surface": 1}
