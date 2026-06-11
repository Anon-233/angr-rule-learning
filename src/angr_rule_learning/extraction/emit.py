from __future__ import annotations

import json
from pathlib import Path

from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.io.schema import report_to_json
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport


def candidate_to_json(candidate: VerificationCandidate) -> dict[str, object]:
    return {
        "candidate_id": candidate.candidate_id,
        "guest": _fragment_to_json(candidate.guest),
        "host": _fragment_to_json(candidate.host),
        "inputs": {"registers": [list(pair) for pair in candidate.input_registers]},
        "outputs": {
            "registers": [list(pair) for pair in candidate.output_registers],
            "flags": [list(pair) for pair in candidate.output_flags],
        },
        "memory": {
            "slots": [],
            "bindings": [],
            "accesses": [],
            "alias": [],
        },
        "preconditions": list(candidate.preconditions),
        "clobbers": {
            "guest": list(candidate.clobbers.guest),
            "host": list(candidate.clobbers.host),
        },
    }


def write_candidates_jsonl(
    path: Path, candidates: tuple[VerificationCandidate, ...]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(candidate_to_json(candidate), sort_keys=True)
        for candidate in candidates
    ]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_diagnostics_json(path: Path, diagnostics: MiningDiagnostics) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(diagnostics.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_reports_jsonl(path: Path, reports: tuple[VerificationReport, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(report_to_json(report), sort_keys=True) for report in reports]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _fragment_to_json(fragment) -> dict[str, object]:
    return {
        "arch": fragment.arch,
        "address": fragment.address,
        "code_hex": fragment.code_hex,
        "instruction_count": fragment.instruction_count,
    }
