from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from angr_rule_learning.io.schema import candidate_from_json
from angr_rule_learning.verification.candidate import VerificationCandidate


def read_candidates(path: Path) -> Iterator[VerificationCandidate]:
    if path.is_dir():
        for child in sorted(path.glob("*.json")):
            yield from read_candidates(child)
        return

    if path.suffix == ".jsonl":
        yield from _read_jsonl_candidates(path)
        return

    yield _read_json_candidate(path)


def _read_json_candidate(path: Path) -> VerificationCandidate:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return candidate_from_json(payload)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise ValueError(f"{path}: {error}") from error


def _read_jsonl_candidates(path: Path) -> Iterator[VerificationCandidate]:
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            yield candidate_from_json(payload)
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise ValueError(f"{path}:{line_number}: {error}") from error
