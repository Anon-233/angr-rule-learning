from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationCandidate:
    candidate_id: str
