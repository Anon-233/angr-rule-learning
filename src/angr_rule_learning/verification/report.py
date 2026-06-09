from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class VerificationReport:
    candidate_id: str
    status: str
    checks: tuple[object, ...] = field(default_factory=tuple)
