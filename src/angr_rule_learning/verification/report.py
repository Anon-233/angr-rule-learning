from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True)
class CheckResult:
    kind: str
    status: str
    guest: str
    host: str
    reason: str = ""
    counterexample: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "counterexample", MappingProxyType(dict(self.counterexample))
        )


@dataclass(frozen=True)
class VerificationReport:
    candidate_id: str
    status: str
    checks: tuple[CheckResult, ...] = field(default_factory=tuple)
    unsupported_features: tuple[str, ...] = field(default_factory=tuple)
    events: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "checks", tuple(self.checks))
        object.__setattr__(
            self,
            "unsupported_features",
            tuple(self.unsupported_features),
        )
        object.__setattr__(
            self,
            "events",
            tuple(MappingProxyType(dict(event)) for event in self.events),
        )

    @property
    def equivalent(self) -> bool:
        return self.status == "pass" and all(
            check.status == "pass" for check in self.checks
        )

    @property
    def failure_reasons(self) -> dict[str, int]:
        reasons = Counter(check.reason for check in self.checks if check.reason)
        reasons.update(self.unsupported_features)
        return dict(reasons)
