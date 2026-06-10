from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping


REPORT_STATUSES = {"pass", "fail", "unsupported", "error"}
CHECK_STATUSES = REPORT_STATUSES


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(value))


@dataclass(frozen=True)
class CheckResult:
    kind: str
    status: str
    guest: str
    host: str
    reason: str = ""
    counterexample: Mapping[str, int] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in CHECK_STATUSES:
            raise ValueError(f"unsupported check status: {self.status}")
        object.__setattr__(self, "counterexample", _freeze_mapping(self.counterexample))
        object.__setattr__(self, "metadata", _freeze_mapping(self.metadata))


@dataclass(frozen=True)
class VerificationReport:
    candidate_id: str
    status: str
    checks: tuple[CheckResult, ...] = field(default_factory=tuple)
    unsupported_features: tuple[str, ...] = field(default_factory=tuple)
    events: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.status not in REPORT_STATUSES:
            raise ValueError(f"unsupported report status: {self.status}")
        object.__setattr__(self, "checks", tuple(self.checks))
        object.__setattr__(
            self,
            "unsupported_features",
            tuple(self.unsupported_features),
        )
        object.__setattr__(
            self,
            "events",
            tuple(_freeze_mapping(event) for event in self.events),
        )

    @property
    def equivalent(self) -> bool:
        return self.status == "pass" and all(
            check.status == "pass" for check in self.checks
        )

    @property
    def failure_reasons(self) -> dict[str, int]:
        return dict(Counter(check.reason for check in self.checks if check.reason))
