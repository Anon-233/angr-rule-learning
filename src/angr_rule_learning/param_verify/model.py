from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from angr_rule_learning.rules.ast import Rule


VerifyStatus = Literal["pass", "fail", "unsupported"]


@dataclass(frozen=True)
class ParameterizedVerifyRequest:
    rule: Rule
    imm_domains: dict[int, tuple[int, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class ParameterizedVerifyReport:
    status: VerifyStatus
    reason: str | None = None
    counterexample: dict[str, int] = field(default_factory=dict)
