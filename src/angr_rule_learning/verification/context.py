from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

import claripy

from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.memory import MemoryEvent, MemoryLayout


@dataclass(frozen=True)
class CheckContext:
    candidate: VerificationCandidate
    guest_state: object
    host_state: object
    symbols: Mapping[str, claripy.ast.BV]
    memory_layout: MemoryLayout
    memory_events: tuple[MemoryEvent, ...] = field(default_factory=tuple)

    @property
    def constraints(self) -> tuple[object, ...]:
        return tuple(self.guest_state.solver.constraints) + tuple(
            self.host_state.solver.constraints
        )
