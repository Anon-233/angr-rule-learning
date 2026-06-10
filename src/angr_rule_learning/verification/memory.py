from __future__ import annotations

from dataclasses import dataclass

import angr
import claripy

from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.config import VerificationConfig
from angr_rule_learning.verification.execution import write_reg


@dataclass(frozen=True)
class MemoryLayout:
    bases: dict[str, int]

    def slot_base(self, slot: str) -> int:
        return self.bases[slot]


@dataclass(frozen=True)
class MemoryEvent:
    side: str
    kind: str
    address: claripy.ast.BV
    value: claripy.ast.BV
    width: int
    endness: str


class MemoryInitializer:
    def __init__(self, config: VerificationConfig) -> None:
        self._config = config

    def initialize(
        self,
        candidate: VerificationCandidate,
        guest_state: angr.SimState,
        host_state: angr.SimState,
    ) -> MemoryLayout:
        bases: dict[str, int] = {}
        for index, slot in enumerate(candidate.memory.slots):
            base = self._config.memory_base + index * self._config.memory_stride
            bases[slot.name] = base
            content = claripy.BVS(
                f"{candidate.candidate_id}_{slot.name}_init", slot.size * 8
            )
            guest_state.memory.store(
                base, content, endness=guest_state.arch.memory_endness
            )
            host_state.memory.store(
                base, content, endness=host_state.arch.memory_endness
            )

        for binding in candidate.memory.bindings:
            base_value = claripy.BVV(bases[binding.slot], guest_state.arch.bits)
            write_reg(guest_state, binding.guest_addr, base_value)
            host_base_value = claripy.BVV(bases[binding.slot], host_state.arch.bits)
            write_reg(host_state, binding.host_addr, host_base_value)

        return MemoryLayout(bases)


class MemoryEventRecorder:
    def __init__(self) -> None:
        self.events: list[MemoryEvent] = []

    def install(self, state: angr.SimState, side: str) -> None:
        state.inspect.b("mem_read", when=angr.BP_AFTER, action=self._record_read(side))
        state.inspect.b(
            "mem_write", when=angr.BP_AFTER, action=self._record_write(side)
        )

    def _record_read(self, side: str):
        def record(state: angr.SimState) -> None:
            attrs = state.inspect.attrs
            length = attrs.mem_read_length
            self.events.append(
                MemoryEvent(
                    side=side,
                    kind="read",
                    address=attrs.mem_read_address,
                    value=attrs.mem_read_expr,
                    width=(
                        int(length)
                        if isinstance(length, int)
                        else state.solver.eval(length)
                    ),
                    endness=state.arch.memory_endness,
                )
            )

        return record

    def _record_write(self, side: str):
        def record(state: angr.SimState) -> None:
            attrs = state.inspect.attrs
            length = attrs.mem_write_length
            self.events.append(
                MemoryEvent(
                    side=side,
                    kind="write",
                    address=attrs.mem_write_address,
                    value=attrs.mem_write_expr,
                    width=(
                        int(length)
                        if isinstance(length, int)
                        else state.solver.eval(length)
                    ),
                    endness=state.arch.memory_endness,
                )
            )

        return record
