from __future__ import annotations

from dataclasses import dataclass

import angr
import claripy

from angr_rule_learning.verification.addressing import parse_address_binding
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


def validate_alias_declarations(candidate: VerificationCandidate) -> None:
    must_alias_pairs: set[tuple[str, str]] = set()
    disjoint_pairs: set[tuple[str, str]] = set()
    for alias in candidate.memory.alias:
        pairs = {
            tuple(sorted((left, right)))
            for index, left in enumerate(alias.slots)
            for right in alias.slots[index + 1 :]
        }
        if alias.relation == "must_alias":
            must_alias_pairs.update(pairs)
        elif alias.relation == "disjoint":
            disjoint_pairs.update(pairs)
    if must_alias_pairs & disjoint_pairs:
        raise ValueError("invalid_alias_declaration")


_INDEX_WITNESS = 3


def _address_register_values(expression: str, base: int) -> dict[str, int]:
    expr = parse_address_binding(expression)
    values: dict[str, int] = {}
    index_value = 0
    if expr.index is not None:
        index_value = _INDEX_WITNESS
        values[expr.index] = index_value
    if expr.base is not None:
        values[expr.base] = expr.solve_base_for_slot(base, index_value)
    return values


def _merge_register_values(
    current: dict[str, int],
    updates: dict[str, int],
) -> None:
    for register, value in updates.items():
        existing = current.get(register)
        if existing is not None and existing != value:
            raise ValueError("unsupported address expression: conflicting bindings")
        current[register] = value


class MemoryInitializer:
    def __init__(self, config: VerificationConfig) -> None:
        self._config = config

    def initialize(
        self,
        candidate: VerificationCandidate,
        guest_state: angr.SimState,
        host_state: angr.SimState,
    ) -> MemoryLayout:
        validate_alias_declarations(candidate)
        roots = _must_alias_roots(candidate)
        bases: dict[str, int] = {}
        base_by_root: dict[str, int] = {}
        size_by_root: dict[str, int] = {}
        for slot in candidate.memory.slots:
            root = roots[slot.name]
            if root not in base_by_root:
                base_by_root[root] = (
                    self._config.memory_base
                    + len(base_by_root) * self._config.memory_stride
                )
            base = base_by_root[root]
            bases[slot.name] = base
            size_by_root[root] = max(size_by_root.get(root, 0), slot.size)

        for root, base in base_by_root.items():
            content = claripy.BVS(
                f"{candidate.candidate_id}_{root}_init", size_by_root[root] * 8
            )
            guest_state.memory.store(
                base, content, endness=guest_state.arch.memory_endness
            )
            host_state.memory.store(
                base, content, endness=host_state.arch.memory_endness
            )

        guest_values: dict[str, int] = {}
        host_values: dict[str, int] = {}
        for binding in candidate.memory.bindings:
            base = bases[binding.slot]
            _merge_register_values(
                guest_values, _address_register_values(binding.guest_addr, base)
            )
            _merge_register_values(
                host_values, _address_register_values(binding.host_addr, base)
            )

        for register, value in guest_values.items():
            write_reg(guest_state, register, claripy.BVV(value, guest_state.arch.bits))
        for register, value in host_values.items():
            write_reg(host_state, register, claripy.BVV(value, host_state.arch.bits))

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


def _must_alias_roots(candidate: VerificationCandidate) -> dict[str, str]:
    parents = {slot.name: slot.name for slot in candidate.memory.slots}

    def find(slot: str) -> str:
        parent = parents[slot]
        if parent != slot:
            parents[slot] = find(parent)
        return parents[slot]

    def union(left: str, right: str) -> None:
        parents[find(right)] = find(left)

    for alias in candidate.memory.alias:
        if alias.relation != "must_alias":
            continue
        root = alias.slots[0]
        for slot in alias.slots[1:]:
            union(root, slot)

    return {slot: find(slot) for slot in parents}
