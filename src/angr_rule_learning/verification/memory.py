from __future__ import annotations

from dataclasses import dataclass

import angr
import claripy

from angr_rule_learning.arch.registers import is_compatible_frame_base_pair
from angr_rule_learning.verification.addressing import (
    AddressExpr,
    parse_address_binding,
)
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


def _is_frame_register_pair(
    candidate: VerificationCandidate,
    guest_reg: str | None,
    host_reg: str | None,
) -> bool:
    return is_compatible_frame_base_pair(
        candidate.guest.arch,
        guest_reg,
        candidate.host.arch,
        host_reg,
    )


def _assign_witness(assigned: dict[str, int], register: str, value: int) -> None:
    existing = assigned.get(register)
    if existing is not None and existing != value:
        raise ValueError("unsupported address expression: conflicting bindings")
    assigned[register] = value


def _initialize_memory_registers(
    candidate: VerificationCandidate,
    guest_state,
    host_state,
    bases: dict[str, int],
) -> None:
    guest_to_host: dict[str, str] = {}
    host_to_guest: dict[str, str] = {}
    for guest_reg, host_reg in candidate.input_registers:
        guest_to_host[guest_reg] = host_reg
        host_to_guest[host_reg] = guest_reg

    assigned: dict[str, int] = {}
    frame_offsets: dict[tuple[str, str], int] = {}

    for binding in candidate.memory.bindings:
        base = bases[binding.slot]
        guest_expr = parse_address_binding(binding.guest_addr)
        host_expr = parse_address_binding(binding.host_addr)

        # Assign index register witnesses.
        # Paired registers get the same non-zero witness value.
        _assign_index_witness(assigned, guest_expr, guest_to_host)
        _assign_index_witness(assigned, host_expr, host_to_guest)

        guest_index_val = assigned.get(guest_expr.index, 0) if guest_expr.index else 0
        host_index_val = assigned.get(host_expr.index, 0) if host_expr.index else 0

        if _is_frame_register_pair(candidate, guest_expr.base, host_expr.base):
            guest_base_val = guest_expr.solve_base_for_slot(base, guest_index_val)
            host_base_val = host_expr.solve_base_for_slot(base, host_index_val)
            offset = host_base_val - guest_base_val
            key = (guest_expr.base, host_expr.base)
            existing_offset = frame_offsets.get(key)
            if existing_offset is not None and existing_offset != offset:
                raise ValueError(
                    "unsupported address expression: inconsistent frame layout"
                )
            frame_offsets[key] = offset
            if guest_expr.base not in assigned:
                _assign_witness(assigned, guest_expr.base, guest_base_val)
                _assign_witness(assigned, host_expr.base, host_base_val)
            continue

        # Compute guest base register value from the guest expression.
        guest_base_val = guest_expr.solve_base_for_slot(base, guest_index_val)
        _assign_witness(assigned, guest_expr.base, guest_base_val)
        host_pair = guest_to_host.get(guest_expr.base)
        if host_pair is not None:
            _assign_witness(assigned, host_pair, guest_base_val)

        # For a host base register NOT paired with a guest register,
        # compute independently so the memory-event address check
        # can still verify the host-side effective address.
        if host_to_guest.get(host_expr.base) is None:
            host_base_val = host_expr.solve_base_for_slot(base, host_index_val)
            _assign_witness(assigned, host_expr.base, host_base_val)

    for register, value in assigned.items():
        if register in guest_state.arch.registers:
            write_reg(guest_state, register, claripy.BVV(value, guest_state.arch.bits))
        host_pair = guest_to_host.get(register)
        if host_pair is not None:
            write_reg(host_state, host_pair, claripy.BVV(value, host_state.arch.bits))
        elif register in host_state.arch.registers:
            write_reg(host_state, register, claripy.BVV(value, host_state.arch.bits))


def _assign_index_witness(
    assigned: dict[str, int],
    expr,
    pair_map: dict[str, str],
) -> None:
    if expr.index is None:
        return
    _assign_witness(assigned, expr.index, _INDEX_WITNESS)
    pair = pair_map.get(expr.index)
    if pair is not None:
        _assign_witness(assigned, pair, _INDEX_WITNESS)


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

        # Identify frame groups: bindings that share the same
        # (guest_base, host_base) frame register pair.
        frame_groups = _collect_frame_groups(candidate)
        frame_slot_names: set[str] = set()
        for _key, group in frame_groups.items():
            for slot_name, _gexpr, _hexpr in group:
                frame_slot_names.add(slot_name)

        bases: dict[str, int] = {}
        base_by_root: dict[str, int] = {}
        size_by_root: dict[str, int] = {}

        # Allocate non-frame slots via the standard stride layout.
        for slot in candidate.memory.slots:
            if slot.name in frame_slot_names:
                continue
            root = roots[slot.name]
            if root not in base_by_root:
                base_by_root[root] = (
                    self._config.memory_base
                    + len(base_by_root) * self._config.memory_stride
                )
            base = base_by_root[root]
            bases[slot.name] = base
            size_by_root[root] = max(size_by_root.get(root, 0), slot.size)

        # Initialise non-frame memory content.
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

        # Allocate frame-group slots from a consistent guest frame base.
        slot_sizes = {slot.name: slot.size for slot in candidate.memory.slots}
        frame_next_base = (
            self._config.memory_base + len(base_by_root) * self._config.memory_stride
        )
        for (_guest_base, _host_base), group in frame_groups.items():
            frame_next_base = _allocate_frame_group(
                candidate.candidate_id,
                group,
                frame_next_base,
                slot_sizes,
                bases,
                guest_state,
                host_state,
            )

        _initialize_memory_registers(candidate, guest_state, host_state, bases)

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


def _collect_frame_groups(
    candidate: VerificationCandidate,
) -> dict[tuple[str, str], list[tuple[str, AddressExpr, AddressExpr]]]:
    """Group memory bindings by frame-register pair.

    Returns a mapping from ``(guest_base, host_base)`` to a list of
    ``(slot_name, guest_expr, host_expr)`` tuples.
    """
    groups: dict[tuple[str, str], list[tuple[str, AddressExpr, AddressExpr]]] = {}
    for binding in candidate.memory.bindings:
        guest_expr = parse_address_binding(binding.guest_addr)
        host_expr = parse_address_binding(binding.host_addr)
        if _is_frame_register_pair(candidate, guest_expr.base, host_expr.base):
            key = (guest_expr.base, host_expr.base)
            groups.setdefault(key, []).append((binding.slot, guest_expr, host_expr))
    return groups


def _allocate_frame_group(
    candidate_id: str,
    group: list[tuple[str, AddressExpr, AddressExpr]],
    frame_next_base: int,
    slot_sizes: dict[str, int],
    bases: dict[str, int],
    guest_state,
    host_state,
) -> int:
    """Position a frame group's slot bases from a consistent guest frame base.

    Returns the next available base address after this group's allocation.
    """
    guest_frame_base = frame_next_base

    host_frame_offset: int | None = None
    slot_bases: dict[str, int] = {}

    for slot_name, guest_expr, host_expr in group:
        guest_index_val = _INDEX_WITNESS if guest_expr.index else 0
        host_index_val = _INDEX_WITNESS if host_expr.index else 0

        slot_base = (
            guest_frame_base
            + guest_index_val * guest_expr.scale
            + guest_expr.displacement
        )

        expected_host_frame = (
            slot_base - host_index_val * host_expr.scale - host_expr.displacement
        )
        current_host_offset = expected_host_frame - guest_frame_base
        if host_frame_offset is None:
            host_frame_offset = current_host_offset
        elif current_host_offset != host_frame_offset:
            raise ValueError(
                "unsupported address expression: inconsistent frame layout"
            )
        slot_bases[slot_name] = slot_base

    bases.update(slot_bases)

    # Initialise memory content at each slot's base.
    for slot_name, slot_base in slot_bases.items():
        size = slot_sizes.get(slot_name, 0)
        if size > 0:
            content = claripy.BVS(f"{candidate_id}_{slot_name}_init", size * 8)
            guest_state.memory.store(
                slot_base, content, endness=guest_state.arch.memory_endness
            )
            host_state.memory.store(
                slot_base, content, endness=host_state.arch.memory_endness
            )

    # Advance past the range of slot addresses we just allocated.
    max_end = max(
        (slot_bases[s] + slot_sizes.get(s, 0) for s in slot_bases),
        default=frame_next_base,
    )
    return max(max_end + 0x10, frame_next_base + 0x1000)
