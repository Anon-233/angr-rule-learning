from __future__ import annotations

import claripy

from angr_rule_learning.verification.context import CheckContext
from angr_rule_learning.verification.relations import RelationChecker
from angr_rule_learning.verification.report import CheckResult


def check_memory_events(context: CheckContext) -> list[CheckResult]:
    expectations = context.candidate.memory.accesses
    guest_events = [e for e in context.memory_events if e.side == "guest"]
    host_events = [e for e in context.memory_events if e.side == "host"]

    if len(guest_events) != len(expectations) or len(host_events) != len(expectations):
        return [
            CheckResult(
                kind="memory",
                status="fail",
                guest="events",
                host="events",
                reason="memory_access_count_mismatch",
            )
        ]

    # --- ordered match --------------------------------------------------
    ordered_checks = _check_ordered(expectations, guest_events, host_events, context)
    if ordered_checks is not None:
        return ordered_checks

    # --- slot-based match -----------------------------------------------
    slot_checks = _check_by_slot(expectations, guest_events, host_events, context)
    if slot_checks is not None:
        return slot_checks

    return [
        CheckResult(
            kind="memory",
            status="fail",
            guest="events",
            host="events",
            reason="memory_access_order_conflict",
        )
    ]


def _check_ordered(
    expectations,
    guest_events,
    host_events,
    context: CheckContext,
) -> list[CheckResult] | None:
    """Check events paired by execution order in two phases.

    Phase 1 validates kind, width, and address for every event.  If any
    address does not match and there are multiple slots the function
    returns ``None`` to signal the caller to try slot-based matching.

    Phase 2 compares values.  This separation guarantees that a partial
    pass from Phase 1 is never mistaken for a full equivalence result
    when a later event has an address mismatch.
    """
    multi_slot = len(expectations) >= 2
    checker = RelationChecker(symbols=context.symbols, constraints=context.constraints)

    # -- Phase 1: kind, width, address ------------------------------------
    fail_checks: list[CheckResult] = []

    for index, (expectation, guest_event, host_event) in enumerate(
        zip(expectations, guest_events, host_events, strict=True)
    ):
        if guest_event.kind != expectation.kind or host_event.kind != expectation.kind:
            fail_checks.append(
                CheckResult(
                    kind="memory",
                    status="fail",
                    guest=guest_event.kind,
                    host=host_event.kind,
                    reason="memory_access_kind_mismatch",
                )
            )
            continue

        if (
            guest_event.width != expectation.width
            or host_event.width != expectation.width
        ):
            fail_checks.append(
                CheckResult(
                    kind="memory",
                    status="fail",
                    guest=str(guest_event.width),
                    host=str(host_event.width),
                    reason="memory_access_width_mismatch",
                )
            )
            continue

        base = context.memory_layout.slot_base(expectation.slot)

        guest_addr_result = checker.check_equal(
            kind="memory",
            guest=expectation.slot,
            host=expectation.slot,
            guest_expr=guest_event.address,
            host_expr=claripy.BVV(base, guest_event.address.size()),
            mismatch_reason="guest_memory_address_mismatch",
            metadata={"event_index": index, "side": "guest"},
        )
        if guest_addr_result.status != "pass":
            if multi_slot:
                return None  # fall back to slot-based match
            fail_checks.append(guest_addr_result)
            continue

        host_addr_result = checker.check_equal(
            kind="memory",
            guest=expectation.slot,
            host=expectation.slot,
            guest_expr=claripy.BVV(base, host_event.address.size()),
            host_expr=host_event.address,
            mismatch_reason="host_memory_address_mismatch",
            metadata={"event_index": index, "side": "host"},
        )
        if host_addr_result.status != "pass":
            if multi_slot:
                return None  # fall back to slot-based match
            fail_checks.append(host_addr_result)
            continue

    if fail_checks:
        return fail_checks

    # -- Phase 2: values (only reached when all addresses matched) --------
    checks: list[CheckResult] = []
    for index, (expectation, guest_event, host_event) in enumerate(
        zip(expectations, guest_events, host_events, strict=True)
    ):
        value_result = checker.check_equal(
            kind="memory",
            guest=expectation.slot,
            host=expectation.slot,
            guest_expr=guest_event.value,
            host_expr=host_event.value,
            mismatch_reason=(
                "memory_read_value_mismatch"
                if expectation.kind == "read"
                else "memory_write_value_mismatch"
            ),
            metadata={"event_index": index, "width": expectation.width},
        )
        checks.append(value_result)
    return checks


def _check_by_slot(
    expectations,
    guest_events,
    host_events,
    context: CheckContext,
) -> list[CheckResult] | None:
    """Match events to slots by concrete address, then check per slot.

    Only allowed when all accesses share the same kind (all read / all
    write), there are no alias declarations, and the mapping is a
    unique bijection.
    """

    # Guard: only when all accesses are the same kind.
    kinds = {exp.kind for exp in expectations}
    if len(kinds) != 1:
        return None

    # Guard: no alias declarations.
    if context.candidate.memory.alias:
        return None

    # Evaluate concrete addresses.
    try:
        guest_addrs = [context.guest_state.solver.eval(e.address) for e in guest_events]
        host_addrs = [context.host_state.solver.eval(e.address) for e in host_events]
    except Exception:
        return None

    # Build slot base lookup.
    slot_bases: dict[str, int] = {}
    for exp in expectations:
        slot_bases[exp.slot] = context.memory_layout.slot_base(exp.slot)

    # Verify non-overlapping address ranges.
    slot_ranges = [
        (slot_bases[exp.slot], slot_bases[exp.slot] + exp.width) for exp in expectations
    ]
    slot_ranges.sort()
    for i in range(len(slot_ranges) - 1):
        if slot_ranges[i][1] > slot_ranges[i + 1][0]:
            return None  # overlapping

    # Match each event to the unique slot whose base matches its address.
    def _match_side(
        addrs: list[int],
        events: list,
        slot_bases: dict[str, int],
    ) -> dict[str, int] | None:
        """Return ``{slot_name: event_index}`` if a bijection exists."""
        slot_to_idx: dict[str, int] = {}
        used_addrs: set[int] = set()
        for idx, addr in enumerate(addrs):
            matched = None
            for slot_name, base in slot_bases.items():
                if addr == base:
                    matched = slot_name
                    break
            if matched is None:
                return None
            if matched in slot_to_idx:
                return None  # duplicate slot match
            if addr in used_addrs:
                return None  # duplicate address
            slot_to_idx[matched] = idx
            used_addrs.add(addr)
        return slot_to_idx

    guest_slot_to_idx = _match_side(guest_addrs, guest_events, slot_bases)
    if guest_slot_to_idx is None:
        return None
    host_slot_to_idx = _match_side(host_addrs, host_events, slot_bases)
    if host_slot_to_idx is None:
        return None

    # Verify both sides map to the same set of slots.
    if set(guest_slot_to_idx.keys()) != set(host_slot_to_idx.keys()):
        return None

    # Run checks with events reordered by slot.
    checker = RelationChecker(symbols=context.symbols, constraints=context.constraints)
    checks: list[CheckResult] = []
    for expectation in expectations:
        slot = expectation.slot
        guest_idx = guest_slot_to_idx[slot]
        host_idx = host_slot_to_idx[slot]
        guest_event = guest_events[guest_idx]
        host_event = host_events[host_idx]

        if guest_event.kind != expectation.kind or host_event.kind != expectation.kind:
            checks.append(
                CheckResult(
                    kind="memory",
                    status="fail",
                    guest=guest_event.kind,
                    host=host_event.kind,
                    reason="memory_access_kind_mismatch",
                )
            )
            continue

        if (
            guest_event.width != expectation.width
            or host_event.width != expectation.width
        ):
            checks.append(
                CheckResult(
                    kind="memory",
                    status="fail",
                    guest=str(guest_event.width),
                    host=str(host_event.width),
                    reason="memory_access_width_mismatch",
                )
            )
            continue

        base = context.memory_layout.slot_base(slot)

        guest_addr_result = checker.check_equal(
            kind="memory",
            guest=slot,
            host=slot,
            guest_expr=guest_event.address,
            host_expr=claripy.BVV(base, guest_event.address.size()),
            mismatch_reason="guest_memory_address_mismatch",
            metadata={"side": "guest"},
        )
        if guest_addr_result.status != "pass":
            checks.append(guest_addr_result)
            continue

        host_addr_result = checker.check_equal(
            kind="memory",
            guest=slot,
            host=slot,
            guest_expr=claripy.BVV(base, host_event.address.size()),
            host_expr=host_event.address,
            mismatch_reason="host_memory_address_mismatch",
            metadata={"side": "host"},
        )
        if host_addr_result.status != "pass":
            checks.append(host_addr_result)
            continue

        value_result = checker.check_equal(
            kind="memory",
            guest=slot,
            host=slot,
            guest_expr=guest_event.value,
            host_expr=host_event.value,
            mismatch_reason=(
                "memory_read_value_mismatch"
                if expectation.kind == "read"
                else "memory_write_value_mismatch"
            ),
            metadata={"width": expectation.width},
        )
        checks.append(value_result)

    return checks
