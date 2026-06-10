from __future__ import annotations

import claripy

from angr_rule_learning.smt.solver import align_widths
from angr_rule_learning.verification.candidate import MemoryAccessExpectation
from angr_rule_learning.verification.memory import MemoryEvent, MemoryLayout
from angr_rule_learning.verification.report import CheckResult


def check_memory_events(
    expectations: tuple[MemoryAccessExpectation, ...],
    layout: MemoryLayout,
    events: list[MemoryEvent],
) -> list[CheckResult]:
    guest_events = [e for e in events if e.side == "guest"]
    host_events = [e for e in events if e.side == "host"]

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

    checks: list[CheckResult] = []
    for expectation, guest_event, host_event in zip(
        expectations, guest_events, host_events, strict=True
    ):
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

        base = layout.slot_base(expectation.slot)
        guest_addr_solver = claripy.Solver()
        host_addr_solver = claripy.Solver()
        if guest_addr_solver.satisfiable(
            extra_constraints=[guest_event.address != base]
        ):
            checks.append(
                CheckResult(
                    kind="memory",
                    status="fail",
                    guest=expectation.slot,
                    host=expectation.slot,
                    reason="memory_address_mismatch",
                )
            )
            continue
        if host_addr_solver.satisfiable(extra_constraints=[host_event.address != base]):
            checks.append(
                CheckResult(
                    kind="memory",
                    status="fail",
                    guest=expectation.slot,
                    host=expectation.slot,
                    reason="memory_address_mismatch",
                )
            )
            continue

        guest_value, host_value = align_widths(guest_event.value, host_event.value)
        solver = claripy.Solver()
        diff = guest_value != host_value
        if solver.satisfiable(extra_constraints=[diff]):
            checks.append(
                CheckResult(
                    kind="memory",
                    status="fail",
                    guest=expectation.slot,
                    host=expectation.slot,
                    reason=(
                        "memory_read_value_mismatch"
                        if expectation.kind == "read"
                        else "memory_write_value_mismatch"
                    ),
                )
            )
            continue

        checks.append(CheckResult("memory", "pass", expectation.slot, expectation.slot))

    return checks
