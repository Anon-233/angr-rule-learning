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

    checker = RelationChecker(symbols=context.symbols, constraints=context.constraints)
    checks: list[CheckResult] = []
    for index, (expectation, guest_event, host_event) in enumerate(
        zip(expectations, guest_events, host_events, strict=True)
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

        base = context.memory_layout.slot_base(expectation.slot)
        addr_result = checker.check_equal(
            kind="memory",
            guest=expectation.slot,
            host=expectation.slot,
            guest_expr=guest_event.address,
            host_expr=claripy.BVV(base, guest_event.address.size()),
            mismatch_reason="memory_address_mismatch",
            metadata={"event_index": index},
        )
        if addr_result.status != "pass":
            checks.append(addr_result)
            continue

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
