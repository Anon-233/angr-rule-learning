from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import claripy

from angr_rule_learning.smt.solver import align_widths
from angr_rule_learning.verification.report import CheckResult


class RelationChecker:
    def __init__(
        self,
        *,
        symbols: Mapping[str, claripy.ast.BV],
        constraints: tuple[object, ...] = (),
    ) -> None:
        self._symbols = symbols
        self._constraints = constraints

    def check_equal(
        self,
        *,
        kind: str,
        guest: str,
        host: str,
        guest_expr: claripy.ast.BV,
        host_expr: claripy.ast.BV,
        mismatch_reason: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> CheckResult:
        guest_expr, host_expr = align_widths(guest_expr, host_expr)
        difference = guest_expr != host_expr
        solver = claripy.Solver()
        if self._constraints:
            solver.add(*self._constraints)
        if not solver.satisfiable(extra_constraints=(difference,)):
            return CheckResult(kind, "pass", guest, host, metadata=metadata or {})
        return CheckResult(
            kind=kind,
            status="fail",
            guest=guest,
            host=host,
            reason=mismatch_reason,
            counterexample=self._counterexample(difference),
            metadata=metadata or {},
        )

    def _counterexample(self, extra_constraint: object) -> dict[str, int]:
        solver = claripy.Solver()
        if self._constraints:
            solver.add(*self._constraints)
        return {
            name: solver.eval(symbol, 1, extra_constraints=(extra_constraint,))[0]
            for name, symbol in self._symbols.items()
        }
