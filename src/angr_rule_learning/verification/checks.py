from __future__ import annotations

from collections.abc import Mapping

from angr_rule_learning.smt.solver import align_widths, merged_solver
from angr_rule_learning.verification.execution import read_reg
from angr_rule_learning.verification.report import CheckResult


def check_register_pair(
    guest_state,
    host_state,
    guest_reg: str,
    host_reg: str,
    symbols: Mapping[str, object],
) -> CheckResult:
    guest_value, host_value = align_widths(
        read_reg(guest_state, guest_reg),
        read_reg(host_state, host_reg),
    )
    difference = guest_value != host_value
    solver = merged_solver(guest_state, host_state)

    if not solver.satisfiable(extra_constraints=(difference,)):
        return CheckResult(
            kind="register",
            status="pass",
            guest=guest_reg,
            host=host_reg,
        )

    counterexample = {
        name: solver.eval(symbol, 1, extra_constraints=(difference,))[0]
        for name, symbol in symbols.items()
    }
    return CheckResult(
        kind="register",
        status="fail",
        guest=guest_reg,
        host=host_reg,
        reason="register_mismatch",
        counterexample=counterexample,
    )
