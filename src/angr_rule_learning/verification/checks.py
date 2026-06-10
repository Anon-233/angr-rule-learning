from __future__ import annotations

from angr_rule_learning.verification.context import CheckContext
from angr_rule_learning.verification.execution import read_reg
from angr_rule_learning.verification.relations import RelationChecker
from angr_rule_learning.verification.report import CheckResult


def check_register_pair(
    context: CheckContext,
    guest_reg: str,
    host_reg: str,
) -> CheckResult:
    checker = RelationChecker(
        symbols=context.symbols,
        constraints=context.constraints,
    )
    return checker.check_equal(
        kind="register",
        guest=guest_reg,
        host=host_reg,
        guest_expr=read_reg(context.guest_state, guest_reg),
        host_expr=read_reg(context.host_state, host_reg),
        mismatch_reason="register_mismatch",
    )
