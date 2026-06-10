from __future__ import annotations

from angr_rule_learning.arch.flags import read_flag
from angr_rule_learning.verification.context import CheckContext
from angr_rule_learning.verification.relations import RelationChecker
from angr_rule_learning.verification.report import CheckResult


def check_flag_pair(
    context: CheckContext,
    guest_flag: str,
    host_flag: str,
) -> CheckResult:
    try:
        guest_expr = read_flag(context.guest_state, guest_flag)
        host_expr = read_flag(context.host_state, host_flag)
    except ValueError:
        return CheckResult(
            "flag",
            "unsupported",
            guest_flag,
            host_flag,
            reason="unsupported_flag",
        )
    checker = RelationChecker(symbols=context.symbols, constraints=context.constraints)
    return checker.check_equal(
        kind="flag",
        guest=guest_flag,
        host=host_flag,
        guest_expr=guest_expr,
        host_expr=host_expr,
        mismatch_reason="flag_mismatch",
    )
