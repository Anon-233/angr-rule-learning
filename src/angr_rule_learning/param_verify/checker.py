from __future__ import annotations

import claripy

from angr_rule_learning.param_verify.model import (
    ParameterizedVerifyReport,
    ParameterizedVerifyRequest,
)
from angr_rule_learning.param_verify.semantics import (
    EvalContext,
    UnsupportedRuleSemantics,
    evaluate_instructions,
)
from angr_rule_learning.smt.solver import fit_width


class ParameterizedRuleVerifier:
    def verify(self, request: ParameterizedVerifyRequest) -> ParameterizedVerifyReport:
        ctx = EvalContext(imm_domains=request.imm_domains)
        try:
            guest = evaluate_instructions(request.rule.guest, ctx)
            host = evaluate_instructions(request.rule.host, ctx)
        except UnsupportedRuleSemantics as exc:
            return ParameterizedVerifyReport(status="unsupported", reason=str(exc))

        outputs = guest.assigned & host.assigned
        if not outputs:
            return ParameterizedVerifyReport(
                status="unsupported", reason="no_common_outputs"
            )
        if outputs & (guest.prestate_reads | host.prestate_reads):
            return ParameterizedVerifyReport(
                status="unsupported",
                reason="prestate_output_placeholders_unsupported",
            )

        for output in sorted(outputs):
            guest_expr = guest.registers[output]
            host_expr = host.registers[output]
            width = max(guest_expr.size(), host_expr.size())
            diff = fit_width(guest_expr, width) != fit_width(host_expr, width)
            solver = claripy.Solver()
            for constraint in ctx.constraints:
                solver.add(constraint)
            solver.add(diff)
            if solver.satisfiable():
                return ParameterizedVerifyReport(
                    status="fail",
                    reason="parameterized_register_mismatch",
                    counterexample=_counterexample(solver, ctx.symbols),
                )

        return ParameterizedVerifyReport(status="pass")


def _counterexample(
    solver: claripy.Solver,
    symbols: dict[str, claripy.ast.BV],
) -> dict[str, int]:
    result: dict[str, int] = {}
    for name, symbol in symbols.items():
        result[name] = int(solver.eval(symbol, 1)[0])
    return result
