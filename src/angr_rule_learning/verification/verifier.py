from __future__ import annotations

import claripy

from angr_rule_learning.verification.checks import check_register_pair
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.execution import (
    FragmentExecutor,
    reg_width,
    write_reg,
)
from angr_rule_learning.verification.report import CheckResult
from angr_rule_learning.verification.report import VerificationReport


class SemanticVerifier:
    def __init__(self, executor: FragmentExecutor | None = None) -> None:
        self.executor = executor or FragmentExecutor()

    def verify(self, candidate: VerificationCandidate) -> VerificationReport:
        if candidate.output_flags:
            return VerificationReport(
                candidate.candidate_id,
                "unsupported",
                unsupported_features=("flag_outputs",),
            )

        guest_state = self.executor.make_state(candidate.guest)
        host_state = self.executor.make_state(candidate.host)
        symbols = self._initialize_input_registers(
            guest_state,
            host_state,
            candidate.input_registers,
        )

        try:
            guest_executed = self.executor.execute(candidate.guest, guest_state)
            host_executed = self.executor.execute(candidate.host, host_state)
        except ValueError:
            return VerificationReport(
                candidate.candidate_id,
                "unsupported",
                unsupported_features=("multi_successor_unsupported",),
            )

        checks: list[CheckResult] = []
        for guest_reg, host_reg in candidate.output_registers:
            check = check_register_pair(
                guest_executed.state,
                host_executed.state,
                guest_reg,
                host_reg,
                symbols,
            )
            checks.append(check)
            if check.status == "fail":
                return VerificationReport(
                    candidate.candidate_id, "fail", checks=tuple(checks)
                )

        return VerificationReport(candidate.candidate_id, "pass", checks=tuple(checks))

    @staticmethod
    def _initialize_input_registers(
        guest_state,
        host_state,
        input_registers: tuple[tuple[str, str], ...],
    ) -> dict[str, object]:
        symbols: dict[str, object] = {}
        for guest_reg, host_reg in input_registers:
            width = max(
                reg_width(guest_state, guest_reg), reg_width(host_state, host_reg)
            )
            symbol = claripy.BVS(guest_reg, width)
            write_reg(guest_state, guest_reg, symbol)
            write_reg(host_state, host_reg, symbol)
            symbols[guest_reg] = symbol
            symbols[host_reg] = symbol
        return symbols
