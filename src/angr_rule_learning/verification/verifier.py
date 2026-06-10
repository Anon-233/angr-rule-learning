from __future__ import annotations

import claripy

import angr

from angr_rule_learning.verification.branches import (
    check_terminal_branch_guard,
    has_non_terminal_branch,
    has_terminal_unconditional_branch,
)
from angr_rule_learning.verification.checks import check_register_pair
from angr_rule_learning.verification.flags import check_flag_pair
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.context import CheckContext
from angr_rule_learning.verification.config import VerificationConfig
from angr_rule_learning.verification.execution import (
    FragmentExecutor,
    reg_width,
    write_reg,
)
from angr_rule_learning.verification.memory import (
    MemoryEventRecorder,
    MemoryInitializer,
)
from angr_rule_learning.verification.memory_checks import check_memory_events
from angr_rule_learning.verification.report import CheckResult
from angr_rule_learning.verification.report import VerificationReport


def _unsupported(
    candidate_id: str,
    kind: str,
    reason: str,
    guest: str = "",
    host: str = "",
) -> VerificationReport:
    return VerificationReport(
        candidate_id,
        "unsupported",
        checks=(CheckResult(kind, "unsupported", guest, host, reason=reason),),
        unsupported_features=(reason,),
    )


def _error(candidate_id: str, reason: str, detail: str) -> VerificationReport:
    return VerificationReport(
        candidate_id,
        "error",
        checks=(
            CheckResult(
                "execution",
                "error",
                "guest",
                "host",
                reason=reason,
                metadata={"detail": detail},
            ),
        ),
    )


def _overall_status(checks: list[CheckResult]) -> str:
    statuses = {check.status for check in checks}
    if "error" in statuses:
        return "error"
    if "unsupported" in statuses:
        return "unsupported"
    if "fail" in statuses:
        return "fail"
    return "pass"


class SemanticVerifier:
    def __init__(
        self,
        executor: FragmentExecutor | None = None,
        config: VerificationConfig | None = None,
    ) -> None:
        self.executor = executor or FragmentExecutor()
        self.config = config or VerificationConfig()

    def verify(self, candidate: VerificationCandidate) -> VerificationReport:
        try:
            return self._verify(candidate)
        except Exception as exc:
            return _error(candidate.candidate_id, "verifier_internal_error", str(exc))

    def _verify(self, candidate: VerificationCandidate) -> VerificationReport:
        if candidate.preconditions:
            return _unsupported(
                candidate.candidate_id,
                "execution",
                "preconditions",
            )

        if any(alias.relation == "may_alias" for alias in candidate.memory.alias):
            return _unsupported(
                candidate.candidate_id,
                "memory",
                "unsupported_may_alias",
            )

        guest_state = self.executor.make_state(candidate.guest)
        host_state = self.executor.make_state(candidate.host)
        symbols = self._initialize_input_registers(
            guest_state,
            host_state,
            candidate.input_registers,
        )

        try:
            layout = MemoryInitializer(self.config).initialize(
                candidate, guest_state, host_state
            )
        except ValueError as exc:
            if str(exc).startswith("unsupported address expression"):
                return _unsupported(
                    candidate.candidate_id,
                    "memory",
                    "unsupported_address_expression",
                    "memory",
                    "memory",
                )
            if str(exc) == "invalid_alias_declaration":
                return _error(
                    candidate.candidate_id, "invalid_alias_declaration", str(exc)
                )
            raise

        recorder = MemoryEventRecorder()
        recorder.install(guest_state, "guest")
        recorder.install(host_state, "host")

        if has_non_terminal_branch(
            candidate.guest, guest_state
        ) or has_non_terminal_branch(candidate.host, host_state):
            return _unsupported(
                candidate.candidate_id,
                "branch",
                "non_terminal_branch_unsupported",
                "branch",
                "branch",
            )

        try:
            guest_successors = self.executor.successors(candidate.guest, guest_state)
            host_successors = self.executor.successors(candidate.host, host_state)
        except angr.errors.SimError:
            return _unsupported(
                candidate.candidate_id,
                "branch",
                "branch_shape_unsupported",
                "guest",
                "host",
            )

        if guest_successors.count > 2 or host_successors.count > 2:
            return _unsupported(
                candidate.candidate_id,
                "branch",
                "multi_branch_unsupported",
                "guest",
                "host",
            )

        if has_terminal_unconditional_branch(candidate.guest, guest_state):
            return _unsupported(
                candidate.candidate_id,
                "branch",
                "unconditional_branch_unsupported",
                "branch",
                "branch",
            )

        if has_terminal_unconditional_branch(candidate.host, host_state):
            return _unsupported(
                candidate.candidate_id,
                "branch",
                "unconditional_branch_unsupported",
                "branch",
                "branch",
            )

        if guest_successors.count == 0 or host_successors.count == 0:
            return _unsupported(
                candidate.candidate_id,
                "branch",
                "branch_shape_unsupported",
                "guest",
                "host",
            )

        is_branch = guest_successors.count == 2 or host_successors.count == 2

        if is_branch:
            guest_post = guest_successors.successors[0]
            host_post = host_successors.successors[0]

            branch_context = CheckContext(
                candidate=candidate,
                guest_state=guest_post,
                host_state=host_post,
                symbols=symbols,
                memory_layout=layout,
                memory_events=tuple(recorder.events),
            )

            checks: list[CheckResult] = []

            memory_checks = check_memory_events(branch_context)
            checks.extend(memory_checks)
            if (
                any(check.status != "pass" for check in memory_checks)
                and self.config.fail_fast
            ):
                return VerificationReport(
                    candidate.candidate_id,
                    _overall_status(checks),
                    checks=tuple(checks),
                )

            for guest_flag, host_flag in candidate.output_flags:
                check = check_flag_pair(branch_context, guest_flag, host_flag)
                checks.append(check)
                if check.status != "pass" and self.config.fail_fast:
                    return VerificationReport(
                        candidate.candidate_id,
                        _overall_status(checks),
                        checks=tuple(checks),
                    )

            if guest_successors.count == 2 and host_successors.count == 2:
                pre_context = CheckContext(
                    candidate=candidate,
                    guest_state=guest_state,
                    host_state=host_state,
                    symbols=symbols,
                    memory_layout=layout,
                    memory_events=tuple(recorder.events),
                )
                branch_check = check_terminal_branch_guard(
                    pre_context,
                    candidate.guest,
                    candidate.host,
                    guest_successors.successors,
                    host_successors.successors,
                )
            else:
                branch_check = CheckResult(
                    "branch",
                    "unsupported",
                    "branch",
                    "branch",
                    reason="branch_shape_unsupported",
                )

            if branch_check is not None:
                checks.append(branch_check)
                if branch_check.status != "pass" and self.config.fail_fast:
                    return VerificationReport(
                        candidate.candidate_id,
                        _overall_status(checks),
                        checks=tuple(checks),
                    )

            if candidate.output_registers:
                checks.append(
                    CheckResult(
                        "register",
                        "unsupported",
                        "registers",
                        "registers",
                        reason="branch_register_outputs_unsupported",
                    )
                )

            return VerificationReport(
                candidate.candidate_id,
                _overall_status(checks),
                checks=tuple(checks),
            )

        guest_executed = guest_successors.successors[0]
        host_executed = host_successors.successors[0]

        context = CheckContext(
            candidate=candidate,
            guest_state=guest_executed,
            host_state=host_executed,
            symbols=symbols,
            memory_layout=layout,
            memory_events=tuple(recorder.events),
        )

        checks: list[CheckResult] = []
        memory_checks = check_memory_events(context)
        checks.extend(memory_checks)
        if (
            any(check.status != "pass" for check in memory_checks)
            and self.config.fail_fast
        ):
            return VerificationReport(
                candidate.candidate_id, _overall_status(checks), checks=tuple(checks)
            )

        for guest_flag, host_flag in candidate.output_flags:
            check = check_flag_pair(context, guest_flag, host_flag)
            checks.append(check)
            if check.status != "pass" and self.config.fail_fast:
                return VerificationReport(
                    candidate.candidate_id,
                    _overall_status(checks),
                    checks=tuple(checks),
                )

        for guest_reg, host_reg in candidate.output_registers:
            check = check_register_pair(context, guest_reg, host_reg)
            checks.append(check)
            if check.status != "pass" and self.config.fail_fast:
                return VerificationReport(
                    candidate.candidate_id,
                    _overall_status(checks),
                    checks=tuple(checks),
                )

        return VerificationReport(
            candidate.candidate_id,
            _overall_status(checks),
            checks=tuple(checks),
        )

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
