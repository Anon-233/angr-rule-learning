from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

import claripy

from angr_rule_learning.arch.registers import (
    is_fixed_role_register,
    register_bit_range,
)
from angr_rule_learning.extraction.blocks import is_control_flow
from angr_rule_learning.extraction.candidates import build_verification_candidate
from angr_rule_learning.extraction.liveness import is_condition_family
from angr_rule_learning.extraction.memory_surfaces import MemorySurface
from angr_rule_learning.extraction.register_bindings import (
    BindingProblem,
    RegisterBindingResult,
    RegisterBindingSolver,
)
from angr_rule_learning.extraction.register_transfer import (
    RegisterTransferError,
    RegisterTransferExtractor,
    SymbolicRegisterTransfer,
)
from angr_rule_learning.verification.candidate import MemorySpec
from angr_rule_learning.verification.report import VerificationReport
from angr_rule_learning.verification.verifier import SemanticVerifier


@dataclass(frozen=True)
class BindingSample:
    guest_input_values: tuple[int, ...]


@dataclass(frozen=True)
class _Selector:
    expression: claripy.ast.BV
    domain: tuple[int, ...]


class SelectorSynthesizer:
    def synthesize(
        self,
        guest: SymbolicRegisterTransfer,
        host: SymbolicRegisterTransfer,
        samples: tuple[BindingSample, ...],
    ) -> RegisterBindingResult | None:
        if len(guest.input_registers) != len(host.input_registers):
            return None
        if len(guest.output_registers) != len(host.output_registers):
            return None

        input_selectors = _selectors_for_widths(
            "input",
            guest.input_widths,
            host.input_widths,
        )
        output_selectors = _selectors_for_widths(
            "output",
            guest.output_widths,
            host.output_widths,
        )
        if input_selectors is None or output_selectors is None:
            return None

        solver = claripy.Solver()
        _constrain_selectors(solver, input_selectors)
        _constrain_selectors(solver, output_selectors)
        for sample in samples:
            if len(sample.guest_input_values) != len(guest.input_symbols):
                raise ValueError("binding sample input count mismatch")
            _add_sample_constraints(
                solver,
                guest,
                host,
                input_selectors,
                output_selectors,
                sample,
            )

        if not solver.satisfiable():
            return None

        input_pairs = tuple(
            (
                guest.input_registers[solver.eval(selector.expression, 1)[0]],
                host.input_registers[host_index],
            )
            for host_index, selector in enumerate(input_selectors)
        )
        output_pairs = tuple(
            (
                guest.output_registers[solver.eval(selector.expression, 1)[0]],
                host.output_registers[host_index],
            )
            for host_index, selector in enumerate(output_selectors)
        )
        return RegisterBindingResult(
            input_registers=input_pairs,
            output_registers=output_pairs,
        )


class CegisRegisterBindingSolver(RegisterBindingSolver):
    def __init__(
        self,
        verifier: SemanticVerifier,
        *,
        transfer_extractor: RegisterTransferExtractor | None = None,
        synthesizer: SelectorSynthesizer | None = None,
        max_iterations: int = 16,
    ) -> None:
        if max_iterations < 1:
            raise ValueError("max_iterations must be positive")
        self._verifier = verifier
        self._transfer_extractor = transfer_extractor or RegisterTransferExtractor()
        self._synthesizer = synthesizer or SelectorSynthesizer()
        self._max_iterations = max_iterations

    def solve(self, problem: BindingProblem) -> RegisterBindingResult:
        eligibility_detail = _eligibility_detail(problem)
        if eligibility_detail is not None:
            return _unsupported(eligibility_detail)

        try:
            guest_transfer = self._transfer_extractor.extract(
                problem.pair.guest,
                problem.guest_surface,
                side="guest",
            )
            host_transfer = self._transfer_extractor.extract(
                problem.pair.host,
                problem.host_surface,
                side="host",
            )
        except RegisterTransferError as exc:
            return _inconclusive(exc.detail)

        samples = [BindingSample((0,) * len(guest_transfer.input_registers))]
        for _iteration in range(self._max_iterations):
            proposal = self._synthesizer.synthesize(
                guest_transfer,
                host_transfer,
                tuple(samples),
            )
            if proposal is None:
                return RegisterBindingResult(
                    skip_reason="register_binding_unsat",
                )

            candidate = build_verification_candidate(
                problem.pair,
                proposal,
                MemorySurface(MemorySpec()),
            )
            report = self._verifier.verify(candidate)
            if report.equivalent:
                return proposal
            if report.status == "unsupported":
                return _inconclusive("verification_unsupported")
            if report.status == "error":
                return _inconclusive("verification_error")

            counterexample = _guest_counterexample(
                report,
                guest_transfer,
            )
            if counterexample is None:
                return _inconclusive("counterexample_missing")
            if counterexample in samples:
                return _inconclusive("counterexample_repeated")
            samples.append(counterexample)

        return _inconclusive("iteration_limit")


def make_register_binding_solver(
    strategy: str,
    *,
    verifier: SemanticVerifier | None = None,
) -> RegisterBindingSolver:
    if strategy == "positional":
        return RegisterBindingSolver()
    if strategy == "cegis":
        if verifier is None:
            raise ValueError("CEGIS register binding requires a semantic verifier")
        return CegisRegisterBindingSolver(verifier)
    raise ValueError(f"unsupported register binding strategy: {strategy}")


def _unsupported(detail: str) -> RegisterBindingResult:
    return RegisterBindingResult(
        skip_reason="unsupported_register_binding_surface",
        skip_detail=detail,
    )


def _inconclusive(detail: str) -> RegisterBindingResult:
    return RegisterBindingResult(
        skip_reason="register_binding_inconclusive",
        skip_detail=detail,
    )


def _eligibility_detail(problem: BindingProblem) -> str | None:
    guest_surface = problem.guest_surface
    host_surface = problem.host_surface
    if problem.has_memory:
        return "memory_surface"
    if guest_surface.kind != "register" or host_surface.kind != "register":
        return "branch_surface"
    if any(
        is_control_flow(inst.arch, inst.mnemonic)
        for window in (problem.pair.guest, problem.pair.host)
        for inst in window.instructions
    ):
        return "branch_surface"
    if _has_flag_surface(problem):
        return "flag_surface"

    guest_inputs = guest_surface.inputs
    host_inputs = host_surface.inputs
    guest_outputs = guest_surface.outputs
    host_outputs = host_surface.outputs
    counts = tuple(
        len(registers)
        for registers in (
            guest_inputs,
            host_inputs,
            guest_outputs,
            host_outputs,
        )
    )
    if any(count < 1 or count > 4 for count in counts):
        return "register_limit_exceeded"
    if len(guest_inputs) != len(host_inputs) or len(guest_outputs) != len(host_outputs):
        return "width_domain_empty"

    guest_arch = problem.pair.guest.instructions[0].arch
    host_arch = problem.pair.host.instructions[0].arch
    if any(
        is_fixed_role_register(arch, register)
        for arch, registers in (
            (guest_arch, guest_inputs),
            (host_arch, host_inputs),
        )
        for register in registers
    ):
        return "unmodeled_input"

    guest_input_widths = _register_widths(guest_arch, guest_inputs)
    host_input_widths = _register_widths(host_arch, host_inputs)
    guest_output_widths = _register_widths(guest_arch, guest_outputs)
    host_output_widths = _register_widths(host_arch, host_outputs)
    if None in {
        guest_input_widths,
        host_input_widths,
        guest_output_widths,
        host_output_widths,
    }:
        return "non_integer_register"
    assert guest_input_widths is not None
    assert host_input_widths is not None
    assert guest_output_widths is not None
    assert host_output_widths is not None
    if not _width_domains_exist(guest_input_widths, host_input_widths):
        return "width_domain_empty"
    if not _width_domains_exist(guest_output_widths, host_output_widths):
        return "width_domain_empty"
    return None


def _has_flag_surface(problem: BindingProblem) -> bool:
    for window, surface in (
        (problem.pair.guest, problem.guest_surface),
        (problem.pair.host, problem.host_surface),
    ):
        arch = window.instructions[0].arch
        families = surface.input_families + surface.output_families
        if any(is_condition_family(arch, family) for family in families):
            return True
        if any(
            is_condition_family(arch, register)
            for register in surface.inputs + surface.outputs
        ):
            return True
    return False


def _register_widths(
    arch: str,
    registers: tuple[str, ...],
) -> tuple[int, ...] | None:
    widths: list[int] = []
    for register in registers:
        bit_range = register_bit_range(arch, register)
        if bit_range is None:
            return None
        widths.append(bit_range[1] - bit_range[0] + 1)
    return tuple(widths)


def _width_domains_exist(
    guest_widths: tuple[int, ...],
    host_widths: tuple[int, ...],
) -> bool:
    return sorted(guest_widths) == sorted(host_widths)


def _guest_counterexample(
    report: VerificationReport,
    transfer: SymbolicRegisterTransfer,
) -> BindingSample | None:
    counterexample = next(
        (
            check.counterexample
            for check in report.checks
            if check.status == "fail" and check.counterexample
        ),
        None,
    )
    if counterexample is None:
        return None
    if any(register not in counterexample for register in transfer.input_registers):
        return None
    return BindingSample(
        tuple(
            counterexample[register] & ((1 << width) - 1)
            for register, width in zip(
                transfer.input_registers,
                transfer.input_widths,
                strict=True,
            )
        )
    )


def _selectors_for_widths(
    kind: str,
    guest_widths: tuple[int, ...],
    host_widths: tuple[int, ...],
) -> tuple[_Selector, ...] | None:
    selector_bits = max(1, (max(1, len(guest_widths)) - 1).bit_length())
    selectors: list[_Selector] = []
    for host_index, host_width in enumerate(host_widths):
        domain = tuple(
            guest_index
            for guest_index, guest_width in enumerate(guest_widths)
            if guest_width == host_width
        )
        if not domain:
            return None
        selectors.append(
            _Selector(
                claripy.BVS(
                    f"cegis_{kind}_selector_{host_index}",
                    selector_bits,
                    explicit_name=True,
                ),
                domain,
            )
        )
    return tuple(selectors)


def _constrain_selectors(
    solver: claripy.Solver,
    selectors: tuple[_Selector, ...],
) -> None:
    for selector in selectors:
        solver.add(
            claripy.Or(*(selector.expression == value for value in selector.domain))
        )
    for left, right in combinations(selectors, 2):
        solver.add(left.expression != right.expression)


def _add_sample_constraints(
    solver: claripy.Solver,
    guest: SymbolicRegisterTransfer,
    host: SymbolicRegisterTransfer,
    input_selectors: tuple[_Selector, ...],
    output_selectors: tuple[_Selector, ...],
    sample: BindingSample,
) -> None:
    guest_values = tuple(
        claripy.BVV(value & ((1 << width) - 1), width)
        for value, width in zip(
            sample.guest_input_values,
            guest.input_widths,
            strict=True,
        )
    )
    guest_replacements = {
        symbol.hash(): value
        for symbol, value in zip(guest.input_symbols, guest_values, strict=True)
    }
    guest_outputs = tuple(
        claripy.replace_dict(expression, guest_replacements)
        for expression in guest.output_expressions
    )

    host_replacements = {
        symbol.hash(): _select_expression(selector, guest_values)
        for symbol, selector in zip(
            host.input_symbols,
            input_selectors,
            strict=True,
        )
    }
    host_outputs = tuple(
        claripy.replace_dict(expression, host_replacements)
        for expression in host.output_expressions
    )

    for host_output, selector in zip(
        host_outputs,
        output_selectors,
        strict=True,
    ):
        solver.add(host_output == _select_expression(selector, guest_outputs))


def _select_expression(
    selector: _Selector,
    values: tuple[claripy.ast.BV, ...],
) -> claripy.ast.BV:
    selected_values = tuple(values[index] for index in selector.domain)
    cases = tuple(
        (selector.expression == index, values[index]) for index in selector.domain[:-1]
    )
    return claripy.ite_cases(cases, selected_values[-1])
