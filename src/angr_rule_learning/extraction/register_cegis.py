from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

import claripy

from angr_rule_learning.extraction.register_bindings import RegisterBindingResult
from angr_rule_learning.extraction.register_transfer import SymbolicRegisterTransfer


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
        claripy.BVV(value, width)
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
