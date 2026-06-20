from __future__ import annotations

from dataclasses import dataclass

import claripy

from angr_rule_learning.extraction.candidates import fragment_for_window
from angr_rule_learning.extraction.liveness import WindowSurface
from angr_rule_learning.extraction.models import InstructionWindow
from angr_rule_learning.verification.execution import (
    FragmentExecutor,
    read_reg,
    reg_width,
    write_reg,
)


@dataclass(frozen=True)
class SymbolicRegisterTransfer:
    input_registers: tuple[str, ...]
    input_symbols: tuple[claripy.ast.BV, ...]
    input_widths: tuple[int, ...]
    output_registers: tuple[str, ...]
    output_expressions: tuple[claripy.ast.BV, ...]
    output_widths: tuple[int, ...]


class RegisterTransferError(ValueError):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class RegisterTransferExtractor:
    def __init__(self, executor: FragmentExecutor | None = None) -> None:
        self._executor = executor or FragmentExecutor()

    def extract(
        self,
        window: InstructionWindow,
        surface: WindowSurface,
        *,
        side: str,
    ) -> SymbolicRegisterTransfer:
        if side not in {"guest", "host"}:
            raise ValueError(f"unsupported transfer side: {side}")

        fragment = fragment_for_window(window)
        state = self._executor.make_state(fragment)
        input_symbols: list[claripy.ast.BV] = []
        input_widths: list[int] = []
        for register in surface.inputs:
            width = reg_width(state, register)
            symbol = claripy.BVS(
                f"cegis_{side}_{register}",
                width,
                explicit_name=True,
            )
            write_reg(state, register, symbol)
            input_symbols.append(symbol)
            input_widths.append(width)

        successors = self._executor.successors(fragment, state)
        if successors.count != 1:
            raise RegisterTransferError("execution_shape")
        post_state = successors.successors[0]

        output_expressions = tuple(
            read_reg(post_state, register) for register in surface.outputs
        )
        allowed_variables = {
            variable for symbol in input_symbols for variable in symbol.variables
        }
        if any(
            expression.variables - allowed_variables
            for expression in output_expressions
        ):
            raise RegisterTransferError("unmodeled_input")

        return SymbolicRegisterTransfer(
            input_registers=surface.inputs,
            input_symbols=tuple(input_symbols),
            input_widths=tuple(input_widths),
            output_registers=surface.outputs,
            output_expressions=output_expressions,
            output_widths=tuple(
                reg_width(post_state, register) for register in surface.outputs
            ),
        )
