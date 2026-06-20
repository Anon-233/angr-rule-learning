from __future__ import annotations

import claripy

from angr_rule_learning.extraction.register_cegis import (
    BindingSample,
    SelectorSynthesizer,
)
from angr_rule_learning.extraction.register_transfer import SymbolicRegisterTransfer


def _transfer(
    inputs: tuple[str, ...],
    symbols: tuple[claripy.ast.BV, ...],
    widths: tuple[int, ...],
    outputs: tuple[str, ...],
    expressions: tuple[claripy.ast.BV, ...],
) -> SymbolicRegisterTransfer:
    return SymbolicRegisterTransfer(
        input_registers=inputs,
        input_symbols=symbols,
        input_widths=widths,
        output_registers=outputs,
        output_expressions=expressions,
        output_widths=tuple(expression.size() for expression in expressions),
    )


def _symbol(name: str, width: int = 32) -> claripy.ast.BV:
    return claripy.BVS(name, width, explicit_name=True)


def test_selector_synthesizer_finds_swapped_shift_inputs() -> None:
    g_value, g_shift = _symbol("g_value"), _symbol("g_shift")
    h_shift, h_value = _symbol("h_shift"), _symbol("h_value")
    guest = _transfer(
        ("w0", "w1"),
        (g_value, g_shift),
        (32, 32),
        ("w0",),
        (g_value << g_shift,),
    )
    host = _transfer(
        ("esi", "edi"),
        (h_shift, h_value),
        (32, 32),
        ("eax",),
        (h_value << h_shift,),
    )

    result = SelectorSynthesizer().synthesize(
        guest,
        host,
        (BindingSample((3, 1)),),
    )

    assert result is not None
    assert result.input_registers == (("w1", "esi"), ("w0", "edi"))
    assert result.output_registers == (("w0", "eax"),)


def test_selector_domains_require_exact_width() -> None:
    g32, g64 = _symbol("g32", 32), _symbol("g64", 64)
    h64, h32 = _symbol("h64", 64), _symbol("h32", 32)
    guest = _transfer(
        ("w0", "x1"),
        (g32, g64),
        (32, 64),
        ("w0", "x1"),
        (g32, g64),
    )
    host = _transfer(
        ("rax", "edi"),
        (h64, h32),
        (64, 32),
        ("rax", "edi"),
        (h64, h32),
    )

    result = SelectorSynthesizer().synthesize(
        guest,
        host,
        (BindingSample((7, 11)),),
    )

    assert result is not None
    assert result.input_registers == (("x1", "rax"), ("w0", "edi"))
    assert result.output_registers == (("x1", "rax"), ("w0", "edi"))


def test_all_different_output_selectors_can_make_samples_unsatisfiable() -> None:
    g0, g1 = _symbol("g0"), _symbol("g1")
    h0, h1 = _symbol("h0"), _symbol("h1")
    guest = _transfer(
        ("w0", "w1"),
        (g0, g1),
        (32, 32),
        ("w0", "w1"),
        (g0, g1),
    )
    host = _transfer(
        ("edi", "esi"),
        (h0, h1),
        (32, 32),
        ("eax", "edx"),
        (h0, h0),
    )

    result = SelectorSynthesizer().synthesize(
        guest,
        host,
        (BindingSample((1, 2)),),
    )

    assert result is None
