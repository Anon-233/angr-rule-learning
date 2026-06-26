"""Partial register equality helpers for semantic verification.

When a semantic input is bound to a sub-register (e.g. ``edi``, ``w1``) but
the fragment uses the wider family register (e.g. ``rdi``, ``x1``), these
helpers initialise the full family register as ``Concat(fresh_hi, semantic)``
so that the verifier explicitly models the register-view semantics of
``reg64(i32_regN)`` — low bits equal, high bits unspecified.

This is side-neutral: it applies to both Guest and Host fragments through
the same ``register_family`` / ``register_bit_range`` queries.
"""

from __future__ import annotations

import claripy

from angr_rule_learning.arch.registers import (
    register_bit_range,
    register_family,
)


def widen_input_register_view(
    state,
    register: str,
    arch: str,
    semantic_symbol,
) -> object | None:
    """If *register* is a sub-register, write the semantic symbol as the
    low bits of the widest same-family register with fresh high bits, and
    return the fresh high-bit symbol.

    When *register* is already the widest family register (e.g. ``rdi``,
    ``x1``), this is a no-op and returns ``None``.

    Returns
    -------
    claripy.ast.BV | None
        The fresh high-bit symbol written, or ``None`` if no widening
        was needed.  Callers should add the returned symbol to their
        symbol map so counterexample display can reference it.
    """
    from angr_rule_learning.verification.execution import reg_width, write_reg

    family = register_family(arch, register)
    if family is None:
        return None

    reg_range = register_bit_range(arch, register)
    family_range = register_bit_range(arch, family)
    if reg_range is None or family_range is None:
        return None

    if reg_range == family_range:
        # Already the widest register — nothing to widen.
        return None

    # Build Concat(fresh_hi, semantic).
    semantic_bits = reg_width(state, register)
    family_bits = family_range[1] + 1
    fresh_hi_bits = family_bits - semantic_bits

    fresh_hi = claripy.BVS(f"{register}_view_hi", fresh_hi_bits)
    widened = claripy.Concat(fresh_hi, semantic_symbol)
    write_reg(state, family, widened)
    return fresh_hi
