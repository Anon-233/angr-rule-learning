"""Partial register equality helpers for semantic verification.

When a semantic input is bound to a sub-register (e.g. ``edi``) but the
fragment actually uses the wider family register (e.g. ``rdi``), these
helpers initialise the full family register as ``Concat(fresh_hi, semantic)``
so that the verifier explicitly models the register-view semantics of
``reg64(i32_regN)`` — low bits equal, high bits unspecified.
"""

from __future__ import annotations

import claripy

from angr_rule_learning.arch.registers import (
    register_bit_range,
    register_family,
)


def widen_host_input_register(
    state,
    host_reg: str,
    arch: str,
    semantic_symbol,
) -> None:
    """If *host_reg* is a sub-register, write the semantic symbol as the
    low bits of the widest same-family register, with fresh high bits.

    When *host_reg* is already the widest family register (e.g. ``rdi``),
    this is a no-op — the caller should write the symbol directly.
    """
    from angr_rule_learning.verification.execution import reg_width, write_reg

    family = register_family(arch, host_reg)
    if family is None:
        return

    host_range = register_bit_range(arch, host_reg)
    family_range = register_bit_range(arch, family)
    if host_range is None or family_range is None:
        return

    if host_range == family_range:
        # Already the widest register — nothing to widen.
        return

    # Build Concat(fresh_hi, semantic).
    semantic_bits = reg_width(state, host_reg)
    family_bits = family_range[1] + 1
    fresh_hi_bits = family_bits - semantic_bits

    fresh_hi = claripy.BVS(f"{host_reg}_hi", fresh_hi_bits)
    widened = claripy.Concat(fresh_hi, semantic_symbol)
    write_reg(state, family, widened)
