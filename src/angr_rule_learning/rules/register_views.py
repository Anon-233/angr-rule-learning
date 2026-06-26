"""Use-site register view / cast resolution.

Detects when a physical register operand should be expressed as a width
view of an already-mapped same-family placeholder, e.g. ``rdi`` →
``reg64(i32_reg2)`` when ``edi`` is already mapped to ``i32_reg2`` and
the instruction is an x86-64 LEA.
"""

from __future__ import annotations

import re as _re
from dataclasses import dataclass

from angr_rule_learning.arch.registers import (
    normalize_register_name,
    register_bit_range,
    register_family,
)
from angr_rule_learning.arch.registry import canonical_arch_name
from angr_rule_learning.extraction.models import ExtractedInstruction
from angr_rule_learning.rules.registers import known_register_tokens


@dataclass(frozen=True)
class RegisterViewReplacement:
    """Describes a single register → view-cast text replacement."""

    physical_register: str
    """Normalized register name being replaced (e.g. ``"rdi"``)."""

    placeholder: str
    """The base placeholder the view wraps (e.g. ``"i32_reg2"``)."""

    replacement_text: str
    """Full replacement text (e.g. ``"reg64(i32_reg2)"``)."""

    reason: str
    """Why the view is applied (e.g. ``"lea_address_operand_same_family_widen"``)."""


def resolve_register_views(
    arch: str,
    instruction: ExtractedInstruction,
    mapping: dict[str, str],
) -> list[RegisterViewReplacement]:
    """Find physical registers in *instruction* that need a width view cast.

    A register needs a view cast when:

    1. It appears in the instruction's operand text.
    2. Another same‑family register is already in *mapping*.
    3. Its bit width is **wider** than the mapped register's width.
    4. The instruction is eligible (initially: x86‑64 LEA).

    Returns a list of replacements; an empty list when no views are needed.
    """
    canonical = canonical_arch_name(arch)
    if canonical != "x86-64":
        return []
    if instruction.mnemonic.strip().lower() != "lea":
        return []

    known = known_register_tokens(canonical)
    op_tokens = _tokenize(instruction.op_str)

    mappings_by_family: dict[str, tuple[str, str]] = {}
    # → (mapped_reg, placeholder)
    for mapped_reg, placeholder in mapping.items():
        family = register_family(canonical, mapped_reg)
        if family is not None:
            mappings_by_family[family] = (mapped_reg, placeholder)

    if not mappings_by_family:
        return []

    replacements: list[RegisterViewReplacement] = []
    for token in op_tokens:
        token_n = normalize_register_name(token)
        if token_n not in known:
            continue
        if token_n in mapping:
            continue  # Already mapped — no view needed.

        family = register_family(canonical, token_n)
        if family is None or family not in mappings_by_family:
            continue

        mapped_reg, placeholder = mappings_by_family[family]
        mapped_range = register_bit_range(canonical, mapped_reg)
        token_range = register_bit_range(canonical, token_n)
        if mapped_range is None or token_range is None:
            continue

        # Only widen when the token register is WIDER than the mapped one.
        if token_range[1] <= mapped_range[1]:
            continue

        view_bits = token_range[1] + 1
        replacements.append(
            RegisterViewReplacement(
                physical_register=token,
                placeholder=placeholder,
                replacement_text=f"reg{view_bits}({placeholder})",
                reason="lea_address_operand_same_family_widen",
            )
        )

    return replacements


# ── Tokenisation helper (mirrors _TOKEN_RE in generalize.py) ──────────

_TOKEN_RE = _re.compile(r"\[|\]|0x[0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[-+*/#]")


def _tokenize(text: str) -> list[str]:
    """Return the ordered list of register-candidate tokens in *text*."""
    return [m.group(0) for m in _TOKEN_RE.finditer(text)]
