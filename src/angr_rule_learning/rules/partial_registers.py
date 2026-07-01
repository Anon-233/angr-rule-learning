"""Host-side partial-register rule operand rewrites."""

from __future__ import annotations

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
class PartialRegisterReplacement:
    physical_register: str
    replacement_text: str
    reason: str


def resolve_partial_register_views(
    arch: str,
    instruction: ExtractedInstruction,
    mapping: dict[str, str],
    *,
    side: str,
) -> list[PartialRegisterReplacement]:
    """Return Host-only low-slice replacements for partial register operands."""
    if side != "host":
        return []

    canonical = canonical_arch_name(arch)
    if canonical != "x86-64":
        return []

    mnemonic = instruction.mnemonic.strip().lower()
    if mnemonic != "movzx":
        return []

    known = known_register_tokens(canonical)
    replacements: list[PartialRegisterReplacement] = []
    for register in instruction.read_registers:
        reg_n = normalize_register_name(register)
        if reg_n not in known:
            continue
        replacement = _low_slice_replacement(canonical, reg_n, mapping)
        if replacement is None:
            continue
        replacements.append(
            PartialRegisterReplacement(
                physical_register=reg_n,
                replacement_text=replacement,
                reason="movzx_low_slice_source",
            )
        )
    return replacements


def _low_slice_replacement(
    arch: str,
    register: str,
    mapping: dict[str, str],
) -> str | None:
    reg_range = register_bit_range(arch, register)
    if reg_range is None or reg_range[0] != 0:
        return None
    reg_bits = reg_range[1] + 1
    family = register_family(arch, register)

    for mapped_reg, placeholder in sorted(mapping.items()):
        mapped_range = register_bit_range(arch, mapped_reg)
        if mapped_range is None:
            continue
        if register_family(arch, mapped_reg) != family:
            continue
        if mapped_range[1] <= reg_range[1]:
            continue
        return f"lo{reg_bits}({placeholder})"
    return None
