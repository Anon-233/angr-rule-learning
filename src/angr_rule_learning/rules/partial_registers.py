"""Host-side partial-register rule operand rewrites."""

from __future__ import annotations

from dataclasses import dataclass

from angr_rule_learning.arch.registers import (
    normalize_register_name,
    register_bit_range,
    register_family,
    register_write_effect,
)
from angr_rule_learning.arch.registry import canonical_arch_name
from angr_rule_learning.extraction.models import ExtractedInstruction
from angr_rule_learning.rules.registers import known_register_tokens


@dataclass(frozen=True)
class PartialRegisterReplacement:
    physical_register: str
    replacement_text: str
    reason: str


class PartialRegisterRewriteError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def resolve_partial_register_views(
    arch: str,
    instruction: ExtractedInstruction,
    mapping: dict[str, str],
    *,
    side: str,
    prior_instructions: tuple[ExtractedInstruction, ...] = (),
) -> list[PartialRegisterReplacement]:
    """Return Host-only low-slice replacements for partial register operands."""
    if side != "host":
        return []

    canonical = canonical_arch_name(arch)
    if canonical != "x86-64":
        return []

    mnemonic = instruction.mnemonic.strip().lower()
    known = known_register_tokens(canonical)
    replacements: list[PartialRegisterReplacement] = []

    for register in instruction.write_registers:
        reg_n = normalize_register_name(register)
        if reg_n not in known:
            continue
        replacement = _zero_extending_write_replacement(
            canonical, instruction, reg_n, mapping
        )
        if replacement is None:
            continue
        replacements.append(
            PartialRegisterReplacement(
                physical_register=reg_n,
                replacement_text=replacement,
                reason="zero_extending_output_write",
            )
        )

    if mnemonic == "movzx":
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

    if mnemonic.startswith("set"):
        for register in instruction.write_registers:
            reg_n = normalize_register_name(register)
            if reg_n not in known:
                continue
            replacement = _low_slice_replacement(canonical, reg_n, mapping)
            if replacement is None:
                continue
            family = register_family(canonical, reg_n)
            placeholder = _placeholder_for_family(canonical, family, mapping)
            if placeholder is None:
                continue
            if not _has_prior_full_definition(
                canonical, family, placeholder, prior_instructions, mapping
            ):
                raise PartialRegisterRewriteError("unsafe_partial_register_write")
            replacements.append(
                PartialRegisterReplacement(
                    physical_register=reg_n,
                    replacement_text=replacement,
                    reason="setcc_low_slice_destination",
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


def _zero_extending_write_replacement(
    arch: str,
    instruction: ExtractedInstruction,
    register: str,
    mapping: dict[str, str],
) -> str | None:
    if register in mapping:
        return None
    mnemonic = instruction.mnemonic.strip().lower()
    if mnemonic not in {"movzx", "xor"}:
        return None
    if mnemonic == "xor" and not _is_same_register_binary(instruction.op_str, register):
        return None
    effect = register_write_effect(arch, register)
    if effect is None or effect.kind != "zero_extend":
        return None
    return _placeholder_for_family(arch, effect.family, mapping)


def _is_same_register_binary(op_str: str, register: str) -> bool:
    parts = [normalize_register_name(part) for part in op_str.split(",")]
    return len(parts) == 2 and parts[0] == register and parts[1] == register


def _placeholder_for_family(
    arch: str,
    family: str,
    mapping: dict[str, str],
) -> str | None:
    for mapped_reg, placeholder in sorted(mapping.items()):
        if register_family(arch, mapped_reg) == family:
            return placeholder
    return None


def _has_prior_full_definition(
    arch: str,
    family: str,
    placeholder: str,
    prior_instructions: tuple[ExtractedInstruction, ...],
    mapping: dict[str, str],
) -> bool:
    for instruction in reversed(prior_instructions):
        for written in instruction.write_registers:
            written_n = normalize_register_name(written)
            effect = register_write_effect(arch, written_n)
            if effect is None or effect.family != family:
                continue
            if effect.kind not in {"full", "zero_extend"}:
                continue
            written_placeholder = _placeholder_for_family(arch, effect.family, mapping)
            if written_placeholder == placeholder:
                return True
    return False
