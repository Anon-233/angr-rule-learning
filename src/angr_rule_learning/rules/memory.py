from __future__ import annotations

from angr_rule_learning.extraction.memory_operands import (
    extract_memory_operands,
)
from angr_rule_learning.extraction.models import ExtractedInstruction
from angr_rule_learning.verification.candidate import MemorySpec


def rewrite_memory_operands(
    instructions: tuple[ExtractedInstruction, ...],
    lines: tuple[str, ...],
    memory: MemorySpec,
    *,
    side: str,
) -> tuple[str, ...]:
    if not memory.slots:
        return lines
    replacements = _replacement_by_operand_text(instructions, memory, side=side)
    result: list[str] = []
    for line in lines:
        rewritten = line
        for text, replacement in sorted(
            replacements.items(), key=lambda item: len(item[0]), reverse=True
        ):
            rewritten = rewritten.replace(text, replacement)
        result.append(rewritten)
    return tuple(result)


def _replacement_by_operand_text(
    instructions: tuple[ExtractedInstruction, ...],
    memory: MemorySpec,
    *,
    side: str,
) -> dict[str, str]:
    operands = tuple(
        operand
        for instruction in instructions
        for operand in extract_memory_operands(instruction)
    )
    bindings = memory.bindings
    if len(operands) != len(bindings):
        return {}
    result: dict[str, str] = {}
    for index, (operand, binding) in enumerate(
        zip(operands, bindings, strict=True), start=1
    ):
        expected = binding.guest_addr if side == "guest" else binding.host_addr
        if operand.address.binding_text() != expected:
            return {}
        result[operand.text] = f"[addr64_{index}]"
    return result
