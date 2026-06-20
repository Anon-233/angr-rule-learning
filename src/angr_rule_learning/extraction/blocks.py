from __future__ import annotations

from angr_rule_learning.extraction.models import (
    BasicBlock,
    ExtractedFunction,
    ExtractedInstruction,
)


_AARCH64_CONTROL_FLOW = {
    "b",
    "bl",
    "br",
    "blr",
    "cbz",
    "cbnz",
    "tbz",
    "tbnz",
    "ret",
    "eret",
}

_X86_64_CONTROL_FLOW_PREFIXES = ("j", "ret", "call", "syscall", "int", "iret")


class BasicBlockBuilder:
    def build(self, function: ExtractedFunction) -> tuple[BasicBlock, ...]:
        blocks: list[BasicBlock] = []
        current: list[ExtractedInstruction] = []
        for instruction in function.instructions:
            current.append(instruction)
            if is_control_flow(function.arch, instruction.mnemonic):
                blocks.append(_block(function, len(blocks), tuple(current)))
                current = []
        if current:
            blocks.append(_block(function, len(blocks), tuple(current)))
        return tuple(blocks)


def _block(
    function: ExtractedFunction,
    index: int,
    instructions: tuple[ExtractedInstruction, ...],
) -> BasicBlock:
    return BasicBlock(
        block_id=f"{function.name}:{index}",
        arch=function.arch,
        function=function.name,
        instructions=instructions,
    )


def is_control_flow(arch: str, mnemonic: str) -> bool:
    normalized_arch = arch.strip().lower()
    normalized = mnemonic.strip().lower()
    if normalized_arch == "aarch64":
        return normalized in _AARCH64_CONTROL_FLOW or normalized.startswith("b.")
    if normalized_arch == "x86-64":
        return normalized.startswith(_X86_64_CONTROL_FLOW_PREFIXES)
    return False
