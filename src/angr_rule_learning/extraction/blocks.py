from __future__ import annotations

from angr_rule_learning.extraction.models import (
    BasicBlock,
    ExtractedFunction,
    ExtractedInstruction,
)


CONTROL_FLOW_PREFIXES = {
    "aarch64": ("b", "cbz", "cbnz", "tbz", "tbnz", "br", "blr", "ret", "eret"),
    "x86-64": ("j", "ret", "call", "syscall", "int"),
}


class BasicBlockBuilder:
    def build(self, function: ExtractedFunction) -> tuple[BasicBlock, ...]:
        blocks: list[BasicBlock] = []
        current: list[ExtractedInstruction] = []
        for instruction in function.instructions:
            current.append(instruction)
            if _is_control_flow(function.arch, instruction.mnemonic):
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


def _is_control_flow(arch: str, mnemonic: str) -> bool:
    normalized = mnemonic.strip().lower()
    prefixes = CONTROL_FLOW_PREFIXES.get(arch.strip().lower(), ())
    if arch.strip().lower() == "x86-64" and normalized == "jmp":
        return True
    return any(normalized.startswith(prefix) for prefix in prefixes)
