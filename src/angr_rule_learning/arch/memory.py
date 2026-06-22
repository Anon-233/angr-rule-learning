from __future__ import annotations

from importlib import import_module
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Literal, Protocol, cast

from angr_rule_learning.arch.registry import canonical_arch_name
from angr_rule_learning.verification.addressing import AddressExpr

if TYPE_CHECKING:
    from angr_rule_learning.extraction.models import ExtractedInstruction


MemoryKind = Literal["read", "write"]


@dataclass(frozen=True)
class MemoryOperand:
    kind: MemoryKind
    width: int
    address: AddressExpr
    text: str
    value_register: str | None
    value_immediate: str | None = None


class MemoryRecognizer(Protocol):
    def extract(self, mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]: ...

    def has_access(self, mnemonic: str, op_str: str) -> bool: ...

    def stack_pointer_delta(self, mnemonic: str, op_str: str) -> int: ...


@lru_cache(maxsize=None)
def _recognizer_for(arch: str) -> MemoryRecognizer | None:
    canonical = canonical_arch_name(arch)
    module_name = f"angr_rule_learning.arch.{canonical.replace('-', '_')}.memory"
    try:
        module = import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name == module_name or module_name.startswith(f"{exc.name}."):
            return None
        raise
    return cast(MemoryRecognizer, module.RECOGNIZER)


def extract_memory_operands(
    instruction: ExtractedInstruction,
) -> tuple[MemoryOperand, ...]:
    recognizer = _recognizer_for(instruction.arch)
    if recognizer is None:
        return ()
    return recognizer.extract(
        instruction.mnemonic.strip().lower(),
        instruction.op_str.strip(),
    )


def has_any_memory_access(instruction: ExtractedInstruction) -> bool:
    recognizer = _recognizer_for(instruction.arch)
    if recognizer is None:
        return False
    return recognizer.has_access(
        instruction.mnemonic.strip().lower(),
        instruction.op_str.strip(),
    )


def stack_pointer_delta(instruction: ExtractedInstruction) -> int:
    recognizer = _recognizer_for(instruction.arch)
    if recognizer is None:
        return 0
    return recognizer.stack_pointer_delta(
        instruction.mnemonic.strip().lower(),
        instruction.op_str.strip(),
    )
