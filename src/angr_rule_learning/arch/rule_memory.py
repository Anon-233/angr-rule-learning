"""ISA adapter seam for rule-level memory operand syntax."""

from __future__ import annotations

from importlib import import_module
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, cast

from angr_rule_learning.arch.registry import canonical_arch_name

if TYPE_CHECKING:
    from angr_rule_learning.rules.ast import MemoryOperand


class RuleMemoryAdapter(Protocol):
    syntax: str

    def parse(
        self,
        text: str,
        parse_operand: Callable[[str], object],
        split_operands: Callable[[str], list[str]],
    ) -> MemoryOperand | None: ...

    def validate(self, operand: MemoryOperand) -> None: ...

    def format(self, operand: MemoryOperand) -> str: ...

    def combine_operands(self, operands: list[object]) -> list[object]: ...


def _adapter_name(syntax: str) -> str:
    return canonical_arch_name(syntax).replace("-", "_")


def rule_memory_syntax(arch: str) -> str | None:
    """Return the adapter-owned rule syntax identifier for an ISA."""
    adapter = _optional_adapter_for(canonical_arch_name(arch))
    return adapter.syntax if adapter is not None else None


def _adapter_for(syntax: str) -> RuleMemoryAdapter:
    adapter = _optional_adapter_for(syntax)
    if adapter is None:
        raise ValueError(f"unsupported rule memory syntax: {syntax}")
    return adapter


def _optional_adapter_for(syntax: str) -> RuleMemoryAdapter | None:
    module_name = f"angr_rule_learning.arch.{_adapter_name(syntax)}.rule_memory"
    try:
        module = import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name == module_name or module_name.startswith(f"{exc.name}."):
            return None
        raise
    return cast(RuleMemoryAdapter, module.ADAPTER)


def format_rule_memory(operand: MemoryOperand) -> str:
    return _adapter_for(operand.syntax).format(operand)


def validate_rule_memory(operand: MemoryOperand) -> None:
    _adapter_for(operand.syntax).validate(operand)


def parse_rule_memory(
    text: str,
    syntax: str,
    parse_operand: Callable[[str], object],
    split_operands: Callable[[str], list[str]],
) -> MemoryOperand | None:
    return _adapter_for(syntax).parse(text, parse_operand, split_operands)


def combine_rule_memory_operands(operands: list[object]) -> list[object]:
    """Let the syntax adapter combine operands spanning top-level commas."""
    syntaxes = {
        operand.syntax
        for operand in operands
        if hasattr(operand, "syntax") and hasattr(operand, "address")
    }
    if not syntaxes:
        return operands
    if len(syntaxes) != 1:
        raise ValueError("instruction contains mixed memory operand syntaxes")
    return _adapter_for(syntaxes.pop()).combine_operands(operands)
