"""ISA adapter seam for rule-level memory operand syntax."""

from __future__ import annotations

from importlib import import_module
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, cast

from angr_rule_learning.arch.registry import canonical_arch_name

if TYPE_CHECKING:
    from angr_rule_learning.rules.ast import MemoryOperand


class RuleMemoryAdapter(Protocol):
    def parse(
        self,
        text: str,
        parse_operand: Callable[[str], object],
        split_operands: Callable[[str], list[str]],
    ) -> MemoryOperand | None: ...

    def validate(self, operand: MemoryOperand) -> None: ...

    def format(self, operand: MemoryOperand) -> str: ...


def _adapter_name(syntax: str) -> str:
    if syntax == "x86":
        return "x86_64"
    return canonical_arch_name(syntax).replace("-", "_")


def _adapter_for(syntax: str) -> RuleMemoryAdapter:
    module = import_module(
        f"angr_rule_learning.arch.{_adapter_name(syntax)}.rule_memory"
    )
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
