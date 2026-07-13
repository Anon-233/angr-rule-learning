from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING

from angr_rule_learning.addressing import AddressExpr

if TYPE_CHECKING:
    from angr_rule_learning.rules.ast import MemoryOperand


class X8664RuleMemoryAdapter:
    syntax = "x86-64"
    _memory_re = re.compile(
        r"^(?:(?P<size>byte|word|dword|qword)\s+ptr\s+)?(?P<addr>\[.+\])$",
        re.IGNORECASE,
    )
    _size_bits = {"byte": 8, "word": 16, "dword": 32, "qword": 64}

    def validate(self, operand: MemoryOperand) -> None:
        address = operand.address
        if address.scale is not None and address.index is None:
            raise ValueError("address scale requires an index")
        if address.shift is not None:
            raise ValueError("x86 memory operand cannot use shift")
        if address.writeback != "none":
            raise ValueError("x86 memory operand cannot use writeback")
        if operand.size_keyword is None:
            return
        keyword = operand.size_keyword.lower()
        if keyword not in self._size_bits:
            raise ValueError(f"unknown x86 memory size keyword: {keyword!r}")
        if (
            operand.value_bits is not None
            and operand.value_bits != self._size_bits[keyword]
        ):
            raise ValueError("memory width does not match size keyword")

    def parse(
        self,
        text: str,
        parse_operand: Callable[[str], object],
        split_operands: Callable[[str], list[str]],
    ) -> MemoryOperand | None:
        del split_operands
        from angr_rule_learning.rules.ast import MemoryOperand

        match = self._memory_re.fullmatch(text)
        if match is None:
            return None
        size = match.group("size")
        address = self._parse_address(match.group("addr")[1:-1], parse_operand)
        return MemoryOperand(
            address=address,
            syntax=self.syntax,
            value_bits=self._size_bits[size.lower()] if size is not None else None,
            size_keyword=size.lower() if size is not None else None,
        )

    def _parse_address(
        self, inner: str, parse_operand: Callable[[str], object]
    ) -> AddressExpr[object, object]:
        base = index = scale = displacement = None
        for sign, term in _split_signed_terms(inner):
            if "*" in term:
                if index is not None or scale is not None:
                    raise ValueError(
                        f"x86 memory operand has multiple index terms: {inner!r}"
                    )
                left, right = (part.strip() for part in term.split("*", 1))
                index = parse_operand(left)
                scale = parse_operand(right)
                if sign == "-":
                    scale = _negated_operand(scale)
                continue
            operand = parse_operand(term)
            if sign == "-":
                operand = _negated_operand(operand)
            if _is_address_register_operand(operand):
                if base is None:
                    base = operand
                elif index is None:
                    index = operand
                else:
                    raise ValueError(
                        f"x86 memory operand has too many register terms: {inner!r}"
                    )
            else:
                if displacement is not None:
                    raise ValueError(
                        f"x86 memory operand has multiple displacements: {inner!r}"
                    )
                displacement = operand
        if base is None and index is None:
            raise ValueError(f"x86 memory operand requires base register: {inner!r}")
        return AddressExpr(
            base=base,
            index=index,
            scale=scale,
            displacement=displacement,
        )

    def format(self, operand: MemoryOperand) -> str:
        address = operand.address
        if address.writeback != "none":
            raise ValueError("x86 address does not support writeback")
        text = address.base.to_text() if address.base is not None else ""
        if address.index is not None:
            index = address.index.to_text()
            if address.scale is not None:
                index = f"{index}*{address.scale.to_text()}"
            text = f"{text} + {index}" if text else index
        if address.displacement is not None:
            displacement = address.displacement.to_text()
            if displacement.startswith("- "):
                text = f"{text} {displacement}" if text else displacement
            elif displacement.startswith("-"):
                text = f"{text} - {displacement[1:]}" if text else displacement
            else:
                text = f"{text} + {displacement}" if text else displacement
        result = f"[{text}]"
        if operand.size_keyword is not None:
            return f"{operand.size_keyword} ptr {result}"
        return result

    def combine_operands(self, operands: list[object]) -> list[object]:
        return operands


ADAPTER = X8664RuleMemoryAdapter()


def _split_signed_terms(text: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    sign = "+"
    depth = 0
    current: list[str] = []
    for char in text:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if depth == 0 and char in "+-":
            term = "".join(current).strip()
            if term:
                result.append((sign, term))
            sign = char
            current = []
        else:
            current.append(char)
    term = "".join(current).strip()
    if term:
        result.append((sign, term))
    return result


def _is_address_register_operand(operand: object) -> bool:
    from angr_rule_learning.rules.ast import (
        BitSliceOp,
        ExtOp,
        GuestRegViewOp,
        LitOp,
        RegOp,
        RegTextOp,
        RegViewOp,
        TmpOp,
    )

    if isinstance(
        operand, (RegOp, RegViewOp, TmpOp, GuestRegViewOp, BitSliceOp, ExtOp)
    ):
        return True
    if isinstance(operand, (LitOp, RegTextOp)):
        return _parse_int_literal(operand.to_text()) is None
    return False


def _parse_int_literal(text: str) -> int | None:
    value = text.strip().lower().removeprefix("#").replace(" ", "")
    try:
        return int(value, 0)
    except ValueError:
        return None


def _negated_operand(operand: object) -> object:
    from angr_rule_learning.rules.ast import ImmOp, LitOp, NegExpr

    if isinstance(operand, ImmOp):
        if operand.derived is not None:
            derived = operand.derived
            derived = (
                derived.value if isinstance(derived, NegExpr) else NegExpr(derived)
            )
            return ImmOp(
                id=operand.id,
                derived=derived,
                aarch64_hash=operand.aarch64_hash,
            )
        return ImmOp(
            id=operand.id,
            derived=operand.derived,
            aarch64_hash=operand.aarch64_hash,
            neg=not operand.neg,
        )
    if isinstance(operand, LitOp):
        value = operand.value.strip()
        return LitOp(value=value[1:].strip() if value.startswith("-") else f"-{value}")
    return LitOp(value=f"-{operand.to_text()}")
