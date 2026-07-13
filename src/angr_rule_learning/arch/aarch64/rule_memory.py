from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from angr_rule_learning.addressing import AddressExpr

if TYPE_CHECKING:
    from angr_rule_learning.rules.ast import MemoryOperand


class AArch64RuleMemoryAdapter:
    syntax = "aarch64"

    def validate(self, operand: MemoryOperand) -> None:
        address = operand.address
        if address.base is None:
            raise ValueError("aarch64 memory operand requires a base")
        if address.scale is not None:
            raise ValueError("aarch64 memory operand cannot use scale")
        if address.index is not None and address.displacement is not None:
            raise ValueError(
                "aarch64 memory operand cannot combine index and displacement"
            )
        if operand.size_keyword is not None:
            raise ValueError("aarch64 memory operand cannot use x86 size keyword")

    def parse(
        self,
        text: str,
        parse_operand: Callable[[str], object],
        split_operands: Callable[[str], list[str]],
    ) -> MemoryOperand | None:
        from angr_rule_learning.rules.ast import MemoryOperand

        pre_index = text.endswith("]!")
        bracket_text = text[:-1] if pre_index else text
        if not bracket_text.startswith("[") or not bracket_text.endswith("]"):
            return None
        parts = [part.strip() for part in split_operands(bracket_text[1:-1])]
        if not parts:
            raise ValueError("empty aarch64 memory operand")
        base = parse_operand(parts[0])
        kwargs: dict[str, object] = {
            "base": base,
            "writeback": "pre" if pre_index else "none",
        }
        if len(parts) == 2:
            second = parse_operand(parts[1])
            if _is_address_register_operand(second):
                kwargs["index"] = second
            else:
                kwargs["displacement"] = second
        elif len(parts) == 3:
            shift_text = parts[2]
            if not shift_text.lower().startswith("lsl "):
                raise ValueError(
                    f"unsupported aarch64 address modifier: {shift_text!r}"
                )
            kwargs["index"] = parse_operand(parts[1])
            kwargs["shift"] = parse_operand(shift_text[4:].strip())
        elif len(parts) > 3:
            raise ValueError(f"unsupported aarch64 memory operand: {text!r}")
        return MemoryOperand(
            address=AddressExpr(**kwargs),
            syntax="aarch64",
        )

    def format(self, operand: MemoryOperand) -> str:
        address = operand.address
        if address.base is None:
            raise ValueError("aarch64 memory operand requires a base register")
        if address.writeback == "post":
            return f"[{address.base.to_text()}], {address.displacement.to_text()}"
        parts = [address.base.to_text()]
        if address.index is not None:
            parts.append(address.index.to_text())
            if address.shift is not None:
                parts.append(f"lsl {address.shift.to_text()}")
        elif address.displacement is not None:
            parts.append(address.displacement.to_text())
        suffix = "!" if address.writeback == "pre" else ""
        return f"[{', '.join(parts)}]{suffix}"

    def combine_operands(self, operands: list[object]) -> list[object]:
        from angr_rule_learning.rules.ast import MemoryOperand

        result: list[object] = []
        index = 0
        while index < len(operands):
            operand = operands[index]
            if (
                isinstance(operand, MemoryOperand)
                and operand.address.writeback == "none"
                and index + 1 == len(operands) - 1
            ):
                update = operands[index + 1]
                address = operand.address
                operand = MemoryOperand(
                    address=AddressExpr(
                        base=address.base,
                        index=address.index,
                        scale=address.scale,
                        shift=address.shift,
                        displacement=update,
                        writeback="post",
                    ),
                    syntax=operand.syntax,
                    value_bits=operand.value_bits,
                    size_keyword=operand.size_keyword,
                )
                index += 1
            result.append(operand)
            index += 1
        return result


ADAPTER = AArch64RuleMemoryAdapter()


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
        value = operand.to_text().strip().lower().removeprefix("#")
        try:
            int(value, 0)
        except ValueError:
            return True
    return False
