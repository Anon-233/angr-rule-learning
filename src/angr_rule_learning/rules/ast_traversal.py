"""Traversal and transformation operations for rule operand trees."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr_rule_learning.rules.ast import Instruction, Operand


def operand_children(op: Operand) -> tuple[Operand, ...]:
    from angr_rule_learning.rules.ast import (
        BitSliceOp,
        ExtOp,
        MemoryOperand,
        ReadWriteOp,
        RegViewOp,
    )

    if isinstance(op, RegViewOp):
        return (op.base,)
    if isinstance(op, BitSliceOp):
        return (op.base,)
    if isinstance(op, ExtOp):
        return (op.value,)
    if isinstance(op, ReadWriteOp):
        return (op.read, op.write)
    if isinstance(op, MemoryOperand):
        address = op.address
        return tuple(
            child
            for child in (
                address.base,
                address.index,
                address.scale,
                address.shift,
                address.displacement,
            )
            if child is not None
        )
    return ()


def iter_operand_tree(op: Operand) -> Iterator[Operand]:
    yield op
    for child in operand_children(op):
        yield from iter_operand_tree(child)


def map_operand(op: Operand, transform: Callable[[Operand], Operand]) -> Operand:
    from angr_rule_learning.addressing import AddressExpr
    from angr_rule_learning.rules.ast import (
        BitSliceOp,
        ExtOp,
        MemoryOperand,
        ReadWriteOp,
        RegOp,
        RegViewOp,
        TmpOp,
    )

    rebuilt = op
    if isinstance(op, RegViewOp):
        base = map_operand(op.base, transform)
        if not isinstance(base, (RegOp, TmpOp)):
            raise ValueError("register view transform produced invalid base")
        rebuilt = RegViewOp(base=base, view_bits=op.view_bits)
    elif isinstance(op, BitSliceOp):
        rebuilt = BitSliceOp(base=map_operand(op.base, transform), bits=op.bits)
    elif isinstance(op, ExtOp):
        rebuilt = ExtOp(
            kind=op.kind,
            bits=op.bits,
            value=map_operand(op.value, transform),
        )
    elif isinstance(op, ReadWriteOp):
        read = map_operand(op.read, transform)
        write = map_operand(op.write, transform)
        if not isinstance(write, (RegOp, TmpOp)):
            raise ValueError("read/write transform produced invalid destination")
        rebuilt = ReadWriteOp(read=read, write=write)
    elif isinstance(op, MemoryOperand):
        address = op.address

        def mapped(child: Operand | None) -> Operand | None:
            return map_operand(child, transform) if child is not None else None

        rebuilt = MemoryOperand(
            address=AddressExpr(
                base=mapped(address.base),
                index=mapped(address.index),
                scale=mapped(address.scale),
                shift=mapped(address.shift),
                displacement=mapped(address.displacement),
                writeback=address.writeback,
            ),
            syntax=op.syntax,
            value_bits=op.value_bits,
            size_keyword=op.size_keyword,
        )
    return transform(rebuilt)


def iter_instruction_operands(
    instructions: tuple[Instruction, ...],
) -> Iterator[Operand]:
    for instruction in instructions:
        for operand in instruction.operands:
            yield from iter_operand_tree(operand)
        for meta in instruction.meta + instruction.post_meta:
            for operand in meta.regs:
                yield from iter_operand_tree(operand)
