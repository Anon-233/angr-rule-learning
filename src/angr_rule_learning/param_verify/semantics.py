from __future__ import annotations
from dataclasses import dataclass, field

import claripy

from angr_rule_learning.rules.ast import (
    BitSliceOp,
    ExtOp,
    ImmOp,
    IntExpr,
    Instruction,
    LitOp,
    Log2Expr,
    MemoryOperand,
    Operand,
    RegOp,
    RegTextOp,
    TmpOp,
    ShiftLeftExpr,
)
from angr_rule_learning.smt.solver import fit_width


class UnsupportedRuleSemantics(ValueError):
    pass


@dataclass
class EvalContext:
    symbols: dict[str, claripy.ast.BV] = field(default_factory=dict)
    constraints: list[claripy.ast.Bool] = field(default_factory=list)
    imm_domains: dict[int, tuple[int, ...]] = field(default_factory=dict)

    def placeholder(self, name: str, bits: int) -> claripy.ast.BV:
        existing = self.symbols.get(name)
        if existing is not None:
            return fit_width(existing, bits)
        symbol = claripy.BVS(name, bits, explicit_name=True)
        self.symbols[name] = symbol
        return symbol

    def immediate(self, imm_id: int, bits: int) -> claripy.ast.BV:
        name = f"imm{imm_id}"
        existing = self.symbols.get(name)
        if existing is None:
            existing = claripy.BVS(name, bits, explicit_name=True)
            self.symbols[name] = existing
            domain = self.imm_domains.get(imm_id, tuple(range(8)))
            self.constraints.append(
                claripy.Or(*(fit_width(existing, bits) == value for value in domain))
            )
        return fit_width(existing, bits)


@dataclass(frozen=True)
class EvaluatedSide:
    registers: dict[str, claripy.ast.BV]
    assigned: frozenset[str]
    prestate_reads: frozenset[str]


def evaluate_instructions(
    instructions: tuple[Instruction, ...],
    ctx: EvalContext,
) -> EvaluatedSide:
    registers: dict[str, claripy.ast.BV] = {}
    assigned: set[str] = set()
    prestate_reads: set[str] = set()
    for inst in instructions:
        _evaluate_instruction(inst, ctx, registers, assigned, prestate_reads)
    return EvaluatedSide(
        registers=registers,
        assigned=frozenset(assigned),
        prestate_reads=frozenset(prestate_reads),
    )


def _evaluate_instruction(
    inst: Instruction,
    ctx: EvalContext,
    registers: dict[str, claripy.ast.BV],
    assigned: set[str],
    prestate_reads: set[str],
) -> None:
    if inst.meta or inst.post_meta:
        raise UnsupportedRuleSemantics("meta_operations_unsupported")
    mnemonic = inst.mnemonic.lower()
    operands = inst.operands
    if mnemonic == "mov":
        _assign(
            operands[0],
            _eval_operand(operands[1], ctx, registers, prestate_reads=prestate_reads),
            registers,
            assigned,
        )
        return
    if mnemonic == "movzx":
        dst_bits = _operand_bits(operands[0])
        value = _eval_operand(
            operands[1], ctx, registers, prestate_reads=prestate_reads
        )
        _assign(operands[0], fit_width(value, dst_bits), registers, assigned)
        return
    if mnemonic == "lea":
        dst = operands[0]
        dst_bits = _operand_bits(dst)
        value = _eval_address_operand(
            operands[1], ctx, registers, prestate_reads, dst_bits
        )
        _assign(dst, fit_width(value, dst_bits), registers, assigned)
        return
    if mnemonic in {"add", "sub", "and", "orr", "or", "eor", "xor", "mul", "imul"}:
        _eval_binary_instruction(
            mnemonic, operands, ctx, registers, assigned, prestate_reads
        )
        return
    if mnemonic in {"lsl", "lsr", "asr", "shl", "shr", "sar"}:
        _eval_shift_instruction(
            mnemonic, operands, ctx, registers, assigned, prestate_reads
        )
        return
    raise UnsupportedRuleSemantics(f"unsupported_instruction:{mnemonic}")


def _eval_binary_instruction(
    mnemonic: str,
    operands: tuple[Operand, ...],
    ctx: EvalContext,
    registers: dict[str, claripy.ast.BV],
    assigned: set[str],
    prestate_reads: set[str],
) -> None:
    if len(operands) == 2:
        dst, rhs_op = operands
        lhs = _eval_operand(dst, ctx, registers, prestate_reads=prestate_reads)
        rhs = fit_width(
            _eval_operand(rhs_op, ctx, registers, lhs.size(), prestate_reads),
            lhs.size(),
        )
    elif len(operands) == 3:
        dst, lhs_op, rhs_op = operands
        lhs = _eval_operand(lhs_op, ctx, registers, prestate_reads=prestate_reads)
        rhs = fit_width(
            _eval_operand(rhs_op, ctx, registers, lhs.size(), prestate_reads),
            lhs.size(),
        )
    else:
        raise UnsupportedRuleSemantics("unsupported_binary_shape")
    if mnemonic == "add":
        value = lhs + rhs
    elif mnemonic == "sub":
        value = lhs - rhs
    elif mnemonic in {"and"}:
        value = lhs & rhs
    elif mnemonic in {"orr", "or"}:
        value = lhs | rhs
    elif mnemonic in {"eor", "xor"}:
        value = lhs ^ rhs
    elif mnemonic in {"mul", "imul"}:
        value = lhs * rhs
    else:
        raise UnsupportedRuleSemantics(f"unsupported_binary:{mnemonic}")
    _assign(
        operands[0], fit_width(value, _operand_bits(operands[0])), registers, assigned
    )


def _eval_shift_instruction(
    mnemonic: str,
    operands: tuple[Operand, ...],
    ctx: EvalContext,
    registers: dict[str, claripy.ast.BV],
    assigned: set[str],
    prestate_reads: set[str],
) -> None:
    if len(operands) == 2:
        dst, amount_op = operands
        value = _eval_operand(dst, ctx, registers, prestate_reads=prestate_reads)
    elif len(operands) == 3:
        dst, value_op, amount_op = operands
        value = _eval_operand(value_op, ctx, registers, prestate_reads=prestate_reads)
    else:
        raise UnsupportedRuleSemantics("unsupported_shift_shape")
    amount = fit_width(
        _eval_operand(amount_op, ctx, registers, value.size(), prestate_reads),
        value.size(),
    )
    if mnemonic in {"lsl", "shl"}:
        result = value << amount
    elif mnemonic in {"lsr", "shr"}:
        result = claripy.LShR(value, amount)
    elif mnemonic in {"asr", "sar"}:
        result = value >> amount
    else:
        raise UnsupportedRuleSemantics(f"unsupported_shift:{mnemonic}")
    _assign(
        operands[0], fit_width(result, _operand_bits(operands[0])), registers, assigned
    )


def _assign(
    dst: Operand,
    value: claripy.ast.BV,
    registers: dict[str, claripy.ast.BV],
    assigned: set[str],
) -> None:
    key = _placeholder_key(dst)
    bits = _operand_bits(dst)
    registers[key] = fit_width(value, bits)
    assigned.add(key)


def _eval_operand(
    op: Operand,
    ctx: EvalContext,
    registers: dict[str, claripy.ast.BV],
    desired_bits: int | None = None,
    prestate_reads: set[str] | None = None,
) -> claripy.ast.BV:
    op = _parse_lit_view(op)
    if isinstance(op, (RegOp, TmpOp)):
        key = op.to_text()
        bits = desired_bits or op.bits
        if key not in registers and prestate_reads is not None:
            prestate_reads.add(key)
        return fit_width(registers.get(key, ctx.placeholder(key, op.bits)), bits)
    if isinstance(op, ImmOp):
        bits = desired_bits or 64
        value = _eval_immediate(op, ctx, bits)
        if op.neg:
            value = -value
        return fit_width(value, bits)
    if isinstance(op, LitOp):
        value = _parse_int_literal(op.value)
        if value is None:
            raise UnsupportedRuleSemantics(f"unsupported_literal:{op.value}")
        bits = desired_bits or _literal_bits(value)
        return claripy.BVV(value % (1 << bits), bits)
    if isinstance(op, BitSliceOp):
        base = _eval_operand(op.base, ctx, registers, prestate_reads=prestate_reads)
        return base[op.bits - 1 : 0]
    if isinstance(op, ExtOp):
        value = _eval_operand(op.value, ctx, registers, prestate_reads=prestate_reads)
        if op.bits < value.size():
            return value[op.bits - 1 : 0]
        if op.kind == "zext":
            return value.zero_extend(op.bits - value.size())
        if op.kind == "sext":
            return value.sign_extend(op.bits - value.size())
    raise UnsupportedRuleSemantics(f"unsupported_operand:{op.to_text()}")


def _eval_immediate(op: ImmOp, ctx: EvalContext, bits: int) -> claripy.ast.BV:
    if op.derived is None:
        return ctx.immediate(op.id, bits)
    return _eval_imm_expr(op.derived, ctx, bits)


def _eval_imm_expr(expr, ctx: EvalContext, bits: int) -> claripy.ast.BV:
    from angr_rule_learning.rules.ast import ImmRefExpr

    if isinstance(expr, ImmRefExpr):
        return ctx.immediate(expr.id, bits)
    if isinstance(expr, IntExpr):
        return claripy.BVV(expr.value % (1 << bits), bits)
    if isinstance(expr, ShiftLeftExpr):
        if not isinstance(expr.left, IntExpr) or expr.left.value != 1:
            raise UnsupportedRuleSemantics(
                f"unsupported_derived_immediate:${{{expr.to_text()}}}"
            )
        if not isinstance(expr.right, ImmRefExpr):
            raise UnsupportedRuleSemantics(
                f"unsupported_derived_immediate:${{{expr.to_text()}}}"
            )
        return _domain_expression(
            ctx,
            expr.right.id,
            bits,
            lambda value: 1 << value,
        )
    if isinstance(expr, Log2Expr):
        if not isinstance(expr.value, ImmRefExpr):
            raise UnsupportedRuleSemantics(
                f"unsupported_derived_immediate:${{{expr.to_text()}}}"
            )
        return _domain_expression(
            ctx,
            expr.value.id,
            bits,
            lambda value: value.bit_length() - 1 if value > 0 else 0,
        )
    raise UnsupportedRuleSemantics(
        f"unsupported_derived_immediate:${{{expr.to_text()}}}"
    )


def _domain_expression(
    ctx: EvalContext,
    imm_id: int,
    bits: int,
    fn,
) -> claripy.ast.BV:
    imm = ctx.immediate(imm_id, bits)
    domain = ctx.imm_domains.get(imm_id, tuple(range(8)))
    result = claripy.BVV(fn(domain[-1]) % (1 << bits), bits)
    for value in reversed(domain[:-1]):
        result = claripy.If(
            imm == value, claripy.BVV(fn(value) % (1 << bits), bits), result
        )
    return result


def _eval_address_operand(
    op: Operand,
    ctx: EvalContext,
    registers: dict[str, claripy.ast.BV],
    prestate_reads: set[str],
    bits: int,
) -> claripy.ast.BV:
    text = op.to_text().strip()
    if isinstance(op, MemoryOperand):
        if op.syntax != "x86":
            raise UnsupportedRuleSemantics(f"unsupported_address:{text}")
        text = op.address.to_x86_text()
    if not (text.startswith("[") and text.endswith("]")):
        raise UnsupportedRuleSemantics(f"unsupported_address:{text}")
    inner = text[1:-1].replace("-", "+ -")
    total = claripy.BVV(0, bits)
    for term in inner.split("+"):
        term = term.strip()
        if not term:
            continue
        if "*" in term:
            left, right = (part.strip() for part in term.split("*", 1))
            lhs = _eval_operand(
                Instruction._parse_operand(left), ctx, registers, bits, prestate_reads
            )
            rhs = _eval_operand(
                Instruction._parse_operand(right), ctx, registers, bits, prestate_reads
            )
            total += lhs * rhs
        else:
            total += _eval_operand(
                Instruction._parse_operand(term), ctx, registers, bits, prestate_reads
            )
    return fit_width(total, bits)


def _parse_lit_view(op: Operand) -> Operand:
    if not isinstance(op, (LitOp, RegTextOp)):
        return op
    parsed = Instruction._parse_operand(op.to_text())
    if isinstance(parsed, (LitOp, RegTextOp)) and parsed.to_text() == op.to_text():
        return op
    return parsed


def _placeholder_key(op: Operand) -> str:
    op = _parse_lit_view(op)
    if isinstance(op, (RegOp, TmpOp)):
        return op.to_text()
    raise UnsupportedRuleSemantics(f"unsupported_destination:{op.to_text()}")


def _operand_bits(op: Operand) -> int:
    op = _parse_lit_view(op)
    if isinstance(op, (RegOp, TmpOp)):
        return op.bits
    if isinstance(op, BitSliceOp):
        return op.bits
    if isinstance(op, ExtOp):
        return op.bits
    raise UnsupportedRuleSemantics(f"unknown_operand_width:{op.to_text()}")


def _parse_int_literal(text: str) -> int | None:
    value = text.strip().lower()
    value = value.removeprefix("#")
    value = value.replace(" ", "")
    try:
        return int(value, 0)
    except ValueError:
        return None


def _literal_bits(value: int) -> int:
    if -(1 << 31) <= value < (1 << 32):
        return 32
    return 64
