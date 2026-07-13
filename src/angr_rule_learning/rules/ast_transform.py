"""Queries and immutable transformations over complete Rule AST values."""

from __future__ import annotations

import re

from angr_rule_learning.rules.ast import (
    BitOrExpr,
    ImmExpr,
    ImmOp,
    ImmRefExpr,
    Instruction,
    IntExpr,
    LitOp,
    Log2Expr,
    MetaOp,
    NegExpr,
    RawImmExpr,
    Rule,
    ShiftLeftExpr,
    iter_instruction_operands,
    map_operand,
)


def collect_imm_ids(rule: Rule) -> set[int]:
    ids: set[int] = set()
    for operand in iter_instruction_operands(rule.guest + rule.host):
        if isinstance(operand, ImmOp):
            if operand.derived is not None:
                ids.update(operand.derived.imm_ids())
            elif operand.id != 0:
                ids.add(operand.id)
    return ids


def has_literal(rule: Rule, literals: frozenset[str]) -> bool:
    return any(
        isinstance(operand, LitOp) and operand.value in literals
        for operand in iter_instruction_operands(rule.guest + rule.host)
    )


def substitute_imm(rule: Rule, imm_id: int, value: str) -> Rule:
    def literal_expr() -> ImmExpr:
        try:
            return IntExpr(int(value, 0))
        except ValueError:
            return RawImmExpr(value)

    def substitute_expr(expression: ImmExpr) -> ImmExpr:
        if isinstance(expression, ImmRefExpr):
            return literal_expr() if expression.id == imm_id else expression
        if isinstance(expression, ShiftLeftExpr):
            return ShiftLeftExpr(
                substitute_expr(expression.left), substitute_expr(expression.right)
            )
        if isinstance(expression, BitOrExpr):
            return BitOrExpr(
                substitute_expr(expression.left), substitute_expr(expression.right)
            )
        if isinstance(expression, NegExpr):
            return NegExpr(substitute_expr(expression.value))
        if isinstance(expression, Log2Expr):
            return Log2Expr(substitute_expr(expression.value))
        if isinstance(expression, RawImmExpr):
            return RawImmExpr(re.sub(rf"\bimm{imm_id}\b", value, expression.text))
        return expression

    def substitute_operand(operand):
        if isinstance(operand, ImmOp):
            if operand.id == imm_id:
                prefix = "#" if operand.aarch64_hash else ""
                literal = value
                if operand.neg:
                    try:
                        literal = str(-int(value, 0))
                    except ValueError:
                        literal = value[1:] if value.startswith("-") else f"-{value}"
                return LitOp(value=f"{prefix}{literal}")
            if operand.derived is not None:
                return ImmOp(
                    id=0,
                    derived=substitute_expr(operand.derived),
                    aarch64_hash=operand.aarch64_hash,
                    neg=operand.neg,
                )
        if isinstance(operand, LitOp):
            text = re.sub(rf"#imm{imm_id}\b", f"#{value}", operand.value)
            text = re.sub(rf"(?<!\$)imm{imm_id}\b", value, text)
            return LitOp(value=text)
        return operand

    def substitute_meta(meta: MetaOp) -> MetaOp:
        return MetaOp(
            meta.kind, tuple(map_operand(op, substitute_operand) for op in meta.regs)
        )

    def substitute_instruction(instruction: Instruction) -> Instruction:
        return Instruction(
            mnemonic=instruction.mnemonic,
            operands=tuple(
                map_operand(op, substitute_operand) for op in instruction.operands
            ),
            meta=tuple(substitute_meta(meta) for meta in instruction.meta),
            post_meta=tuple(substitute_meta(meta) for meta in instruction.post_meta),
        )

    return Rule(
        rule_id=rule.rule_id,
        candidate_id=rule.candidate_id,
        guest=tuple(substitute_instruction(inst) for inst in rule.guest),
        host=tuple(substitute_instruction(inst) for inst in rule.host),
    )
