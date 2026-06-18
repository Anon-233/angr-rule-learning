"""Heuristic immediate expression derivation.

Given guest and host instruction ASTs, attempts to express host-only
immediate values as arithmetic expressions of guest immediates.

The primary entry point is :func:`derive_host_expressions`, which accepts
full instruction AST from both architectures together with an extracted
value table.  The current heuristics only inspect immediate values, but the
interface exposes complete instruction context so that future strategies can
inspect mnemonics, operand positions, and surrounding instructions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from angr_rule_learning.rules.ast import (
    IMM_PLACEHOLDER_RE,
    ImmOp,
    Instruction,
    LitOp,
    RegTextOp,
    collect_instruction_imm_ids,
)


@dataclass(frozen=True)
class DerivationContext:
    """Complete context for deriving host-only immediate expressions.

    Carries full instruction AST from both architectures so that future
    heuristics can inspect mnemonics, operand ordering, and surrounding
    instructions — beyond the current numeric value table.
    """

    guest_insts: tuple[Instruction, ...]
    host_insts: tuple[Instruction, ...]
    guest_arch: str
    host_arch: str
    value_by_id: dict[str, int]  # imm_id → integer value
    scale_shifts: set[int]  # detected shift amounts (lsl #N, *N)
    implicit_ids: set[str]  # imm_ids with implicit base values (e.g., "1" for tbz)


def derive_host_expressions(ctx: DerivationContext) -> tuple[Instruction, ...]:
    """Attempt to express host-only immediates in terms of guest immediates.

    For each host-side ``ImmOp`` whose ID does not appear on the guest side,
    search for an arithmetic expression of guest immediates that equals the
    host value.  Found derivations are stored in ``ImmOp.derived``.

    Returns new host instructions (the guest side is unchanged).
    """
    guest_imm_ids = collect_instruction_imm_ids(ctx.guest_insts)
    host_imm_ids = collect_instruction_imm_ids(ctx.host_insts)
    host_only = host_imm_ids - guest_imm_ids

    if not host_only:
        return ctx.host_insts

    guest_values = {
        k: v
        for k, v in ctx.value_by_id.items()
        if k in guest_imm_ids or k in ctx.implicit_ids
    }

    result: list[Instruction] = []
    for inst in ctx.host_insts:
        new_operands = []
        for op in inst.operands:
            if isinstance(op, ImmOp) and str(op.id) in host_only:
                derived = _search_expression(
                    ctx.value_by_id[str(op.id)],
                    guest_values,
                    ctx.scale_shifts,
                    ctx.implicit_ids,
                    ctx.value_by_id,
                )
                if derived is not None:
                    op = ImmOp(
                        id=op.id,
                        derived=f"${{{derived}}}",
                        aarch64_hash=op.aarch64_hash,
                        neg=op.neg,
                    )
            elif isinstance(op, (LitOp, RegTextOp)):
                text = op.to_text()
                for m in IMM_PLACEHOLDER_RE.finditer(text):
                    imm_id = m.group(1)
                    if imm_id in host_only:
                        derived = _search_expression(
                            ctx.value_by_id[imm_id],
                            guest_values,
                            ctx.scale_shifts,
                            ctx.implicit_ids,
                            ctx.value_by_id,
                        )
                        if derived is not None:
                            text = re.sub(
                                rf"\bimm{re.escape(imm_id)}\b",
                                f"${{{derived}}}",
                                text,
                            )
                if isinstance(op, LitOp):
                    op = LitOp(value=text)
                else:
                    op = RegTextOp(text=text)
            new_operands.append(op)
        result.append(
            Instruction(
                mnemonic=inst.mnemonic,
                operands=tuple(new_operands),
                meta=inst.meta,
            )
        )
    return tuple(result)


def _search_expression(
    target_value: int,
    guest_values: dict[str, int],
    scale_shifts: set[int],
    implicit_ids: set[str],
    all_values: dict[str, int],
) -> str | None:
    """Search for an expression of guest immediates that equals *target_value*.

    Templates are tried by complexity; the first match wins.
    """
    items = list(guest_values.items())  # [(id, value), ...]
    candidate_shifts = scale_shifts if scale_shifts else {0, 16, 32, 48}

    def _operand(imm_id: str) -> str:
        """Return the literal value for implicit operands, otherwise immN."""
        if imm_id in implicit_ids:
            return str(all_values[imm_id])
        return f"imm{imm_id}"

    def _shift_operand(s: int) -> str:
        """Return ``immN`` if *s* matches a guest immediate, else the literal."""
        for imm_id, val in guest_values.items():
            if val == s:
                return _operand(imm_id)
        return str(s)

    # L1: (imm_a << s)  —  single-shifted immediate  (e.g. 1 << bitpos)
    for id_a, va in items:
        for s in sorted(candidate_shifts, reverse=True):
            if va << s == target_value:
                return f"({_operand(id_a)} << {_shift_operand(s)})"

    # L2: (imm_a << s) | imm_b  —  mov + movk → movabs
    for id_a, va in items:
        for id_b, vb in items:
            if id_a == id_b:
                continue
            for s in sorted(candidate_shifts, reverse=True):
                if (va << s) | vb == target_value:
                    return (
                        f"({_operand(id_a)} << {_shift_operand(s)}) | {_operand(id_b)}"
                    )

    # L3: imm_a + imm_b  —  add chain
    for id_a, va in items:
        for id_b, vb in items:
            if id_a == id_b:
                continue
            if va + vb == target_value:
                return f"{_operand(id_a)} + {_operand(id_b)}"
            if va - vb == target_value:
                return f"{_operand(id_a)} - {_operand(id_b)}"

    return None
