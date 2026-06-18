"""Heuristic immediate expression derivation.

Given guest and host instruction ASTs, attempts to express host-only
immediate values as arithmetic expressions of guest immediates using
instruction-aware derivation strategies.

The primary entry point is :func:`derive_host_expressions`, which accepts
full instruction AST from both architectures together with an extracted
value table. Each derivation strategy inspects mnemonics and operand
positions to ensure the derivation is semantically valid for the
instruction pattern rather than coincidental arithmetic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

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

    Carries full instruction AST from both architectures together with a
    value-by-id table so that derivation strategies can inspect mnemonics,
    operand positions, and original immediate values.
    """

    guest_insts: tuple[Instruction, ...]
    host_insts: tuple[Instruction, ...]
    guest_arch: str
    host_arch: str
    value_by_id: dict[str, int]  # imm_id → integer value


class DerivationStrategy(Protocol):
    """Strategy that attempts to derive a host-only immediate in terms of guest
    immediates.

    Returns a derivation expression string (e.g. ``"(1 << imm1)"``)
    suitable for use in ``ImmOp.derived``, or ``None`` if the strategy
    does not apply.
    """

    def __call__(self, ctx: DerivationContext, imm_id: str) -> str | None: ...


def derive_host_expressions(ctx: DerivationContext) -> tuple[Instruction, ...]:
    """Attempt to express host-only immediates in terms of guest immediates.

    For each host-side ``ImmOp`` whose ID does not appear on the guest side,
    attempts derivation strategies in order.  Found derivations are stored in
    ``ImmOp.derived``.

    Returns new host instructions (the guest side is unchanged).
    """
    guest_imm_ids = collect_instruction_imm_ids(ctx.guest_insts)
    host_imm_ids = collect_instruction_imm_ids(ctx.host_insts)
    host_only = host_imm_ids - guest_imm_ids

    if not host_only:
        return ctx.host_insts

    strategies: list[DerivationStrategy] = [
        _derive_tbz_mask,
        _derive_movk_constant,
        _derive_index_scale,
    ]

    result: list[Instruction] = []
    for inst in ctx.host_insts:
        new_operands = []
        for op in inst.operands:
            if isinstance(op, ImmOp) and str(op.id) in host_only:
                derived = None
                for strategy in strategies:
                    derived = strategy(ctx, str(op.id))
                    if derived is not None:
                        break
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
                        derived = None
                        for strategy in strategies:
                            derived = strategy(ctx, imm_id)
                            if derived is not None:
                                break
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
                post_meta=inst.post_meta,
            )
        )
    return tuple(result)


# ── Derivation strategies ─────────────────────────────────────────────────


def _derive_tbz_mask(ctx: DerivationContext, imm_id: str) -> str | None:
    """Derive host mask from a guest ``tbz``/``tbnz`` bit-position immediate.

    Requires:
    - A guest instruction with mnemonic ``tbz`` or ``tbnz``.
    - Its second operand is the bit-position immediate (ImmOp).
    - The host value equals ``1 << bitpos_value``.

    Returns ``"(1 << immN)"`` where ``immN`` is the guest bit-position
    placeholder.
    """
    target_value = ctx.value_by_id.get(imm_id)
    if target_value is None:
        return None

    for inst in ctx.guest_insts:
        mnemonic = inst.mnemonic.strip().lower()
        if mnemonic not in {"tbz", "tbnz"}:
            continue
        if len(inst.operands) < 2:
            continue
        bitpos_op = inst.operands[1]
        if not isinstance(bitpos_op, ImmOp) or bitpos_op.id == 0:
            continue
        bitpos_id = str(bitpos_op.id)
        bitpos_value = ctx.value_by_id.get(bitpos_id)
        if bitpos_value is None:
            continue
        if (1 << bitpos_value) == target_value:
            return f"(1 << imm{bitpos_id})"

    return None


def _derive_movk_constant(ctx: DerivationContext, imm_id: str) -> str | None:
    """Derive a 64-bit host constant from guest ``mov`` + ``movk`` pattern.

    Requires:
    - A guest instruction with mnemonic ``mov`` writing a register.
    - A guest instruction with mnemonic ``movk`` writing the same register
      with an ``lsl #immN`` shift operand.
    - The host value equals ``(movk_imm << shift) | mov_imm``.

    Returns ``"((imm_high << imm_shift) | imm_low)"`` where the placeholder
    IDs come from the guest instructions.
    """
    target_value = ctx.value_by_id.get(imm_id)
    if target_value is None:
        return None

    # Collect guest mov instructions and their dest + imm.
    mov_entries: list[tuple[ImmOp, str]] = []  # (imm_op, dest_placeholder)
    for inst in ctx.guest_insts:
        mnemonic = inst.mnemonic.strip().lower()
        if mnemonic != "mov":
            continue
        if len(inst.operands) < 2:
            continue
        dest_op = inst.operands[0]
        src_op = inst.operands[1]
        if isinstance(src_op, ImmOp) and src_op.id != 0:
            dest_text = dest_op.to_text()
            mov_entries.append((src_op, dest_text))

    # Collect guest movk instructions.
    movk_entries: list[
        tuple[ImmOp, str, str]
    ] = []  # (imm_op, shift_id, dest_placeholder)
    for inst in ctx.guest_insts:
        mnemonic = inst.mnemonic.strip().lower()
        if mnemonic != "movk":
            continue
        if len(inst.operands) < 3:
            continue
        dest_op = inst.operands[0]
        imm_op = inst.operands[1]
        shift_op = inst.operands[2]
        if not isinstance(imm_op, ImmOp) or imm_op.id == 0:
            continue
        dest_text = dest_op.to_text()
        # Extract immN from the shift operand (LitOp like "lsl #imm3").
        shift_id: str | None = None
        if isinstance(shift_op, ImmOp) and shift_op.id != 0:
            shift_id = str(shift_op.id)
        elif isinstance(shift_op, (LitOp, RegTextOp)):
            m_shift = re.search(r"imm(\d+)", shift_op.to_text())
            if m_shift:
                shift_id = m_shift.group(1)
        if shift_id is None:
            continue
        movk_entries.append((imm_op, shift_id, dest_text))

    # For each (mov, movk) pair writing the same dest register, check the
    # expression.
    for mov_imm, mov_dest in mov_entries:
        for movk_imm, shift_id, movk_dest in movk_entries:
            if mov_dest != movk_dest:
                continue
            mov_val = ctx.value_by_id.get(str(mov_imm.id))
            movk_val = ctx.value_by_id.get(str(movk_imm.id))
            shift_val = ctx.value_by_id.get(shift_id)
            if mov_val is None or movk_val is None or shift_val is None:
                continue
            if ((movk_val << shift_val) | mov_val) == target_value:
                return f"(imm{movk_imm.id} << imm{shift_id}) | imm{mov_imm.id}"

    return None


def _derive_index_scale(ctx: DerivationContext, imm_id: str) -> str | None:
    """Derive a host index scale factor from a guest ``lsl #immN`` shift.

    Requires:
    - A guest instruction with an ``lsl #immN`` operand (detected via
      LitOp/RegTextOp text containing ``lsl #immN``).
    - The host value equals ``1 << shift_value``.

    Returns ``"(1 << immN)"`` where ``immN`` is the guest lsl shift
    placeholder.
    """
    target_value = ctx.value_by_id.get(imm_id)
    if target_value is None:
        return None

    # Find guest lsl #immN operands.
    guest_shift_ids: list[str] = []
    for inst in ctx.guest_insts:
        for op in inst.operands:
            if isinstance(op, (LitOp, RegTextOp)):
                text = op.to_text()
                for m in IMM_PLACEHOLDER_RE.finditer(text):
                    imm_id_candidate = m.group(1)
                    # Check if this imm_id appears in a lsl #immN context.
                    lsl_match = re.search(
                        rf"lsl #imm{re.escape(imm_id_candidate)}", text
                    )
                    if lsl_match:
                        guest_shift_ids.append(imm_id_candidate)
            elif isinstance(op, ImmOp):
                pass  # standalone ImmOp wouldn't have lsl context

    for shift_id in guest_shift_ids:
        shift_value = ctx.value_by_id.get(shift_id)
        if shift_value is None:
            continue
        if (1 << shift_value) == target_value:
            return f"(1 << imm{shift_id})"

    return None
