"""Heuristic immediate expression derivation — precise to Host occurrence.

Given guest and host instruction ASTs, attempts to express host-only
immediate values as arithmetic expressions of guest immediates.  Each
derivation strategy is specific to a known instruction pattern (tbz→and,
mov+movk→movabs, indexed scale) and receives the exact Host instruction
index, operand index, and (for compound operands) the match span so it
can verify that the derived expression belongs at that position.

If **any** host-only occurrence cannot be derived, the entire rule is
rejected as ``unpaired_host_immediate``.
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
    """Complete context for deriving host-only immediate expressions."""

    guest_insts: tuple[Instruction, ...]
    host_insts: tuple[Instruction, ...]
    guest_arch: str
    host_arch: str
    value_by_id: dict[str, int]  # imm_id → integer value


class DerivationStrategy(Protocol):
    """Strategy that attempts to derive a host-only immediate at a specific
    position in the Host instruction sequence.

    *imm_id* is the host-only immediate identifier.
    *host_idx* and *op_idx* locate the operand within ``ctx.host_insts``.
    *span* is ``(start, end)`` for the match inside a ``LitOp``/``RegTextOp``
    operand, or ``None`` for a standalone ``ImmOp`` operand.
    """

    def __call__(
        self,
        ctx: DerivationContext,
        imm_id: str,
        host_idx: int,
        op_idx: int,
        span: tuple[int, int] | None,
    ) -> str | None: ...


def derive_host_expressions(ctx: DerivationContext) -> tuple[Instruction, ...]:
    """Attempt to express host-only immediates in terms of guest immediates.

    Strategies receive the exact Host position (instruction index, operand
    index, span) and must verify the instruction context matches their
    pattern.  If any host-only immediate remains underived after all
    strategies are tried, it is left as-is — the caller is responsible for
    rejecting the rule.
    """
    guest_imm_ids = collect_instruction_imm_ids(ctx.guest_insts)
    host_imm_ids = collect_instruction_imm_ids(ctx.host_insts)
    host_only = host_imm_ids - guest_imm_ids

    if not host_only:
        return ctx.host_insts

    strategies = _STRATEGIES.get((ctx.guest_arch, ctx.host_arch), [])

    result: list[Instruction] = []
    for host_idx, inst in enumerate(ctx.host_insts):
        new_operands = []
        for op_idx, op in enumerate(inst.operands):
            if isinstance(op, ImmOp) and str(op.id) in host_only:
                derived = _try_strategies(
                    strategies, ctx, str(op.id), host_idx, op_idx, None
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
                # Collect all matches first, then process in reverse so
                # span positions remain valid after each replacement.
                replacements: list[tuple[int, int, str]] = []
                for m in IMM_PLACEHOLDER_RE.finditer(text):
                    imm_id = m.group(1)
                    if imm_id in host_only:
                        match_span = (m.start(), m.end())
                        derived = _try_strategies(
                            strategies, ctx, imm_id, host_idx, op_idx, match_span
                        )
                        if derived is not None:
                            replacements.append((m.start(), m.end(), f"${{{derived}}}"))
                for start, end, repl in reversed(replacements):
                    text = text[:start] + repl + text[end:]
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


def _try_strategies(
    strategies: list[DerivationStrategy],
    ctx: DerivationContext,
    imm_id: str,
    host_idx: int,
    op_idx: int,
    span: tuple[int, int] | None,
) -> str | None:
    for strategy in strategies:
        derived = strategy(ctx, imm_id, host_idx, op_idx, span)
        if derived is not None:
            return derived
    return None


# ── Derivation strategies ─────────────────────────────────────────────────


def _derive_tbz_mask(
    ctx: DerivationContext,
    imm_id: str,
    host_idx: int,
    op_idx: int,
    span: tuple[int, int] | None,
) -> str | None:
    """Derive host ``and`` mask from guest ``tbz``/``tbnz`` bit position.

    Only applies when the Host instruction is ``and`` — the lowering of
    a bit-test into a mask-and-compare sequence.

    Handles both parameterised bit positions (``ImmOp``) and the reserved
    literal ``#0`` (``LitOp`` with value ``\"0\"`` or ``\"#0\"``).
    """
    host_inst = ctx.host_insts[host_idx]
    if host_inst.mnemonic.strip().lower() != "and":
        return None

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
        if isinstance(bitpos_op, ImmOp) and bitpos_op.id != 0:
            bitpos_id = str(bitpos_op.id)
            bitpos_value = ctx.value_by_id.get(bitpos_id)
            if bitpos_value is not None and (1 << bitpos_value) == target_value:
                return f"(1 << imm{bitpos_id})"
        elif isinstance(bitpos_op, LitOp) and bitpos_op.value in {"0", "#0"}:
            if (1 << 0) == target_value:
                return "(1 << 0)"

    return None


def _derive_movk_constant(
    ctx: DerivationContext,
    imm_id: str,
    host_idx: int,
    op_idx: int,
    span: tuple[int, int] | None,
) -> str | None:
    """Derive a 64-bit host constant from guest ``mov`` + ``movk``.

    Only applies when the Host instruction is ``mov`` or ``movabs`` and
    the immediate is a standalone ``ImmOp`` (not embedded in a compound
    operand).
    """
    host_inst = ctx.host_insts[host_idx]
    host_mnem = host_inst.mnemonic.strip().lower()
    if host_mnem not in {"mov", "movabs"}:
        return None
    # Must be a standalone ImmOp, not embedded in a compound operand.
    if span is not None:
        return None

    target_value = ctx.value_by_id.get(imm_id)
    if target_value is None:
        return None

    mov_entries: list[tuple[ImmOp, str]] = []
    for inst in ctx.guest_insts:
        mnemonic = inst.mnemonic.strip().lower()
        if mnemonic != "mov":
            continue
        if len(inst.operands) < 2:
            continue
        src_op = inst.operands[1]
        if isinstance(src_op, ImmOp) and src_op.id != 0:
            mov_entries.append((src_op, inst.operands[0].to_text()))

    movk_entries: list[tuple[ImmOp, str, str]] = []
    for inst in ctx.guest_insts:
        mnemonic = inst.mnemonic.strip().lower()
        if mnemonic != "movk":
            continue
        if len(inst.operands) < 3:
            continue
        imm_op = inst.operands[1]
        shift_op = inst.operands[2]
        if not isinstance(imm_op, ImmOp) or imm_op.id == 0:
            continue
        dest_text = inst.operands[0].to_text()
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


def _derive_index_scale(
    ctx: DerivationContext,
    imm_id: str,
    host_idx: int,
    op_idx: int,
    span: tuple[int, int] | None,
) -> str | None:
    """Derive host index scale from guest ``lsl #immN``.

    Only applies when the ``immN`` is part of a ``*immN`` scale factor
    within a host memory operand, not a plain displacement.
    """
    target_value = ctx.value_by_id.get(imm_id)
    if target_value is None:
        return None

    # Only apply to embedded immediates inside memory operands.
    if span is None:
        return None
    host_inst = ctx.host_insts[host_idx]
    host_op = host_inst.operands[op_idx]
    operand_text = host_op.to_text()

    # Verify that the character immediately before the match span is "*",
    # confirming this occurrence is a scale factor, not a displacement.
    start, _end = span
    if start == 0 or operand_text[start - 1] != "*":
        return None

    # Find guest lsl #immN operands.
    for inst in ctx.guest_insts:
        for op in inst.operands:
            if isinstance(op, (LitOp, RegTextOp)):
                text = op.to_text()
                for m in IMM_PLACEHOLDER_RE.finditer(text):
                    candidate_id = m.group(1)
                    lsl_match = re.search(rf"lsl #imm{re.escape(candidate_id)}", text)
                    if not lsl_match:
                        continue
                    shift_value = ctx.value_by_id.get(candidate_id)
                    if shift_value is None:
                        continue
                    if (1 << shift_value) == target_value:
                        return f"(1 << imm{candidate_id})"

    return None


# ── Strategy registry ──────────────────────────────────────────────────

# Strategies registered per (guest_arch, host_arch) pair.
# The derivation framework is ISA-agnostic; each ISA pair contributes
# its own strategies that understand the relevant instruction patterns.
_STRATEGIES: dict[tuple[str, str], list[DerivationStrategy]] = {
    ("aarch64", "x86-64"): [
        _derive_tbz_mask,
        _derive_movk_constant,
        _derive_index_scale,
    ],
}
