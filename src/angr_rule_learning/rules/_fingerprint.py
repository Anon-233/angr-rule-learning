"""Shared fingerprint builder for alpha-equivalence.

Internal implementation detail of ``rules.ast`` — not part of the public API.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr_rule_learning.rules.ast import Instruction, MetaOp, Operand, Rule

# ── Regex patterns for embedded placeholders ──────────────────────────

_REG_RE = re.compile(r"\b((?:i|ptr)\d+)_reg(\d+)\b")


def _prefix_bits(prefix: str) -> int:
    """Extract bit width from a register prefix (``"i32"`` → 32, ``"ptr64"`` → 64)."""
    return int("".join(ch for ch in prefix if ch.isdigit()))


_REGVIEW_RE = re.compile(r"\breg(\d+)\(((?:(?:i|ptr)\d+|f\d+|v\d+)_(?:reg|tmp)\d+)\)")
_GUEST_REGVIEW_RE = re.compile(r"\blo(\d+)\((guest|host)\.([A-Za-z][A-Za-z0-9]*)\)")
_BITS_SLICE_RE = re.compile(r"\blo(\d+)\(((?:(?:i|ptr)\d+|f\d+|v\d+)_(?:reg|tmp)\d+)\)")
_EXT_RE = re.compile(
    r"\b(zext|sext)(\d+)\((lo\d+\((?:(?:i|ptr)\d+|f\d+|v\d+)_(?:reg|tmp)\d+\)|(?:(?:i|ptr)\d+|f\d+|v\d+)_(?:reg|tmp)\d+)\)"
)
_TMP_RE = re.compile(r"\b(i\d+|f\d+|v\d+)_tmp(\d+)\b")
_LABEL_RE = re.compile(r"(#?)label(\d+)\b")
_IMM_RE = re.compile(r"\bimm(\d+)\b")

# ── Marker / tag constants ────────────────────────────────────────────

GUEST_MARKER = 0
HOST_MARKER = 1
TAG_REG = 10
TAG_IMM = 11
TAG_TMP = 12
TAG_LIT = 13
TAG_LABEL = 14
TAG_REGTEXT = 15
TAG_REGVIEW = 16
TAG_GUEST_REGVIEW = 17
TAG_BITSLICE = 18
TAG_EXT = 19
TAG_SAVE = 20
TAG_RESTORE = 21
TAG_META_BLOCK = 22
TAG_POST_META_BLOCK = 23
SYN_HASH = 30
SYN_NEG = 31


class _FingerprintBuilder:
    """Builds a canonical structured fingerprint for a Rule or instruction
    sequence.

    Each namespace (registers, immediates, temporaries, labels) is
    canonicalised independently.  On first encounter, a new canonical ID
    is assigned; subsequent occurrences reuse the same ID.  This preserves
    the *relationship* graph (which operands alias each other) while
    ignoring only the arbitrary initial numbering.

    Embedded placeholder references inside ``LitOp``, ``RegTextOp``, and
    ``ImmOp.derived`` text share the same namespace maps as their
    standalone counterparts.
    """

    __slots__ = (
        "_reg_map",
        "_tmp_map",
        "_imm_map",
        "_label_map",
        "_reg_next",
        "_tmp_next",
        "_imm_next",
        "_label_next",
    )

    def __init__(self) -> None:
        self._reg_map: dict[tuple[object, ...], int] = {}
        self._tmp_map: dict[tuple[object, ...], int] = {}
        self._imm_map: dict[int, int] = {}
        self._label_map: dict[int, int] = {}
        self._reg_next = 1
        self._tmp_next = 1
        self._imm_next = 1
        self._label_next = 1

    # ── Canonical-ID lookups ──────────────────────────────────────────

    def _cid_reg(self, key: tuple[object, ...]) -> int:
        if key not in self._reg_map:
            self._reg_map[key] = self._reg_next
            self._reg_next += 1
        return self._reg_map[key]

    def _cid_tmp(self, key: tuple[object, ...]) -> int:
        if key not in self._tmp_map:
            self._tmp_map[key] = self._tmp_next
            self._tmp_next += 1
        return self._tmp_map[key]

    def _cid_imm(self, orig_id: int) -> int:
        if orig_id not in self._imm_map:
            self._imm_map[orig_id] = self._imm_next
            self._imm_next += 1
        return self._imm_map[orig_id]

    def _cid_label(self, orig_id: int) -> int:
        if orig_id not in self._label_map:
            self._label_map[orig_id] = self._label_next
            self._label_next += 1
        return self._label_map[orig_id]

    # ── Text canonicalisation (embedded placeholders) ─────────────────

    def _canon_text(self, text: str) -> tuple[object, ...]:
        matches: list[tuple[int, int, str, int, tuple[object, ...]]] = []
        for m in _LABEL_RE.finditer(text):
            is_hash = bool(m.group(1))
            cid = self._cid_label(int(m.group(2)))
            matches.append((m.start(), m.end(), "L", cid, (is_hash,)))
        # REGVIEW before TMP/REG so that reg64(i32_reg1) is matched as
        # a single unit rather than its inner placeholder first.
        for m in _REGVIEW_RE.finditer(text):
            view_bits = int(m.group(1))
            inner = m.group(2)
            # Canonicalize the inner placeholder to get its fingerprint.
            inner_fp = self._canon_text(inner)
            matches.append((m.start(), m.end(), "RV", view_bits, (view_bits, inner_fp)))
        for m in _GUEST_REGVIEW_RE.finditer(text):
            bits = int(m.group(1))
            scope = m.group(2).lower()
            register = m.group(3).lower()
            matches.append((m.start(), m.end(), "GRV", bits, (scope, register)))
        for m in _EXT_RE.finditer(text):
            kind = m.group(1)
            bits = int(m.group(2))
            inner_fp = self._canon_text(m.group(3))
            matches.append((m.start(), m.end(), "EXT", bits, (kind, inner_fp)))
        for m in _BITS_SLICE_RE.finditer(text):
            bits = int(m.group(1))
            inner_fp = self._canon_text(m.group(2))
            matches.append((m.start(), m.end(), "LO", bits, (inner_fp,)))
        for m in _TMP_RE.finditer(text):
            prefix = m.group(1)
            bits = int(prefix[1:])
            cid = self._cid_tmp((prefix, bits, int(m.group(2))))
            matches.append((m.start(), m.end(), "T", cid, (prefix, bits)))
        for m in _REG_RE.finditer(text):
            prefix = m.group(1)
            bits = _prefix_bits(prefix)
            cid = self._cid_reg((prefix, bits, int(m.group(2))))
            matches.append((m.start(), m.end(), "R", cid, (prefix, bits)))
        for m in _IMM_RE.finditer(text):
            cid = self._cid_imm(int(m.group(1)))
            matches.append((m.start(), m.end(), "I", cid, ()))
        matches.sort(key=lambda x: x[0])
        # Remove matches whose span is contained within another match
        # (e.g. reg64(i32_reg1) contains i32_reg1 — keep only the outer).
        filtered: list[tuple[int, int, str, int, tuple[object, ...]]] = []
        for i, m in enumerate(matches):
            contained = False
            for j, other in enumerate(matches):
                if i == j:
                    continue
                if other[0] <= m[0] and m[1] <= other[1]:
                    contained = True
                    break
            if not contained:
                filtered.append(m)
        parts: list[object] = []
        pos = 0
        for start, end, kind, cid, extra in filtered:
            if start > pos:
                parts.append(text[pos:start])
            parts.append(self._text_tag(kind, cid, *extra))
            pos = end
        if pos < len(text):
            parts.append(text[pos:])
        return tuple(parts)

    @staticmethod
    def _text_tag(kind: str, cid_or_bits: int, *extra: object) -> tuple[object, ...]:
        if kind == "L":
            return ("L", cid_or_bits, extra[0])
        elif kind == "T":
            return ("T", cid_or_bits, extra[0], extra[1])
        elif kind == "R":
            return ("R", cid_or_bits, extra[0], extra[1])
        elif kind == "RV":
            # extra is (view_bits, inner_fp) from the match construction.
            # extra[0] is view_bits (redundant with cid_or_bits),
            # extra[1] is the canonicalized inner fingerprint.
            return ("RV", cid_or_bits, extra[1])
        elif kind == "GRV":
            return ("GRV", cid_or_bits, extra[0], extra[1])
        elif kind == "LO":
            return ("LO", cid_or_bits, extra[0])
        elif kind == "EXT":
            return ("EXT", extra[0], cid_or_bits, extra[1])
        elif kind == "I":
            return ("I", cid_or_bits)
        raise ValueError(f"unknown text kind: {kind!r}")

    # ── Operand / meta / instruction fingerprinting ───────────────────

    def _fingerprint_op(self, op: Operand) -> tuple[object, ...]:
        from angr_rule_learning.rules.ast import (
            BitSliceOp,
            ExtOp,
            ImmOp,
            GuestRegViewOp,
            LabelOp,
            LitOp,
            RegOp,
            RegTextOp,
            RegViewOp,
            TmpOp,
        )

        if isinstance(op, RegOp):
            cid = self._cid_reg((op.prefix, op.bits, op.id))
            return (TAG_REG, cid, op.prefix, op.bits)
        elif isinstance(op, RegViewOp):
            base_fp = self._fingerprint_op(op.base)
            return (TAG_REGVIEW, op.view_bits, op.mode) + base_fp
        elif isinstance(op, GuestRegViewOp):
            return (TAG_GUEST_REGVIEW, op.bits, op.scope, op.register)
        elif isinstance(op, BitSliceOp):
            base_fp = self._fingerprint_op(op.base)
            return (TAG_BITSLICE, op.bits) + base_fp
        elif isinstance(op, ExtOp):
            value_fp = self._fingerprint_op(op.value)
            return (TAG_EXT, op.kind, op.bits) + value_fp
        elif isinstance(op, ImmOp):
            if op.derived is not None:
                return (TAG_IMM, 0, "derived") + self._canon_text(op.derived)
            cid = self._cid_imm(op.id)
            parts: list[object] = [TAG_IMM, cid]
            if op.aarch64_hash:
                parts.append(SYN_HASH)
            if op.neg:
                parts.append(SYN_NEG)
            return tuple(parts)
        elif isinstance(op, TmpOp):
            cid = self._cid_tmp((op.prefix, op.bits, op.id))
            return (TAG_TMP, cid, op.prefix, op.bits)
        elif isinstance(op, LitOp):
            return (TAG_LIT,) + self._canon_text(op.value)
        elif isinstance(op, LabelOp):
            cid = self._cid_label(op.id)
            parts: list[object] = [TAG_LABEL, cid]
            if op.aarch64_hash:
                parts.append(SYN_HASH)
            return tuple(parts)
        elif isinstance(op, RegTextOp):
            return (TAG_REGTEXT,) + self._canon_text(op.text)
        else:
            raise TypeError(f"unknown operand type: {type(op)!r}")

    def _fingerprint_meta(self, m: MetaOp) -> tuple[object, ...]:
        kind_tag = TAG_SAVE if m.kind == "save" else TAG_RESTORE
        return (kind_tag,) + tuple(p for r in m.regs for p in self._fingerprint_op(r))

    def _fingerprint_inst(self, inst: Instruction) -> tuple[object, ...]:
        parts: list[object] = [inst.mnemonic]
        if inst.meta:
            parts.append(
                (TAG_META_BLOCK,)
                + tuple(p for m in inst.meta for p in self._fingerprint_meta(m))
            )
        for op in inst.operands:
            parts.append(self._fingerprint_op(op))
        if inst.post_meta:
            parts.append(
                (TAG_POST_META_BLOCK,)
                + tuple(p for m in inst.post_meta for p in self._fingerprint_meta(m))
            )
        return tuple(parts)

    # ── Public entry points ───────────────────────────────────────────

    def fingerprint_rule(self, rule: Rule) -> tuple[object, ...]:
        """Fingerprint a full Rule with Guest/Host boundary markers."""
        guest_fps = tuple(self._fingerprint_inst(i) for i in rule.guest)
        host_fps = tuple(self._fingerprint_inst(i) for i in rule.host)
        return ((GUEST_MARKER,),) + guest_fps + ((HOST_MARKER,),) + host_fps

    def fingerprint_sequence(
        self, insts: tuple[Instruction, ...]
    ) -> tuple[object, ...]:
        """Fingerprint an instruction sequence (no Guest/Host markers)."""
        return tuple(self._fingerprint_inst(i) for i in insts)


def build_rule_fingerprint(rule: Rule) -> tuple[object, ...]:
    """Convenience wrapper — creates a fresh builder and fingerprints
    the full Rule."""
    return _FingerprintBuilder().fingerprint_rule(rule)


def build_sequence_fingerprint(
    insts: tuple[Instruction, ...],
) -> tuple[object, ...]:
    """Convenience wrapper — creates a fresh builder and fingerprints
    an instruction sequence."""
    return _FingerprintBuilder().fingerprint_sequence(insts)
