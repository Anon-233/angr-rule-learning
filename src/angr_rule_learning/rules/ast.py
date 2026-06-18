"""Structured rule representation.

Replaces text-based regex operations with typed AST nodes that support
structural comparison, substitution, and normalisation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar


# ── Operand types ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class RegOp:
    """Typed register placeholder: ``i32_reg1``, ``sp64``, ``fp64``."""

    prefix: str  # "i8", "i16", "i32", "i64", "sp", "fp"
    bits: int
    id: int

    def to_text(self) -> str:
        if self.prefix in ("sp", "fp"):
            return f"{self.prefix}{self.bits}"
        return f"{self.prefix}_reg{self.id}"


@dataclass(frozen=True)
class ImmOp:
    """Immediate placeholder: ``imm1``, ``#-imm1``, or ``${expression}``."""

    id: int
    derived: str | None = None  # "${ (1 << imm1) }" when derived
    aarch64_hash: bool = False  # True when the original text had a '#' prefix
    neg: bool = False  # True for negative immediates like #-imm1

    def to_text(self) -> str:
        if self.derived is not None:
            return self.derived
        prefix = "#" if self.aarch64_hash else ""
        sign = "-" if self.neg else ""
        return f"{prefix}{sign}imm{self.id}"


@dataclass(frozen=True)
class TmpOp:
    """Typed temporary register: ``i32_tmp1``, ``i64_tmp1``."""

    prefix: str  # "i8", "i16", "i32", "i64", "f32", "f64", "v128"
    bits: int
    id: int

    def to_text(self) -> str:
        return f"{self.prefix}_tmp{self.id}"


@dataclass(frozen=True)
class LitOp:
    """Literal value preserved as-is: ``0``, ``#0``, ``#-4``."""

    value: str

    def to_text(self) -> str:
        return self.value


@dataclass(frozen=True)
class LabelOp:
    """Branch label: ``label1`` or ``#label1``."""

    id: int
    aarch64_hash: bool = False

    def to_text(self) -> str:
        prefix = "#" if self.aarch64_hash else ""
        return f"{prefix}label{self.id}"


@dataclass(frozen=True)
class RegTextOp:
    """Unresolved register text (falls back to literal)."""

    text: str

    def to_text(self) -> str:
        return self.text


# ── Operand union ──────────────────────────────────────────────────────

Operand = RegOp | ImmOp | TmpOp | LitOp | LabelOp | RegTextOp


# ── Meta-operations ────────────────────────────────────────────────────


@dataclass(frozen=True)
class MetaOp:
    """Save/restore annotation applied to an instruction."""

    kind: str  # "save" | "restore"
    regs: tuple[Operand, ...]

    def to_text(self) -> str:
        return f"{self.kind} {', '.join(r.to_text() for r in self.regs)}"


# ── Instruction ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Instruction:
    mnemonic: str
    operands: tuple[Operand, ...]
    meta: tuple[MetaOp, ...] = ()
    post_meta: tuple[MetaOp, ...] = ()

    _PUNCT_RE: ClassVar[re.Pattern[str]] = re.compile(r"([\[\],#+*\-])")

    def to_text(self) -> str:
        parts: list[str] = []
        for m in self.meta:
            parts.append(m.to_text())
        if not self.operands:
            line = self.mnemonic
        else:
            ops = ", ".join(op.to_text() for op in self.operands)
            line = f"{self.mnemonic} {ops}"
        parts.append(line)
        for m in self.post_meta:
            parts.append(m.to_text())
        return "\n".join(parts)

    @classmethod
    def from_text(cls, line: str) -> "Instruction":
        """Parse a rule text line into structured form.

        This is a best-effort parser for the subset of syntax the
        generalizer produces.  It is not a full assembly parser.
        """
        tokens = line.strip().split(maxsplit=1)
        mnemonic = tokens[0]
        ops_text = tokens[1] if len(tokens) > 1 else ""
        operands = tuple(cls._parse_operands(ops_text))
        return cls(mnemonic=mnemonic, operands=operands, post_meta=())

    @classmethod
    def _parse_operands(cls, text: str) -> list[Operand]:
        if not text:
            return []
        # Split on commas that are not inside brackets or ${}.
        parts = cls._split_operands(text)
        result: list[Operand] = []
        for part in parts:
            result.append(cls._parse_operand(part.strip()))
        return result

    @staticmethod
    def _split_operands(text: str) -> list[str]:
        parts: list[str] = []
        depth = 0
        current: list[str] = []
        for ch in text:
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            if ch == "," and depth == 0:
                parts.append("".join(current))
                current = []
            else:
                current.append(ch)
        if current:
            parts.append("".join(current))
        return parts

    @staticmethod
    def _parse_operand(text: str) -> Operand:
        text = text.strip()
        if not text:
            return RegTextOp(text)

        # Label
        m = re.fullmatch(r"(#?)label(\d+)", text)
        if m:
            return LabelOp(id=int(m.group(2)), aarch64_hash=bool(m.group(1)))

        # Temp: i32_tmp1, i64_tmp1, etc.
        m = re.fullmatch(r"(i\d+|f\d+|v\d+)_tmp(\d+)", text)
        if m:
            prefix = m.group(1)
            bits = int(prefix[1:])
            return TmpOp(prefix=prefix, bits=bits, id=int(m.group(2)))

        # Immediate with derivation
        m = re.fullmatch(r"\$\{\((\d+)\s*<<\s*(\d+)\)\}", text)
        if m:
            return ImmOp(id=0, derived=text)
        # Generic derived immediate
        m = re.fullmatch(r"\$\{.*\}", text)
        if m:
            return ImmOp(id=0, derived=text)

        # Immediate: #immN, #-immN, -immN, immN
        m = re.fullmatch(r"(#?)(-?)imm(\d+)", text)
        if m:
            return ImmOp(
                id=int(m.group(3)),
                aarch64_hash=bool(m.group(1)),
                neg=bool(m.group(2)),
            )

        # Register: delegate to parse_placeholder
        try:
            return parse_placeholder(text)
        except ValueError:
            pass

        # Literal: #0, #-4, 0, etc.
        return LitOp(value=text)


# ── Rule ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Rule:
    rule_id: int
    candidate_id: str
    guest: tuple[Instruction, ...]
    host: tuple[Instruction, ...]

    def to_text(self) -> str:
        lines = [f"{self.rule_id}.Guest:"]
        for inst in self.guest:
            for line in inst.to_text().split("\n"):
                lines.append(f"\t{line}")
        lines.append(".Host:")
        for inst in self.host:
            for line in inst.to_text().split("\n"):
                lines.append(f"\t{line}")
        lines.append("")  # trailing blank separator
        return "\n".join(lines) + "\n"

    @classmethod
    def from_generated(
        cls,
        rule_id: int,
        candidate_id: str,
        guest_lines: tuple[str, ...],
        host_lines: tuple[str, ...],
    ) -> "Rule":
        """Build AST from the text-based generalizer output."""
        guest = tuple(Instruction.from_text(ln) for ln in guest_lines)
        host = tuple(Instruction.from_text(ln) for ln in host_lines)
        return cls(rule_id=rule_id, candidate_id=candidate_id, guest=guest, host=host)


# ── Collection helpers ────────────────────────────────────────────────


def collect_imm_ids(rule: Rule) -> set[int]:
    """Return the set of immediate placeholder IDs used in *rule*."""
    ids: set[int] = set()

    def _walk(op):
        if isinstance(op, ImmOp) and op.id != 0:
            ids.add(op.id)

    _walk_rule(rule, _walk)
    return ids


def has_literal(rule: Rule, literals: frozenset[str]) -> bool:
    """Return True if *rule* contains any of the given literal values."""
    found = False

    def _walk(op):
        nonlocal found
        if isinstance(op, LitOp) and op.value in literals:
            found = True

    _walk_rule(rule, _walk)
    return found


def substitute_imm(rule: Rule, imm_id: int, value: str) -> Rule:
    """Return a new rule with every occurrence of ``imm{N}`` replaced by *value*.

    Substitution handles plain ``immN``, AArch64 ``#immN``, and ``immN``
    nested inside derived ``${...}`` expressions.
    """

    def _sub(op: Operand) -> Operand:
        if isinstance(op, ImmOp):
            if op.id == imm_id:
                prefix = "#" if op.aarch64_hash else ""
                return LitOp(value=f"{prefix}{value}")
            if op.derived is not None:
                new_derived = op.derived
                new_derived = re.sub(rf"#imm{imm_id}\b", f"#{value}", new_derived)
                new_derived = re.sub(rf"(?<!\$)imm{imm_id}\b", value, new_derived)
                return ImmOp(
                    id=op.id,
                    derived=new_derived,
                    aarch64_hash=op.aarch64_hash,
                    neg=op.neg,
                )
            return op
        if isinstance(op, LitOp):
            text = op.value
            text = re.sub(rf"#imm{imm_id}\b", f"#{value}", text)
            text = re.sub(rf"(?<!\$)imm{imm_id}\b", value, text)
            return LitOp(value=text)
        return op

    def _sub_inst(inst: Instruction) -> Instruction:
        return Instruction(
            mnemonic=inst.mnemonic,
            operands=tuple(_sub(op) for op in inst.operands),
            meta=inst.meta,
            post_meta=inst.post_meta,
        )

    return Rule(
        rule_id=rule.rule_id,
        candidate_id=rule.candidate_id,
        guest=tuple(_sub_inst(i) for i in rule.guest),
        host=tuple(_sub_inst(i) for i in rule.host),
    )


def _walk_rule(rule: Rule, visitor):
    for inst in rule.guest + rule.host:
        for op in inst.operands:
            visitor(op)
        for meta in inst.meta + inst.post_meta:
            for op in meta.regs:
                visitor(op)


def _op_equal(a: Operand, b: Operand) -> bool:
    if type(a) is not type(b):
        return False
    if isinstance(a, RegOp) and isinstance(b, RegOp):
        return a.prefix == b.prefix and a.bits == b.bits
    if isinstance(a, ImmOp) and isinstance(b, ImmOp):
        return (
            a.derived == b.derived
            and a.aarch64_hash == b.aarch64_hash
            and a.neg == b.neg
        )
    if isinstance(a, TmpOp) and isinstance(b, TmpOp):
        return a.prefix == b.prefix and a.bits == b.bits
    if isinstance(a, LitOp) and isinstance(b, LitOp):
        return a.value == b.value
    if isinstance(a, LabelOp) and isinstance(b, LabelOp):
        return a.aarch64_hash == b.aarch64_hash
    if isinstance(a, RegTextOp) and isinstance(b, RegTextOp):
        return a.text == b.text
    return False


def _insts_equal(a: tuple[Instruction, ...], b: tuple[Instruction, ...]) -> bool:
    if len(a) != len(b):
        return False
    for ia, ib in zip(a, b):
        if ia.mnemonic != ib.mnemonic:
            return False
        if ia.meta != ib.meta:
            return False
        if ia.post_meta != ib.post_meta:
            return False
        if len(ia.operands) != len(ib.operands):
            return False
        for oa, ob in zip(ia.operands, ib.operands):
            if not _op_equal(oa, ob):
                return False
    return True


# ── Placeholder parsing and collection ─────────────────────────────────


IMM_PLACEHOLDER_RE = re.compile(r"\bimm(\d+)\b")


def parse_placeholder(placeholder: str) -> RegOp | TmpOp:
    """Parse a placeholder string into its AST operand type.

    Supports ``i32_reg1``, ``sp64``, ``fp64`` → RegOp, and
    ``i32_tmp1``, ``i64_tmp1`` → TmpOp.
    """
    m = re.fullmatch(r"(i\d+)_reg(\d+)", placeholder)
    if m:
        bits = int(m.group(1)[1:])
        return RegOp(prefix=m.group(1), bits=bits, id=int(m.group(2)))
    m = re.fullmatch(r"(sp|fp)(\d+)", placeholder)
    if m:
        return RegOp(prefix=m.group(1), bits=int(m.group(2)), id=0)
    m = re.fullmatch(r"(i\d+|f\d+|v\d+)_tmp(\d+)", placeholder)
    if m:
        prefix = m.group(1)
        bits = int(prefix[1:])
        return TmpOp(prefix=prefix, bits=bits, id=int(m.group(2)))
    raise ValueError(f"unknown placeholder format: {placeholder!r}")


def collect_instruction_imm_ids(insts: tuple[Instruction, ...]) -> set[str]:
    """Collect immN placeholder IDs from AST instructions.

    Checks both typed ImmOp operands and LitOp/RegTextOp values that may
    contain embedded ``immN`` placeholders (e.g. ``dword ptr [fp64 - imm2]``).

    For ImmOp operands with a derived expression (``${…}``), the derivation
    text is scanned for guest ``immN`` references instead of collecting the
    ImmOp's own host-only id.
    """
    ids: set[str] = set()
    for inst in insts:
        for op in inst.operands:
            if isinstance(op, ImmOp) and op.id != 0:
                if op.derived is not None:
                    for m in IMM_PLACEHOLDER_RE.finditer(op.derived):
                        ids.add(m.group(1))
                else:
                    ids.add(str(op.id))
            elif isinstance(op, (LitOp, RegTextOp)):
                for m in IMM_PLACEHOLDER_RE.finditer(op.to_text()):
                    ids.add(m.group(1))
    return ids


def labels_are_consistent(
    guest: tuple[Instruction, ...],
    host: tuple[Instruction, ...],
) -> bool:
    """Check that guest and host use the same set of label IDs."""

    def _collect(insts: tuple[Instruction, ...]) -> set[str]:
        return {
            str(op.id)
            for inst in insts
            for op in inst.operands
            if isinstance(op, LabelOp)
        }

    guest_labels = _collect(guest)
    host_labels = _collect(host)
    if guest_labels or host_labels:
        return guest_labels == host_labels
    return True


# ── Alpha-equivalence ───────────────────────────────────────────────────

_REG_PLACEHOLDER_RE = re.compile(r"(i\d+)_reg(\d+)\b")
_TMP_PLACEHOLDER_RE = re.compile(r"\b(i\d+|f\d+|v\d+)_tmp(\d+)\b")
_LABEL_PLACEHOLDER_RE = re.compile(r"#?label(\d+)\b")


def canonicalize_rule(rule: Rule) -> tuple[int, ...]:
    """Return a canonical integer fingerprint that preserves placeholder
    relationships across the entire *rule*.

    Guest and host instructions share the same namespace maps so that
    relationships between guest and host operands are preserved.  Two
    rules that are the same modulo consistent placeholder renumbering
    produce identical fingerprints.  Two rules where the same guest
    register maps to different operand positions produce different
    fingerprints.

    Each namespace (registers, temps, immediates, labels) gets its own
    canonical-ID map so that relationships are only compared within the
    same kind, but guest and host share the same map per kind.
    """
    return _canonicalize_instruction_sequence(rule.guest + rule.host)


def _canonicalize_instruction_sequence(
    insts: tuple[Instruction, ...],
) -> tuple[int, ...]:
    """Return a flat integer fingerprint for a sequence of instructions.

    Uses independent namespace maps so that two sequences produce identical
    fingerprints when they are the same modulo consistent renumbering of
    placeholder IDs.
    """
    # Map: (key) -> canonical_id for each namespace.
    reg_map: dict[tuple[object, ...], int] = {}
    tmp_map: dict[tuple[object, ...], int] = {}
    imm_map: dict[tuple[object, ...], int] = {}
    label_map: dict[tuple[object, ...], int] = {}

    reg_next = 1
    tmp_next = 1
    imm_next = 1
    label_next = 1

    _REG_PAD_RE = re.compile(r"(i\d+)_reg(\d+)\b")
    _IMM_PAD_RE = re.compile(r"\bimm(\d+)\b")
    _TMP_PAD_RE = re.compile(r"\b(i\d+|f\d+|v\d+)_tmp(\d+)\b")
    _LABEL_PAD_RE = re.compile(r"#?label(\d+)\b")

    def _lookup_reg(key: tuple[object, ...]) -> int:
        nonlocal reg_next
        if key not in reg_map:
            reg_map[key] = reg_next
            reg_next += 1
        return reg_map[key]

    def _lookup_tmp(key: tuple[object, ...]) -> int:
        nonlocal tmp_next
        if key not in tmp_map:
            tmp_map[key] = tmp_next
            tmp_next += 1
        return tmp_map[key]

    def _lookup_imm(key: tuple[object, ...]) -> int:
        nonlocal imm_next
        if key not in imm_map:
            imm_map[key] = imm_next
            imm_next += 1
        return imm_map[key]

    def _lookup_label(key: tuple[object, ...]) -> int:
        nonlocal label_next
        if key not in label_map:
            label_map[key] = label_next
            label_next += 1
        return label_map[key]

    def _canonicalize_lit_text(text: str) -> str:
        """Replace placeholder IDs in text with canonical numbers."""

        def _reg_repl(m: re.Match[str]) -> str:
            prefix = m.group(1)
            orig_id = int(m.group(2))
            cid = _lookup_reg((prefix, orig_id))
            return f"{prefix}_reg{cid}"

        def _imm_repl(m: re.Match[str]) -> str:
            orig_id = int(m.group(1))
            cid = _lookup_imm(("inline", orig_id))
            return f"imm{cid}"

        def _tmp_repl(m: re.Match[str]) -> str:
            prefix = m.group(1)
            orig_id = int(m.group(2))
            bits = int(prefix[1:])
            cid = _lookup_tmp((prefix, bits, orig_id))
            return f"{prefix}_tmp{cid}"

        def _label_repl(m: re.Match[str]) -> str:
            orig_id = int(m.group(1))
            is_hash = m.group(0).startswith("#")
            cid = _lookup_label((orig_id, is_hash))
            prefix = "#" if is_hash else ""
            return f"{prefix}label{cid}"

        # label and reg before imm so `#imm1` is not mangled.
        text = _LABEL_PAD_RE.sub(_label_repl, text)
        text = _TMP_PAD_RE.sub(_tmp_repl, text)
        text = _REG_PAD_RE.sub(_reg_repl, text)
        text = _IMM_PAD_RE.sub(_imm_repl, text)
        return text

    def _canonicalize_operand(op: Operand) -> tuple[int, int, ...]:
        if isinstance(op, RegOp):
            cid = _lookup_reg((op.prefix, op.bits, op.id))
            return (0, cid)
        elif isinstance(op, ImmOp):
            if op.derived is not None:
                norm = _canonicalize_lit_text(op.derived)
                cid = _lookup_imm(("derived", norm))
            else:
                cid = _lookup_imm((op.id, op.aarch64_hash, op.neg))
            return (1, cid)
        elif isinstance(op, TmpOp):
            cid = _lookup_tmp((op.prefix, op.bits, op.id))
            return (2, cid)
        elif isinstance(op, LitOp):
            text = _canonicalize_lit_text(op.value)
            return (3, hash(text))
        elif isinstance(op, LabelOp):
            cid = _lookup_label((op.id, op.aarch64_hash))
            return (4, cid)
        elif isinstance(op, RegTextOp):
            text = _canonicalize_lit_text(op.text)
            return (5, hash(text))
        else:
            raise TypeError(f"unknown operand type: {type(op)!r}")

    def _canonicalize_meta(meta: MetaOp) -> tuple[int, ...]:
        kind_hash = hash(meta.kind)
        sigs: list[int] = [kind_hash]
        for r in meta.regs:
            sigs.extend(_canonicalize_operand(r))
        return tuple(sigs)

    def _canonicalize_instruction(inst: Instruction) -> tuple[int, ...]:
        mnemonic_hash = hash(inst.mnemonic)
        sigs = [mnemonic_hash]
        for op in inst.operands:
            sigs.extend(_canonicalize_operand(op))
        for m in inst.meta:
            sigs.extend(_canonicalize_meta(m))
        for m in inst.post_meta:
            sigs.extend(_canonicalize_meta(m))
        return tuple(sigs)

    flat: list[int] = []
    for inst in insts:
        flat.extend(_canonicalize_instruction(inst))
    return tuple(flat)


def rule_alpha_equal(a: Rule, b: Rule) -> bool:
    """Return True if *a* and *b* are alpha-equivalent.

    Two rules are alpha-equivalent when they differ only by consistent
    renaming of placeholder IDs (registers, immediates, temporaries,
    labels) but preserve all relationships between placeholders.
    """
    return canonicalize_rule(a) == canonicalize_rule(b)


def instruction_sequences_alpha_equal(
    a: tuple[Instruction, ...],
    b: tuple[Instruction, ...],
) -> bool:
    """Return True if two instruction sequences are alpha-equivalent.

    Compares the sequences directly, using independent namespace maps so
    that only the relative structure within each sequence matters.
    """
    return _canonicalize_instruction_sequence(a) == _canonicalize_instruction_sequence(
        b
    )
