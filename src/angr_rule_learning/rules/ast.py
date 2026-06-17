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
    """Temporary register: ``tmp1``."""

    id: int

    def to_text(self) -> str:
        return f"tmp{self.id}"


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

    _PUNCT_RE: ClassVar[re.Pattern[str]] = re.compile(r"([\[\],#+*\-])")

    def to_text(self) -> str:
        if not self.operands:
            return self.mnemonic
        ops = ", ".join(op.to_text() for op in self.operands)
        return f"{self.mnemonic} {ops}"

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
        return cls(mnemonic=mnemonic, operands=operands)

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

        # Temp
        m = re.fullmatch(r"tmp(\d+)", text)
        if m:
            return TmpOp(id=int(m.group(1)))

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

        # Register: i32_reg1, sp64, fp64
        m = re.fullmatch(r"(i\d+)_reg(\d+)", text)
        if m:
            bits = int(m.group(1)[1:])
            return RegOp(prefix=m.group(1), bits=bits, id=int(m.group(2)))
        m = re.fullmatch(r"(sp|fp)(\d+)", text)
        if m:
            return RegOp(prefix=m.group(1), bits=int(m.group(2)), id=0)

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
            for meta in inst.meta:
                lines.append(f"\t{meta.to_text()}")
            lines.append(f"\t{inst.to_text()}")
        lines.append(".Host:")
        for inst in self.host:
            for meta in inst.meta:
                lines.append(f"\t{meta.to_text()}")
            lines.append(f"\t{inst.to_text()}")
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
    nested inside derived ``\${...}`` expressions.
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
        )

    return Rule(
        rule_id=rule.rule_id,
        candidate_id=rule.candidate_id,
        guest=tuple(_sub_inst(i) for i in rule.guest),
        host=tuple(_sub_inst(i) for i in rule.host),
    )


def structurally_equal(a: Rule, b: Rule) -> bool:
    """Return True if *a* and *b* have the same structure (ignoring IDs)."""
    return _insts_equal(a.guest, b.guest) and _insts_equal(a.host, b.host)


def _walk_rule(rule: Rule, visitor):
    for inst in rule.guest + rule.host:
        for op in inst.operands:
            visitor(op)
        for meta in inst.meta:
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
        return True
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
        if len(ia.operands) != len(ib.operands):
            return False
        for oa, ob in zip(ia.operands, ib.operands):
            if not _op_equal(oa, ob):
                return False
    return True
