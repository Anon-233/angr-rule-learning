"""Structured rule representation.

Replaces text-based regex operations with typed AST nodes that support
structural comparison, substitution, and normalisation.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable, Iterator

from angr_rule_learning.addressing import AddressExpr
from angr_rule_learning.rules.ast_immediates import (
    IMM_PLACEHOLDER_RE,
    BitOrExpr,
    ImmExpr,
    ImmRefExpr,
    IntExpr,
    Log2Expr,
    NegExpr,
    RawImmExpr,
    ShiftLeftExpr,
    parse_imm_expr,
)

__all__ = [
    "AddressExpr",
    "BitOrExpr",
    "BitSliceOp",
    "ExtOp",
    "GuestRegViewOp",
    "ImmExpr",
    "ImmOp",
    "ImmRefExpr",
    "Instruction",
    "IntExpr",
    "LabelOp",
    "LitOp",
    "Log2Expr",
    "MemoryOperand",
    "MetaOp",
    "NegExpr",
    "Operand",
    "RawImmExpr",
    "ReadWriteOp",
    "RegOp",
    "RegTextOp",
    "RegViewOp",
    "Rule",
    "ShiftLeftExpr",
    "TmpOp",
    "collect_imm_ids",
    "collect_instruction_imm_ids",
    "has_literal",
    "instruction_sequences_alpha_equal",
    "iter_instruction_operands",
    "iter_operand_tree",
    "labels_are_consistent",
    "map_operand",
    "operand_children",
    "parse_imm_expr",
    "parse_instruction_sequence",
    "parse_placeholder",
    "rule_alpha_equal",
    "substitute_imm",
]


# ── Operand types ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class RegOp:
    """Typed register placeholder: ``i32_reg1``, ``sp64``, ``fp64``."""

    prefix: str  # "i8", "i16", "i32", "i64", "sp", "fp"
    bits: int
    id: int

    def __post_init__(self) -> None:
        if self.bits <= 0:
            raise ValueError("register width must be positive")
        if self.id < 0:
            raise ValueError("register placeholder id must not be negative")
        if self.prefix in {"sp", "fp"}:
            if self.id != 0:
                raise ValueError("stack/frame placeholders must use id zero")
        else:
            width_text = self.prefix.removeprefix("ptr").removeprefix("i")
            if not width_text.isdigit() or int(width_text) != self.bits:
                raise ValueError("register prefix does not match its bit width")

    def to_text(self) -> str:
        if self.prefix in ("sp", "fp"):
            return f"{self.prefix}{self.bits}"
        return f"{self.prefix}_reg{self.id}"


@dataclass(frozen=True)
class ImmOp:
    """Immediate placeholder: ``imm1``, ``#-imm1``, or ``${expression}``."""

    id: int
    derived: ImmExpr | str | None = None
    aarch64_hash: bool = False  # True when the original text had a '#' prefix
    neg: bool = False  # True for negative immediates like #-imm1

    def __post_init__(self) -> None:
        if self.derived is None and self.id < 1:
            raise ValueError("immediate placeholder id must be positive")
        if self.derived is not None and self.id != 0:
            raise ValueError("derived immediate must use id zero")
        derived = self.derived
        if isinstance(self.derived, str):
            derived = parse_imm_expr(self.derived)
            object.__setattr__(self, "derived", derived)
        if derived is not None and self.neg:
            if not isinstance(derived, NegExpr):
                object.__setattr__(self, "derived", NegExpr(derived))
            object.__setattr__(self, "neg", False)

    def to_text(self) -> str:
        if self.derived is not None:
            prefix = "#" if self.aarch64_hash else ""
            if isinstance(self.derived, NegExpr):
                return f"{prefix}-${{{self.derived.value.to_text()}}}"
            return f"{prefix}${{{self.derived.to_text()}}}"
        prefix = "#" if self.aarch64_hash else ""
        sign = "-" if self.neg else ""
        return f"{prefix}{sign}imm{self.id}"


@dataclass(frozen=True)
class TmpOp:
    """Typed temporary register: ``i32_tmp1``, ``i64_tmp1``."""

    prefix: str  # "i8", "i16", "i32", "i64", "f32", "f64", "v128"
    bits: int
    id: int

    def __post_init__(self) -> None:
        if self.bits <= 0:
            raise ValueError("temporary width must be positive")
        if self.id < 1:
            raise ValueError("temporary id must be positive")
        width_text = self.prefix[1:] if self.prefix[:1] in {"i", "f", "v"} else ""
        if not width_text.isdigit() or int(width_text) != self.bits:
            raise ValueError("temporary prefix does not match its bit width")

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

    def __post_init__(self) -> None:
        if self.id < 1:
            raise ValueError("label id must be positive")

    def to_text(self) -> str:
        prefix = "#" if self.aarch64_hash else ""
        return f"{prefix}label{self.id}"


@dataclass(frozen=True)
class RegTextOp:
    """Unresolved register text (falls back to literal)."""

    text: str

    def to_text(self) -> str:
        return self.text


@dataclass(frozen=True)
class RegViewOp:
    """Register view/cast: ``reg64(i32_reg1)``, ``reg32(i64_reg1)``.

    Expresses that a semantic placeholder is accessed at a different bit
    width at a specific use point. Low bits are bound to the base placeholder;
    newly exposed high bits are unspecified. Zero/sign extension use
    :class:`ExtOp` instead.
    """

    base: RegOp | TmpOp
    view_bits: int

    def __post_init__(self) -> None:
        if self.view_bits <= 0:
            raise ValueError("register view width must be positive")

    def to_text(self) -> str:
        return f"reg{self.view_bits}({self.base.to_text()})"


@dataclass(frozen=True)
class GuestRegViewOp:
    """View of a physical Guest register: ``lo8(guest.rcx)``.

    This expresses fixed-role or partial-register semantics that must be
    read from the Guest instruction stream rather than from a regular
    cross-ISA placeholder.  The first-stage use is x86 ``cl`` shift counts.
    """

    scope: str
    register: str
    bits: int

    def __post_init__(self) -> None:
        if self.scope not in {"guest", "host"}:
            raise ValueError("physical register view scope must be guest or host")
        if not self.register:
            raise ValueError("physical register view requires a register")
        if self.bits <= 0:
            raise ValueError("physical register view width must be positive")

    def to_text(self) -> str:
        return f"lo{self.bits}({self.scope}.{self.register})"


@dataclass(frozen=True)
class BitSliceOp:
    """Low-bit slice of a semantic operand: ``lo8(i32_reg1)``."""

    base: Operand
    bits: int

    def __post_init__(self) -> None:
        if self.bits <= 0:
            raise ValueError("bit slice width must be positive")

    def to_text(self) -> str:
        return f"lo{self.bits}({self.base.to_text()})"


@dataclass(frozen=True)
class ExtOp:
    """Zero/sign extension: ``zext32(lo8(i32_reg1))``."""

    kind: str
    bits: int
    value: Operand

    def __post_init__(self) -> None:
        if self.kind not in {"zext", "sext"}:
            raise ValueError(f"unsupported extension kind: {self.kind!r}")
        if self.bits <= 0:
            raise ValueError("extension width must be positive")

    def to_text(self) -> str:
        return f"{self.kind}{self.bits}({self.value.to_text()})"


@dataclass(frozen=True)
class ReadWriteOp:
    """One physical operand with distinct pre-state and post-state values."""

    read: Operand
    write: RegOp | TmpOp

    def to_text(self) -> str:
        return f"rw({self.read.to_text()}, {self.write.to_text()})"


@dataclass(frozen=True)
class MemoryOperand:
    address: AddressExpr
    syntax: str
    value_bits: int | None = None
    size_keyword: str | None = None

    def __post_init__(self) -> None:
        if not self.syntax.strip():
            raise ValueError("memory operand syntax must not be empty")
        if self.value_bits is not None and self.value_bits <= 0:
            raise ValueError("memory operand width must be positive")
        from angr_rule_learning.arch.rule_memory import validate_rule_memory

        validate_rule_memory(self)

    def to_text(self) -> str:
        from angr_rule_learning.arch.rule_memory import format_rule_memory

        return format_rule_memory(self)


# ── Operand union ──────────────────────────────────────────────────────

Operand = (
    RegOp
    | ImmOp
    | TmpOp
    | LitOp
    | LabelOp
    | RegTextOp
    | RegViewOp
    | GuestRegViewOp
    | BitSliceOp
    | ExtOp
    | ReadWriteOp
    | MemoryOperand
)


# ── Meta-operations ────────────────────────────────────────────────────


@dataclass(frozen=True)
class MetaOp:
    """Save/restore annotation applied to an instruction."""

    kind: str  # "save" | "restore"
    regs: tuple[Operand, ...]

    def __post_init__(self) -> None:
        if self.kind not in {"save", "restore"}:
            raise ValueError(f"unknown meta operation: {self.kind!r}")
        if not self.regs:
            raise ValueError("meta operation requires at least one register")

    def to_text(self) -> str:
        return f"{self.kind} {', '.join(r.to_text() for r in self.regs)}"


# ── Instruction ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Instruction:
    mnemonic: str
    operands: tuple[Operand, ...]
    meta: tuple[MetaOp, ...] = ()
    post_meta: tuple[MetaOp, ...] = ()

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
    def from_text(cls, line: str, *, arch: str | None = None) -> "Instruction":
        """Parse a rule text line into structured form.

        This is a best-effort parser for the subset of syntax the
        generalizer produces.  It is not a full assembly parser.
        """
        from angr_rule_learning.rules.ast_parser import parse_instruction

        return parse_instruction(line, arch=arch)

    @classmethod
    def _parse_operands(
        cls,
        text: str,
        *,
        arch: str | None = None,
    ) -> list[Operand]:
        from angr_rule_learning.rules.ast_parser import parse_operands

        return parse_operands(text, arch=arch)

    @staticmethod
    def _split_operands(text: str) -> list[str]:
        from angr_rule_learning.rules.ast_parser import split_operands

        return split_operands(text)

    @staticmethod
    def _parse_operand(text: str, *, arch: str | None = None) -> Operand:
        from angr_rule_learning.rules.ast_parser import parse_operand

        return parse_operand(text, arch=arch)


def operand_children(op: Operand) -> tuple[Operand, ...]:
    """Return direct nested operands in stable semantic order."""
    from angr_rule_learning.rules.ast_traversal import operand_children as impl

    return impl(op)


def iter_operand_tree(op: Operand) -> Iterator[Operand]:
    """Yield an operand and every nested operand depth-first."""
    from angr_rule_learning.rules.ast_traversal import iter_operand_tree as impl

    yield from impl(op)


def map_operand(op: Operand, transform: Callable[[Operand], Operand]) -> Operand:
    """Map an operand tree bottom-up while preserving wrapper semantics."""
    from angr_rule_learning.rules.ast_traversal import map_operand as impl

    return impl(op, transform)


def iter_instruction_operands(
    instructions: tuple[Instruction, ...],
) -> Iterator[Operand]:
    """Yield operands, including nested and metadata operands, in order."""
    from angr_rule_learning.rules.ast_traversal import (
        iter_instruction_operands as impl,
    )

    yield from impl(instructions)


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
        *,
        guest_arch: str | None = None,
        host_arch: str | None = None,
    ) -> "Rule":
        """Build AST from the text-based generalizer output."""
        guest = parse_instruction_sequence(guest_lines, arch=guest_arch)
        host = parse_instruction_sequence(host_lines, arch=host_arch)
        return cls(rule_id=rule_id, candidate_id=candidate_id, guest=guest, host=host)


def parse_instruction_sequence(
    lines: tuple[str, ...], *, arch: str | None = None
) -> tuple[Instruction, ...]:
    """Parse serialized rule lines and restore save/restore attachment."""
    from angr_rule_learning.rules.ast_parser import parse_instruction_sequence as impl

    return impl(lines, arch=arch)


# ── Collection helpers ────────────────────────────────────────────────


def collect_imm_ids(rule: Rule) -> set[int]:
    """Return the set of immediate placeholder IDs used in *rule*."""
    from angr_rule_learning.rules.ast_transform import collect_imm_ids as impl

    return impl(rule)


def has_literal(rule: Rule, literals: frozenset[str]) -> bool:
    """Return True if *rule* contains any of the given literal values."""
    from angr_rule_learning.rules.ast_transform import has_literal as impl

    return impl(rule, literals)


def substitute_imm(rule: Rule, imm_id: int, value: str) -> Rule:
    """Return a new rule with every occurrence of ``imm{N}`` replaced by *value*.

    Substitution handles plain ``immN``, AArch64 ``#immN``, and ``immN``
    nested inside derived ``${...}`` expressions.
    """

    from angr_rule_learning.rules.ast_transform import substitute_imm as impl

    return impl(rule, imm_id, value)


# ── Placeholder parsing and collection ─────────────────────────────────


def parse_placeholder(
    placeholder: str,
) -> RegOp | TmpOp | RegViewOp | BitSliceOp | ExtOp | ReadWriteOp:
    """Parse a placeholder string into its AST operand type.

    Supports ``i32_reg1``, ``ptr64_reg1``, ``sp64``, ``fp64`` → RegOp,
    ``i32_tmp1``, ``i64_tmp1`` → TmpOp, and
    ``reg64(i32_reg1)`` → RegViewOp.
    """
    from angr_rule_learning.rules.ast_parser import parse_placeholder as impl

    return impl(placeholder)


def collect_instruction_imm_ids(insts: tuple[Instruction, ...]) -> set[str]:
    """Collect immN placeholder IDs from AST instructions.

    Checks both typed ImmOp operands and LitOp/RegTextOp values that may
    contain embedded ``immN`` placeholders (e.g. ``dword ptr [fp64 - imm2]``).

    For ImmOp operands with a derived expression (``${…}``), the derivation
    text is scanned for guest ``immN`` references instead of collecting the
    ImmOp's own host-only id.
    """
    ids: set[str] = set()

    def _collect(op: Operand) -> None:
        if isinstance(op, ImmOp):
            if op.derived is not None:
                ids.update(str(imm_id) for imm_id in op.derived.imm_ids())
            elif op.id != 0:
                ids.add(str(op.id))
        elif isinstance(op, (LitOp, RegTextOp)):
            for m in IMM_PLACEHOLDER_RE.finditer(op.to_text()):
                ids.add(m.group(1))

    for op in iter_instruction_operands(insts):
        _collect(op)
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


def rule_alpha_equal(a: Rule, b: Rule) -> bool:
    """Return True if *a* and *b* are alpha-equivalent.

    Two rules are structurally identical but for consistent placeholder
    renumbering.  The fingerprint preserves: Guest/Host boundaries,
    instruction ordering, operand types and their alias relationships,
    metadata (save/restore) placement, and embedded placeholder
    references within ``LitOp``, ``RegTextOp``, and derived expressions.
    """
    from angr_rule_learning.rules._fingerprint import build_rule_fingerprint

    return build_rule_fingerprint(a) == build_rule_fingerprint(b)


def instruction_sequences_alpha_equal(
    a: tuple[Instruction, ...],
    b: tuple[Instruction, ...],
) -> bool:
    """Return True if two instruction sequences are alpha-equivalent."""
    from angr_rule_learning.rules._fingerprint import build_sequence_fingerprint

    return build_sequence_fingerprint(a) == build_sequence_fingerprint(b)
