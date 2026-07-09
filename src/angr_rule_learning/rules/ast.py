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
class ImmRefExpr:
    id: int

    def to_text(self) -> str:
        return f"imm{self.id}"

    def imm_ids(self) -> set[int]:
        return {self.id}


@dataclass(frozen=True)
class IntExpr:
    value: int

    def to_text(self) -> str:
        return str(self.value)

    def imm_ids(self) -> set[int]:
        return set()


@dataclass(frozen=True)
class ShiftLeftExpr:
    left: "ImmExpr"
    right: "ImmExpr"

    def to_text(self) -> str:
        return f"({self.left.to_text()} << {self.right.to_text()})"

    def imm_ids(self) -> set[int]:
        return self.left.imm_ids() | self.right.imm_ids()


@dataclass(frozen=True)
class Log2Expr:
    value: "ImmExpr"

    def to_text(self) -> str:
        return f"log2({self.value.to_text()})"

    def imm_ids(self) -> set[int]:
        return self.value.imm_ids()


@dataclass(frozen=True)
class RawImmExpr:
    text: str

    def to_text(self) -> str:
        return self.text

    def imm_ids(self) -> set[int]:
        return {int(m.group(1)) for m in IMM_PLACEHOLDER_RE.finditer(self.text)}


ImmExpr = ImmRefExpr | IntExpr | ShiftLeftExpr | Log2Expr | RawImmExpr


def parse_imm_expr(text: str) -> ImmExpr:
    inner = text.strip()
    if inner.startswith("${") and inner.endswith("}"):
        inner = inner[2:-1].strip()
    match = re.fullmatch(r"imm(\d+)", inner)
    if match:
        return ImmRefExpr(int(match.group(1)))
    match = re.fullmatch(r"\d+", inner)
    if match:
        return IntExpr(int(match.group(0)))
    match = re.fullmatch(r"\((.+)\s*<<\s*(.+)\)", inner)
    if match:
        return ShiftLeftExpr(
            parse_imm_expr(match.group(1)),
            parse_imm_expr(match.group(2)),
        )
    match = re.fullmatch(r"log2\((.+)\)", inner)
    if match:
        return Log2Expr(parse_imm_expr(match.group(1)))
    return RawImmExpr(inner)


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
    derived: ImmExpr | str | None = None
    aarch64_hash: bool = False  # True when the original text had a '#' prefix
    neg: bool = False  # True for negative immediates like #-imm1

    def __post_init__(self) -> None:
        if isinstance(self.derived, str):
            object.__setattr__(self, "derived", parse_imm_expr(self.derived))

    def to_text(self) -> str:
        if self.derived is not None:
            prefix = "#" if self.aarch64_hash else ""
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


@dataclass(frozen=True)
class RegViewOp:
    """Register view/cast: ``reg64(i32_reg1)``, ``reg32(i64_reg1)``.

    Expresses that a semantic placeholder is accessed at a different bit
    width at a specific use point.  ``mode="reg"`` means same-family
    register view: low bits are bound to the base placeholder, high bits
    are unspecified.  Modes ``"zext"``, ``"sext"``, and ``"lo"`` are
    reserved for future use.
    """

    base: RegOp | TmpOp
    view_bits: int
    mode: str = "reg"

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

    def to_text(self) -> str:
        return f"lo{self.bits}({self.scope}.{self.register})"


@dataclass(frozen=True)
class BitSliceOp:
    """Low-bit slice of a semantic operand: ``lo8(i32_reg1)``."""

    base: Operand
    bits: int

    def to_text(self) -> str:
        return f"lo{self.bits}({self.base.to_text()})"


@dataclass(frozen=True)
class ExtOp:
    """Zero/sign extension: ``zext32(lo8(i32_reg1))``."""

    kind: str
    bits: int
    value: Operand

    def to_text(self) -> str:
        return f"{self.kind}{self.bits}({self.value.to_text()})"


@dataclass(frozen=True)
class AddressExpr:
    base: "Operand | None"
    index: "Operand | None" = None
    scale: "Operand | None" = None
    shift: "Operand | None" = None
    displacement: "Operand | None" = None

    def to_x86_text(self) -> str:
        text = self.base.to_text() if self.base is not None else ""
        if self.index is not None:
            index = self.index.to_text()
            if self.scale is not None:
                index = f"{index}*{self.scale.to_text()}"
            text = f"{text} + {index}" if text else index
        if self.displacement is not None:
            disp = self.displacement.to_text()
            if disp.startswith("- "):
                text = f"{text} {disp}" if text else disp
            elif disp.startswith("-"):
                text = f"{text} - {disp[1:]}" if text else disp
            else:
                text = f"{text} + {disp}" if text else disp
        return f"[{text}]"

    def to_aarch64_text(self) -> str:
        if self.base is None:
            raise ValueError("aarch64 memory operand requires a base register")
        parts = [self.base.to_text()]
        if self.index is not None:
            parts.append(self.index.to_text())
            if self.shift is not None:
                parts.append(f"lsl {self.shift.to_text()}")
        elif self.displacement is not None:
            parts.append(self.displacement.to_text())
        return f"[{', '.join(parts)}]"


@dataclass(frozen=True)
class MemoryOperand:
    address: AddressExpr
    syntax: str
    value_bits: int | None = None
    size_keyword: str | None = None

    def to_text(self) -> str:
        if self.syntax == "x86":
            address = self.address.to_x86_text()
            if self.size_keyword is not None:
                return f"{self.size_keyword} ptr {address}"
            return address
        if self.syntax == "aarch64":
            return self.address.to_aarch64_text()
        raise ValueError(f"unknown memory operand syntax: {self.syntax!r}")


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
    | MemoryOperand
)


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

        memory = _parse_memory_operand(text)
        if memory is not None:
            return memory

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
        m = re.fullmatch(r"(#?)\$\{.*\}", text)
        if m:
            return ImmOp(
                id=0, derived=text.removeprefix("#"), aarch64_hash=bool(m.group(1))
            )

        # Immediate: #immN, #-immN, -immN, immN
        m = re.fullmatch(r"(#?)(-?)imm(\d+)", text)
        if m:
            return ImmOp(
                id=int(m.group(3)),
                aarch64_hash=bool(m.group(1)),
                neg=bool(m.group(2)),
            )

        # Physical Guest register view: lo8(guest.rcx)
        m = re.fullmatch(r"lo(\d+)\((guest|host)\.([A-Za-z][A-Za-z0-9]*)\)", text)
        if m:
            return GuestRegViewOp(
                scope=m.group(2).lower(),
                register=m.group(3).lower(),
                bits=int(m.group(1)),
            )

        # Zero/sign extension: zext32(lo8(i32_reg1)), sext64(i32_reg1)
        m = re.fullmatch(r"(zext|sext)(\d+)\((.+)\)", text)
        if m:
            inner = Instruction._parse_operand(m.group(3))
            return ExtOp(kind=m.group(1), bits=int(m.group(2)), value=inner)

        # Low-bit slice: lo8(i32_reg1)
        m = re.fullmatch(r"lo(\d+)\((.+)\)", text)
        if m:
            inner = Instruction._parse_operand(m.group(2))
            return BitSliceOp(base=inner, bits=int(m.group(1)))

        # Register view/cast: reg64(i32_reg1)
        m = re.fullmatch(r"reg(\d+)\((.+)\)", text)
        if m:
            view_bits = int(m.group(1))
            inner_text = m.group(2)
            base = Instruction._parse_operand(inner_text)
            if isinstance(base, (RegOp, TmpOp)):
                return RegViewOp(base=base, view_bits=view_bits)
            # If the inner text didn't parse as a placeholder, fall through
            # to LitOp rather than producing an invalid RegViewOp.

        # Register: delegate to parse_placeholder
        try:
            return parse_placeholder(text)
        except ValueError:
            pass

        # Literal: #0, #-4, 0, etc.
        return LitOp(value=text)


_X86_MEMORY_RE = re.compile(
    r"^(?:(?P<size>byte|word|dword|qword)\s+ptr\s+)?(?P<addr>\[.+\])$",
    re.IGNORECASE,
)
_SIZE_BITS = {"byte": 8, "word": 16, "dword": 32, "qword": 64}


def _parse_memory_operand(text: str) -> MemoryOperand | None:
    if text.startswith("[") and text.endswith("]") and "," in text:
        return MemoryOperand(
            address=_parse_aarch64_address(text[1:-1]),
            syntax="aarch64",
        )
    x86_match = _X86_MEMORY_RE.fullmatch(text)
    if x86_match is not None:
        size = x86_match.group("size")
        return MemoryOperand(
            address=_parse_x86_address(x86_match.group("addr")[1:-1]),
            syntax="x86",
            value_bits=_SIZE_BITS[size.lower()] if size is not None else None,
            size_keyword=size.lower() if size is not None else None,
        )
    if text.startswith("[") and text.endswith("]"):
        return MemoryOperand(
            address=_parse_x86_address(text[1:-1]),
            syntax="x86",
        )
    return None


def _parse_x86_address(inner: str) -> AddressExpr:
    base: Operand | None = None
    index: Operand | None = None
    scale: Operand | None = None
    displacement: Operand | None = None
    for sign, term in _split_signed_terms(inner):
        if "*" in term:
            left, right = (part.strip() for part in term.split("*", 1))
            index = Instruction._parse_operand(left)
            scale = Instruction._parse_operand(right)
            if sign == "-":
                scale = _negated_operand(scale)
            continue
        operand = Instruction._parse_operand(term)
        if sign == "-":
            operand = _negated_operand(operand)
        if _is_address_register_operand(operand):
            if base is None:
                base = operand
            elif index is None:
                index = operand
            else:
                displacement = operand
        else:
            displacement = operand
    if base is None and index is None:
        raise ValueError(f"x86 memory operand requires base register: {inner!r}")
    return AddressExpr(
        base=base,
        index=index,
        scale=scale,
        displacement=displacement,
    )


def _parse_aarch64_address(inner: str) -> AddressExpr:
    parts = [part.strip() for part in Instruction._split_operands(inner)]
    if not parts:
        raise ValueError("empty aarch64 memory operand")
    base = Instruction._parse_operand(parts[0])
    if len(parts) == 1:
        return AddressExpr(base=base)
    if len(parts) == 2:
        return AddressExpr(base=base, displacement=Instruction._parse_operand(parts[1]))
    if len(parts) == 3:
        shift_text = parts[2]
        if not shift_text.lower().startswith("lsl "):
            raise ValueError(f"unsupported aarch64 address modifier: {shift_text!r}")
        return AddressExpr(
            base=base,
            index=Instruction._parse_operand(parts[1]),
            shift=Instruction._parse_operand(shift_text[4:].strip()),
        )
    raise ValueError(f"unsupported aarch64 memory operand: {inner!r}")


def _split_signed_terms(text: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    sign = "+"
    depth = 0
    current: list[str] = []
    for char in text:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if depth == 0 and char in "+-":
            term = "".join(current).strip()
            if term:
                result.append((sign, term))
            sign = char
            current = []
        else:
            current.append(char)
    term = "".join(current).strip()
    if term:
        result.append((sign, term))
    return result


def _is_address_register_operand(op: Operand) -> bool:
    if isinstance(op, (RegOp, RegViewOp, TmpOp, GuestRegViewOp, BitSliceOp, ExtOp)):
        return True
    if isinstance(op, (LitOp, RegTextOp)):
        return _parse_int_literal_for_address(op.to_text()) is None
    return False


def _parse_int_literal_for_address(text: str) -> int | None:
    value = text.strip().lower().removeprefix("#").replace(" ", "")
    try:
        return int(value, 0)
    except ValueError:
        return None


def _negated_operand(op: Operand) -> Operand:
    if isinstance(op, ImmOp):
        return ImmOp(
            id=op.id,
            derived=op.derived,
            aarch64_hash=op.aarch64_hash,
            neg=not op.neg,
        )
    if isinstance(op, LitOp):
        value = op.value.strip()
        if value.startswith("-"):
            return LitOp(value=value[1:].strip())
        return LitOp(value=f"-{value}")
    return LitOp(value=f"-{op.to_text()}")


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
                new_derived = op.derived.to_text()
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
        if isinstance(op, MemoryOperand):
            return Instruction._parse_operand(
                op.to_text().replace(f"imm{imm_id}", value)
            )
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
    def _walk(op: Operand) -> None:
        visitor(op)
        if isinstance(op, RegViewOp):
            _walk(op.base)
        elif isinstance(op, BitSliceOp):
            _walk(op.base)
        elif isinstance(op, ExtOp):
            _walk(op.value)
        elif isinstance(op, MemoryOperand):
            if op.address.base is not None:
                _walk(op.address.base)
            if op.address.index is not None:
                _walk(op.address.index)
            if op.address.scale is not None:
                _walk(op.address.scale)
            if op.address.shift is not None:
                _walk(op.address.shift)
            if op.address.displacement is not None:
                _walk(op.address.displacement)

    for inst in rule.guest + rule.host:
        for op in inst.operands:
            _walk(op)
        for meta in inst.meta + inst.post_meta:
            for op in meta.regs:
                _walk(op)


# ── Placeholder parsing and collection ─────────────────────────────────


IMM_PLACEHOLDER_RE = re.compile(r"\bimm(\d+)\b")


def parse_placeholder(
    placeholder: str,
) -> RegOp | TmpOp | RegViewOp | BitSliceOp | ExtOp:
    """Parse a placeholder string into its AST operand type.

    Supports ``i32_reg1``, ``ptr64_reg1``, ``sp64``, ``fp64`` → RegOp,
    ``i32_tmp1``, ``i64_tmp1`` → TmpOp, and
    ``reg64(i32_reg1)`` → RegViewOp.
    """
    m = re.fullmatch(r"reg(\d+)\((.+)\)", placeholder)
    if m:
        view_bits = int(m.group(1))
        inner = m.group(2)
        base = parse_placeholder(inner)  # recursively parse inner
        if isinstance(base, (RegOp, TmpOp)):
            return RegViewOp(base=base, view_bits=view_bits)
        raise ValueError(f"invalid register view base: {placeholder!r}")
    m = re.fullmatch(r"(zext|sext)(\d+)\((.+)\)", placeholder)
    if m:
        value = Instruction._parse_operand(m.group(3))
        return ExtOp(kind=m.group(1), bits=int(m.group(2)), value=value)
    m = re.fullmatch(r"lo(\d+)\((.+)\)", placeholder)
    if m:
        base = Instruction._parse_operand(m.group(2))
        return BitSliceOp(base=base, bits=int(m.group(1)))
    m = re.fullmatch(r"(ptr\d+)_reg(\d+)", placeholder)
    if m:
        prefix = m.group(1)
        bits = int(prefix[3:])
        return RegOp(prefix=prefix, bits=bits, id=int(m.group(2)))
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

    def _collect(op: Operand) -> None:
        if isinstance(op, ImmOp):
            if op.derived is not None:
                ids.update(str(imm_id) for imm_id in op.derived.imm_ids())
            elif op.id != 0:
                ids.add(str(op.id))
        elif isinstance(op, (LitOp, RegTextOp)):
            for m in IMM_PLACEHOLDER_RE.finditer(op.to_text()):
                ids.add(m.group(1))
        elif isinstance(op, RegViewOp):
            _collect(op.base)
        elif isinstance(op, BitSliceOp):
            _collect(op.base)
        elif isinstance(op, ExtOp):
            _collect(op.value)
        elif isinstance(op, MemoryOperand):
            if op.address.base is not None:
                _collect(op.address.base)
            if op.address.index is not None:
                _collect(op.address.index)
            if op.address.scale is not None:
                _collect(op.address.scale)
            if op.address.shift is not None:
                _collect(op.address.shift)
            if op.address.displacement is not None:
                _collect(op.address.displacement)

    for inst in insts:
        for op in inst.operands:
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
