"""Structured rule representation.

Replaces text-based regex operations with typed AST nodes that support
structural comparison, substitution, and normalisation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from collections.abc import Callable, Iterator
from typing import ClassVar, Literal


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
class NegExpr:
    value: "ImmExpr"

    def to_text(self) -> str:
        return f"-{self.value.to_text()}"

    def imm_ids(self) -> set[int]:
        return self.value.imm_ids()


@dataclass(frozen=True)
class BitOrExpr:
    left: "ImmExpr"
    right: "ImmExpr"

    def to_text(self) -> str:
        return f"{self.left.to_text()} | {self.right.to_text()}"

    def imm_ids(self) -> set[int]:
        return self.left.imm_ids() | self.right.imm_ids()


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


ImmExpr = (
    ImmRefExpr | IntExpr | NegExpr | BitOrExpr | ShiftLeftExpr | Log2Expr | RawImmExpr
)


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
    if inner.startswith("-"):
        return NegExpr(parse_imm_expr(inner[1:].strip()))
    split = _split_top_level_expr(inner, "|")
    if split is not None:
        left, right = split
        return BitOrExpr(parse_imm_expr(left), parse_imm_expr(right))
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


def _split_top_level_expr(text: str, operator: str) -> tuple[str, str] | None:
    depth = 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == operator and depth == 0:
            return text[:index].strip(), text[index + 1 :].strip()
    return None


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
class ReadWriteOp:
    """One physical operand with distinct pre-state and post-state values."""

    read: Operand
    write: RegOp | TmpOp

    def to_text(self) -> str:
        return f"rw({self.read.to_text()}, {self.write.to_text()})"


@dataclass(frozen=True)
class AddressExpr:
    base: "Operand | None"
    index: "Operand | None" = None
    scale: "Operand | None" = None
    shift: "Operand | None" = None
    displacement: "Operand | None" = None
    writeback: Literal["none", "pre", "post"] = "none"

    def __post_init__(self) -> None:
        if self.scale is not None and self.index is None:
            raise ValueError("address scale requires an index")
        if self.shift is not None and self.index is None:
            raise ValueError("address shift requires an index")
        if self.scale is not None and self.shift is not None:
            raise ValueError("address cannot contain both scale and shift")
        if self.writeback not in {"none", "pre", "post"}:
            raise ValueError(f"unknown address writeback mode: {self.writeback!r}")
        if self.writeback != "none" and self.base is None:
            raise ValueError("writeback address requires a base")
        if self.writeback != "none" and self.displacement is None:
            raise ValueError("writeback address requires a displacement")
        if self.writeback == "post" and self.index is not None:
            raise ValueError("post-index address cannot contain an index")

    def to_x86_text(self) -> str:
        if self.writeback != "none":
            raise ValueError("x86 address does not support writeback")
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
        if self.writeback == "post":
            return f"[{self.base.to_text()}], {self.displacement.to_text()}"
        parts = [self.base.to_text()]
        if self.index is not None:
            parts.append(self.index.to_text())
            if self.shift is not None:
                parts.append(f"lsl {self.shift.to_text()}")
        elif self.displacement is not None:
            parts.append(self.displacement.to_text())
        suffix = "!" if self.writeback == "pre" else ""
        return f"[{', '.join(parts)}]{suffix}"


@dataclass(frozen=True)
class MemoryOperand:
    address: AddressExpr
    syntax: str
    value_bits: int | None = None
    size_keyword: str | None = None

    def __post_init__(self) -> None:
        if self.syntax not in {"x86", "aarch64"}:
            raise ValueError(f"unknown memory operand syntax: {self.syntax!r}")
        if self.value_bits is not None and self.value_bits <= 0:
            raise ValueError("memory operand width must be positive")
        if self.syntax == "x86":
            if self.address.shift is not None:
                raise ValueError("x86 memory operand cannot use shift")
            if self.address.writeback != "none":
                raise ValueError("x86 memory operand cannot use writeback")
        else:
            if self.address.base is None:
                raise ValueError("aarch64 memory operand requires a base")
            if self.address.scale is not None:
                raise ValueError("aarch64 memory operand cannot use scale")
            if self.address.index is not None and self.address.displacement is not None:
                raise ValueError(
                    "aarch64 memory operand cannot combine index and displacement"
                )
            if self.size_keyword is not None:
                raise ValueError("aarch64 memory operand cannot use x86 size keyword")
        if self.size_keyword is not None:
            keyword = self.size_keyword.lower()
            if keyword not in _SIZE_BITS:
                raise ValueError(
                    f"unknown x86 memory size keyword: {self.size_keyword!r}"
                )
            if self.value_bits is not None and self.value_bits != _SIZE_BITS[keyword]:
                raise ValueError("memory width does not match size keyword")

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
    def from_text(cls, line: str, *, arch: str | None = None) -> "Instruction":
        """Parse a rule text line into structured form.

        This is a best-effort parser for the subset of syntax the
        generalizer produces.  It is not a full assembly parser.
        """
        tokens = line.strip().split(maxsplit=1)
        mnemonic = tokens[0]
        ops_text = tokens[1] if len(tokens) > 1 else ""
        operands = tuple(cls._parse_operands(ops_text, arch=arch))
        return cls(mnemonic=mnemonic, operands=operands, post_meta=())

    @classmethod
    def _parse_operands(
        cls,
        text: str,
        *,
        arch: str | None = None,
    ) -> list[Operand]:
        if not text:
            return []
        # Split on commas that are not inside brackets or ${}.
        parts = cls._split_operands(text)
        result: list[Operand] = []
        index = 0
        while index < len(parts):
            operand = cls._parse_operand(parts[index].strip(), arch=arch)
            if (
                isinstance(operand, MemoryOperand)
                and operand.syntax == "aarch64"
                and operand.address.writeback == "none"
                and index + 1 == len(parts) - 1
            ):
                update = cls._parse_operand(parts[index + 1].strip(), arch=arch)
                address = operand.address
                operand = MemoryOperand(
                    address=AddressExpr(
                        base=address.base,
                        index=address.index,
                        scale=address.scale,
                        shift=address.shift,
                        displacement=update,
                        writeback="post",
                    ),
                    syntax=operand.syntax,
                    value_bits=operand.value_bits,
                    size_keyword=operand.size_keyword,
                )
                index += 1
            result.append(operand)
            index += 1
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
    def _parse_operand(text: str, *, arch: str | None = None) -> Operand:
        text = text.strip()
        if not text:
            return RegTextOp(text)

        memory = _parse_memory_operand(text, syntax_hint=_memory_syntax_for_arch(arch))
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
        m = re.fullmatch(r"(#?)(-?)\$\{.*\}", text)
        if m:
            derived_text = text[len(m.group(1)) + len(m.group(2)) :]
            return ImmOp(
                id=0,
                derived=derived_text,
                aarch64_hash=bool(m.group(1)),
                neg=bool(m.group(2)),
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

        # Implicit read/modify/write register with distinct semantic roles.
        m = re.fullmatch(r"rw\((.*)\)", text)
        if m:
            parts = Instruction._split_operands(m.group(1))
            if len(parts) != 2:
                raise ValueError(f"read/write operand requires two roles: {text!r}")
            read = Instruction._parse_operand(parts[0])
            write = Instruction._parse_operand(parts[1])
            if not isinstance(write, (RegOp, TmpOp)):
                raise ValueError(f"read/write destination is not assignable: {text!r}")
            return ReadWriteOp(read=read, write=write)

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


def operand_children(op: Operand) -> tuple[Operand, ...]:
    """Return direct nested operands in stable semantic order."""
    if isinstance(op, RegViewOp):
        return (op.base,)
    if isinstance(op, BitSliceOp):
        return (op.base,)
    if isinstance(op, ExtOp):
        return (op.value,)
    if isinstance(op, ReadWriteOp):
        return (op.read, op.write)
    if isinstance(op, MemoryOperand):
        address = op.address
        return tuple(
            child
            for child in (
                address.base,
                address.index,
                address.scale,
                address.shift,
                address.displacement,
            )
            if child is not None
        )
    return ()


def iter_operand_tree(op: Operand) -> Iterator[Operand]:
    """Yield an operand and every nested operand depth-first."""
    yield op
    for child in operand_children(op):
        yield from iter_operand_tree(child)


def map_operand(op: Operand, transform: Callable[[Operand], Operand]) -> Operand:
    """Map an operand tree bottom-up while preserving wrapper semantics."""
    rebuilt = op
    if isinstance(op, RegViewOp):
        base = map_operand(op.base, transform)
        if not isinstance(base, (RegOp, TmpOp)):
            raise ValueError("register view transform produced invalid base")
        rebuilt = RegViewOp(base=base, view_bits=op.view_bits, mode=op.mode)
    elif isinstance(op, BitSliceOp):
        rebuilt = BitSliceOp(base=map_operand(op.base, transform), bits=op.bits)
    elif isinstance(op, ExtOp):
        rebuilt = ExtOp(
            kind=op.kind,
            bits=op.bits,
            value=map_operand(op.value, transform),
        )
    elif isinstance(op, ReadWriteOp):
        read = map_operand(op.read, transform)
        write = map_operand(op.write, transform)
        if not isinstance(write, (RegOp, TmpOp)):
            raise ValueError("read/write transform produced invalid destination")
        rebuilt = ReadWriteOp(read=read, write=write)
    elif isinstance(op, MemoryOperand):
        address = op.address

        def _map_optional(child: Operand | None) -> Operand | None:
            return map_operand(child, transform) if child is not None else None

        rebuilt = MemoryOperand(
            address=AddressExpr(
                base=_map_optional(address.base),
                index=_map_optional(address.index),
                scale=_map_optional(address.scale),
                shift=_map_optional(address.shift),
                displacement=_map_optional(address.displacement),
                writeback=address.writeback,
            ),
            syntax=op.syntax,
            value_bits=op.value_bits,
            size_keyword=op.size_keyword,
        )
    return transform(rebuilt)


def iter_instruction_operands(
    instructions: tuple[Instruction, ...],
) -> Iterator[Operand]:
    """Yield operands, including nested and metadata operands, in order."""
    for instruction in instructions:
        for operand in instruction.operands:
            yield from iter_operand_tree(operand)
        for meta in instruction.meta + instruction.post_meta:
            for operand in meta.regs:
                yield from iter_operand_tree(operand)


_X86_MEMORY_RE = re.compile(
    r"^(?:(?P<size>byte|word|dword|qword)\s+ptr\s+)?(?P<addr>\[.+\])$",
    re.IGNORECASE,
)
_SIZE_BITS = {"byte": 8, "word": 16, "dword": 32, "qword": 64}


def _memory_syntax_for_arch(arch: str | None) -> str | None:
    if arch is None:
        return None
    normalized = arch.strip().lower().replace("_", "-")
    if normalized in {"aarch64", "arm64"}:
        return "aarch64"
    if normalized in {"x86-64", "amd64"}:
        return "x86"
    return None


def _parse_memory_operand(
    text: str, *, syntax_hint: str | None = None
) -> MemoryOperand | None:
    pre_index = text.endswith("]!")
    bracket_text = text[:-1] if pre_index else text
    if (
        syntax_hint == "aarch64"
        and bracket_text.startswith("[")
        and bracket_text.endswith("]")
    ) or (
        bracket_text.startswith("[")
        and bracket_text.endswith("]")
        and "," in bracket_text
    ):
        return MemoryOperand(
            address=_parse_aarch64_address(
                bracket_text[1:-1], writeback="pre" if pre_index else "none"
            ),
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
            if index is not None or scale is not None:
                raise ValueError(
                    f"x86 memory operand has multiple index terms: {inner!r}"
                )
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
                raise ValueError(
                    f"x86 memory operand has too many register terms: {inner!r}"
                )
        else:
            if displacement is not None:
                raise ValueError(
                    f"x86 memory operand has multiple displacements: {inner!r}"
                )
            displacement = operand
    if base is None and index is None:
        raise ValueError(f"x86 memory operand requires base register: {inner!r}")
    return AddressExpr(
        base=base,
        index=index,
        scale=scale,
        displacement=displacement,
    )


def _parse_aarch64_address(
    inner: str, *, writeback: Literal["none", "pre"] = "none"
) -> AddressExpr:
    parts = [part.strip() for part in Instruction._split_operands(inner)]
    if not parts:
        raise ValueError("empty aarch64 memory operand")
    base = Instruction._parse_operand(parts[0])
    if len(parts) == 1:
        return AddressExpr(base=base, writeback=writeback)
    if len(parts) == 2:
        second = Instruction._parse_operand(parts[1])
        if _is_address_register_operand(second):
            return AddressExpr(base=base, index=second, writeback=writeback)
        return AddressExpr(base=base, displacement=second, writeback=writeback)
    if len(parts) == 3:
        shift_text = parts[2]
        if not shift_text.lower().startswith("lsl "):
            raise ValueError(f"unsupported aarch64 address modifier: {shift_text!r}")
        return AddressExpr(
            base=base,
            index=Instruction._parse_operand(parts[1]),
            shift=Instruction._parse_operand(shift_text[4:].strip()),
            writeback=writeback,
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
        if op.derived is not None:
            derived = op.derived
            if isinstance(derived, NegExpr):
                derived = derived.value
            else:
                derived = NegExpr(derived)
            return ImmOp(
                id=op.id,
                derived=derived,
                aarch64_hash=op.aarch64_hash,
            )
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
    result: list[Instruction] = []
    pending_meta: list[MetaOp] = []
    for line in lines:
        parsed = Instruction.from_text(line, arch=arch)
        mnemonic = parsed.mnemonic.lower()
        if mnemonic == "save":
            pending_meta.append(MetaOp("save", parsed.operands))
            continue
        if mnemonic == "restore":
            if pending_meta:
                raise ValueError("restore cannot appear before pending save target")
            if not result:
                raise ValueError("restore requires a preceding instruction")
            previous = result[-1]
            result[-1] = Instruction(
                mnemonic=previous.mnemonic,
                operands=previous.operands,
                meta=previous.meta,
                post_meta=previous.post_meta + (MetaOp("restore", parsed.operands),),
            )
            continue
        result.append(
            Instruction(
                mnemonic=parsed.mnemonic,
                operands=parsed.operands,
                meta=tuple(pending_meta),
                post_meta=parsed.post_meta,
            )
        )
        pending_meta.clear()
    if pending_meta:
        raise ValueError("save requires a following instruction")
    return tuple(result)


# ── Collection helpers ────────────────────────────────────────────────


def collect_imm_ids(rule: Rule) -> set[int]:
    """Return the set of immediate placeholder IDs used in *rule*."""
    ids: set[int] = set()

    def _walk(op):
        if isinstance(op, ImmOp):
            if op.derived is not None:
                ids.update(op.derived.imm_ids())
            elif op.id != 0:
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

    def _literal_expr() -> ImmExpr:
        try:
            return IntExpr(int(value, 0))
        except ValueError:
            return RawImmExpr(value)

    def _sub_expr(expr: ImmExpr) -> ImmExpr:
        if isinstance(expr, ImmRefExpr):
            return _literal_expr() if expr.id == imm_id else expr
        if isinstance(expr, ShiftLeftExpr):
            return ShiftLeftExpr(_sub_expr(expr.left), _sub_expr(expr.right))
        if isinstance(expr, BitOrExpr):
            return BitOrExpr(_sub_expr(expr.left), _sub_expr(expr.right))
        if isinstance(expr, NegExpr):
            return NegExpr(_sub_expr(expr.value))
        if isinstance(expr, Log2Expr):
            return Log2Expr(_sub_expr(expr.value))
        if isinstance(expr, RawImmExpr):
            text = re.sub(rf"\bimm{imm_id}\b", value, expr.text)
            return RawImmExpr(text)
        return expr

    def _sub(op: Operand) -> Operand:
        if isinstance(op, ImmOp):
            if op.id == imm_id:
                prefix = "#" if op.aarch64_hash else ""
                literal = value
                if op.neg:
                    try:
                        literal = str(-int(value, 0))
                    except ValueError:
                        literal = value[1:] if value.startswith("-") else f"-{value}"
                return LitOp(value=f"{prefix}{literal}")
            if op.derived is not None:
                return ImmOp(
                    id=op.id,
                    derived=_sub_expr(op.derived),
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

    def _sub_meta(meta: MetaOp) -> MetaOp:
        return MetaOp(meta.kind, tuple(map_operand(op, _sub) for op in meta.regs))

    def _sub_inst(inst: Instruction) -> Instruction:
        return Instruction(
            mnemonic=inst.mnemonic,
            operands=tuple(map_operand(op, _sub) for op in inst.operands),
            meta=tuple(_sub_meta(meta) for meta in inst.meta),
            post_meta=tuple(_sub_meta(meta) for meta in inst.post_meta),
        )

    return Rule(
        rule_id=rule.rule_id,
        candidate_id=rule.candidate_id,
        guest=tuple(_sub_inst(i) for i in rule.guest),
        host=tuple(_sub_inst(i) for i in rule.host),
    )


def _walk_rule(rule: Rule, visitor):
    for operand in iter_instruction_operands(rule.guest + rule.host):
        visitor(operand)


# ── Placeholder parsing and collection ─────────────────────────────────


IMM_PLACEHOLDER_RE = re.compile(r"\bimm(\d+)\b")


def parse_placeholder(
    placeholder: str,
) -> RegOp | TmpOp | RegViewOp | BitSliceOp | ExtOp | ReadWriteOp:
    """Parse a placeholder string into its AST operand type.

    Supports ``i32_reg1``, ``ptr64_reg1``, ``sp64``, ``fp64`` → RegOp,
    ``i32_tmp1``, ``i64_tmp1`` → TmpOp, and
    ``reg64(i32_reg1)`` → RegViewOp.
    """
    m = re.fullmatch(r"rw\((.*)\)", placeholder)
    if m:
        parsed = Instruction._parse_operand(placeholder)
        if isinstance(parsed, ReadWriteOp):
            return parsed
        raise ValueError(f"invalid read/write placeholder: {placeholder!r}")
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
