from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from angr_rule_learning.extraction.models import ExtractedInstruction
from angr_rule_learning.verification.addressing import (
    AddressExpr,
    parse_address_binding,
)


MemoryKind = Literal["read", "write"]


@dataclass(frozen=True)
class MemoryOperand:
    kind: MemoryKind
    width: int
    address: AddressExpr
    text: str
    value_register: str | None
    value_immediate: str | None = None


_AARCH64_VALUE_RE = r"(?P<value>[wx]\d+|sp|wsp|fp|x29|x30|lr)"
_AARCH64_BASE_RE = r"(?P<base>[a-z0-9]+)"
_AARCH64_INDEX_RE = r"(?P<index>[x]\d+)"

_AARCH64_MEM_RE = re.compile(
    rf"^{_AARCH64_VALUE_RE}\s*,\s*"
    rf"(?P<mem>\[{_AARCH64_BASE_RE}"
    rf"(?:\s*,\s*#(?P<disp>[+-]?(?:0x[0-9a-fA-F]+|\d+)))?\])$",
    re.IGNORECASE,
)

_AARCH64_PAIR_PRE_OR_OFFSET_RE = re.compile(
    r"^(?P<rt1>[a-z0-9]+)\s*,\s*(?P<rt2>[a-z0-9]+)\s*,\s*"
    r"(?P<mem>\[(?P<base>[a-z0-9]+)\s*,\s*#(?P<offset>-?(?:0x[0-9a-fA-F]+|\d+))\])(?P<writeback>!)?$",
    re.IGNORECASE,
)

_AARCH64_PAIR_POST_RE = re.compile(
    r"^(?P<rt1>[a-z0-9]+)\s*,\s*(?P<rt2>[a-z0-9]+)\s*,\s*"
    r"(?P<mem>\[(?P<base>[a-z0-9]+)\]),\s*#(?P<offset>-?(?:0x[0-9a-fA-F]+|\d+))$",
    re.IGNORECASE,
)

_AARCH64_INDEX_MEM_RE = re.compile(
    rf"^{_AARCH64_VALUE_RE}\s*,\s*"
    rf"(?P<mem>\[{_AARCH64_BASE_RE}\s*,\s*{_AARCH64_INDEX_RE}"
    rf"(?:\s*,\s*lsl\s*#(?P<shift>[0-3]))?\])$",
    re.IGNORECASE,
)

_X86_BRACKET_RE = re.compile(r"(?P<mem>\[[^\]]+\])", re.IGNORECASE)
_X86_SEGMENT_OVERRIDE_RE = re.compile(r"(?:cs|ds|es|fs|gs|ss)\s*:\s*\[", re.IGNORECASE)

_X86_RMW_MNEMONICS = frozenset({"add", "sub", "and", "or", "xor", "imul"})

_X86_PUSH_POP_REG_RE = re.compile(r"^(?P<reg>[a-z][a-z0-9]+)$", re.IGNORECASE)
_X86_PUSH_IMM_RE = re.compile(r"^(?P<imm>(?:0x[0-9a-fA-F]+|\d+))$", re.IGNORECASE)

_X86_REGISTER_TOKEN_RE = re.compile(
    r"^(?:r(?:[0-9]+|[abcd]x|[sb]p|[sd]i)|e(?:[abcd]x|[sb]p|[sd]i)|"
    r"(?:[abcd][lh])|(?:[abcd]x)|(?:[sb]p)|(?:[sd]i)|r(?:8|9|1[0-5])[bwd]?)$",
    re.IGNORECASE,
)


def _x86_register_or_immediate(text: str) -> tuple[str | None, str | None]:
    value = text.strip().lower()
    if _X86_REGISTER_TOKEN_RE.match(value):
        return value, None
    return None, value


def extract_memory_operands(
    instruction: ExtractedInstruction,
) -> tuple[MemoryOperand, ...]:
    arch = instruction.arch.strip().lower()
    mnemonic = instruction.mnemonic.strip().lower()
    op_str = instruction.op_str.strip()
    if arch == "aarch64":
        return _extract_aarch64(mnemonic, op_str)
    if arch == "x86-64":
        return _extract_x86_64(mnemonic, op_str)
    return ()


def _extract_aarch64(mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]:
    if mnemonic in {"ldp", "stp", "ldnp", "stnp"}:
        return _extract_aarch64_pair(mnemonic, op_str)
    if mnemonic not in {"ldr", "ldur", "ldrsw", "str", "stur"}:
        return ()
    # Try displacement form first: [base, #disp] or [base]
    match = _AARCH64_MEM_RE.match(op_str)
    if match is not None:
        value = match.group("value").lower()
        width = 4 if mnemonic == "ldrsw" else _aarch64_register_width(value)
        if width is None:
            return ()
        return (
            MemoryOperand(
                kind="read" if mnemonic in {"ldr", "ldur", "ldrsw"} else "write",
                width=width,
                address=AddressExpr(
                    base=match.group("base").lower(),
                    displacement=_parse_displacement(match.group("disp"), "+"),
                ),
                text=match.group("mem"),
                value_register=value,
            ),
        )
    # Try indexed form: [base, index] or [base, index, lsl #shift]
    match = _AARCH64_INDEX_MEM_RE.match(op_str)
    if match is None:
        return ()
    value = match.group("value").lower()
    width = 4 if mnemonic == "ldrsw" else _aarch64_register_width(value)
    if width is None:
        return ()
    shift = int(match.group("shift") or "0", 10)
    return (
        MemoryOperand(
            kind="read" if mnemonic in {"ldr", "ldur", "ldrsw"} else "write",
            width=width,
            address=AddressExpr(
                base=match.group("base").lower(),
                index=match.group("index").lower(),
                scale=1 << shift,
            ),
            text=match.group("mem"),
            value_register=value,
        ),
    )


def _extract_aarch64_pair(mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]:
    """Parse ``stp``/``ldp`` (and non-temporal variants) as paired memory
    operands.
    """
    is_store = mnemonic.startswith("st")

    # Try pre-index / offset form first: stp rt1, rt2, [base, #simm][!]
    match = _AARCH64_PAIR_PRE_OR_OFFSET_RE.match(op_str)
    if match is not None:
        rt1 = match.group("rt1").lower()
        rt2 = match.group("rt2").lower()
        base = match.group("base").lower()
        offset = _parse_displacement(match.group("offset"), "+")
        width = _aarch64_register_width(rt1)
        if width is None:
            return ()
        kind: MemoryKind = "write" if is_store else "read"
        text1 = f"[{base}, #{offset}]"
        text2 = f"[{base}, #{offset + width}]"
        return (
            MemoryOperand(
                kind=kind,
                width=width,
                address=AddressExpr(base=base, displacement=offset),
                text=text1,
                value_register=rt1,
            ),
            MemoryOperand(
                kind=kind,
                width=width,
                address=AddressExpr(base=base, displacement=offset + width),
                text=text2,
                value_register=rt2,
            ),
        )

    # Try post-index form: ldp rt1, rt2, [base], #simm
    match = _AARCH64_PAIR_POST_RE.match(op_str)
    if match is not None:
        rt1 = match.group("rt1").lower()
        rt2 = match.group("rt2").lower()
        base = match.group("base").lower()
        width = _aarch64_register_width(rt1)
        if width is None:
            return ()
        kind: MemoryKind = "write" if is_store else "read"
        text1 = f"[{base}]"
        text2 = f"[{base}, #{width}]"
        return (
            MemoryOperand(
                kind=kind,
                width=width,
                address=AddressExpr(base=base),
                text=text1,
                value_register=rt1,
            ),
            MemoryOperand(
                kind=kind,
                width=width,
                address=AddressExpr(base=base, displacement=width),
                text=text2,
                value_register=rt2,
            ),
        )

    return ()


def _extract_x86_64(mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]:
    if mnemonic in {"push", "pop"}:
        return _extract_x86_64_push_pop(mnemonic, op_str)
    if mnemonic not in {"mov", "movsxd"} and mnemonic not in _X86_RMW_MNEMONICS:
        return ()
    parts = [part.strip() for part in op_str.split(",", maxsplit=1)]
    if len(parts) != 2:
        return ()
    left, right = parts
    left_mem = _X86_BRACKET_RE.search(left)
    right_mem = _X86_BRACKET_RE.search(right)
    if left_mem is not None and right_mem is not None:
        return ()
    if mnemonic == "movsxd" and left_mem is not None:
        return ()
    # RMW arithmetic only supports memory-as-source (right operand);
    # memory-as-destination (add [mem], reg) requires a full RMW model.
    if mnemonic in _X86_RMW_MNEMONICS and left_mem is not None:
        return ()
    if left_mem is None and right_mem is None:
        return ()
    if left_mem is not None:
        if _X86_SEGMENT_OVERRIDE_RE.search(left):
            return ()
        value_register, value_immediate = _x86_register_or_immediate(right)
        width = _x86_width(left, value_register or "")
        if width is None:
            return ()
        operand = _x86_operand(
            "write",
            width,
            left_mem,
            value_register,
            value_immediate=value_immediate,
        )
        return (operand,) if operand is not None else ()
    if _X86_SEGMENT_OVERRIDE_RE.search(right):
        return ()
    value_register = left.strip().lower()
    if mnemonic == "movsxd":
        width = 4
    elif mnemonic in _X86_RMW_MNEMONICS:
        width = _x86_width(op_str, value_register) or _x86_width(left, value_register)
    else:
        width = _x86_width(op_str, value_register)
    if width is None:
        return ()
    operand = _x86_operand("read", width, right_mem, value_register)
    return (operand,) if operand is not None else ()


def _extract_x86_64_push_pop(mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]:
    """Parse ``push``/``pop`` as implicit rsp-relative memory operands."""
    if mnemonic == "push":
        match = _X86_PUSH_POP_REG_RE.match(op_str)
        if match is not None:
            reg = match.group("reg").lower()
            width = _x86_reg_width(reg)
            if width is None:
                return ()
            return (
                MemoryOperand(
                    kind="write",
                    width=width,
                    address=AddressExpr(base="rsp", displacement=-width),
                    text="[rsp]",
                    value_register=reg,
                ),
            )
        match = _X86_PUSH_IMM_RE.match(op_str)
        if match is not None:
            return (
                MemoryOperand(
                    kind="write",
                    width=8,
                    address=AddressExpr(base="rsp", displacement=-8),
                    text="[rsp]",
                    value_register=None,
                    value_immediate=match.group("imm"),
                ),
            )
        return ()

    if mnemonic == "pop":
        match = _X86_PUSH_POP_REG_RE.match(op_str)
        if match is not None:
            reg = match.group("reg").lower()
            width = _x86_reg_width(reg)
            if width is None:
                return ()
            return (
                MemoryOperand(
                    kind="read",
                    width=width,
                    address=AddressExpr(base="rsp"),
                    text="[rsp]",
                    value_register=reg,
                ),
            )
    return ()


def _x86_reg_width(register: str) -> int | None:
    """Return memory access width implied by an x86-64 register name."""
    reg = register.strip().lower()
    if reg.startswith("r") and len(reg) >= 3:
        return 8
    if reg.startswith("e"):
        return 4
    if reg.endswith("w"):
        return 2
    if reg.endswith("b") or reg in {
        "al",
        "ah",
        "bl",
        "bh",
        "cl",
        "ch",
        "dl",
        "dh",
    }:
        return 1
    return None


def _x86_operand(
    kind: MemoryKind,
    width: int,
    match: re.Match[str],
    value_register: str | None,
    *,
    value_immediate: str | None = None,
) -> MemoryOperand | None:
    address = _x86_address_from_mem_text(match.group("mem"))
    if address is None:
        return None
    return MemoryOperand(
        kind=kind,
        width=width,
        address=address,
        text=match.group("mem"),
        value_register=value_register,
        value_immediate=value_immediate,
    )


def _x86_address_from_mem_text(mem_text: str) -> AddressExpr | None:
    inner = mem_text.strip()[1:-1].strip().lower()
    if inner.startswith("rip"):
        return None
    if ":" in inner:
        return None
    normalized = re.sub(r"\s+", " ", inner)
    normalized = normalized.replace("*", " * ")
    normalized = re.sub(r"\s+", " ", normalized)
    try:
        return parse_address_binding(normalized)
    except ValueError:
        return None


def _parse_displacement(text: str | None, sign: str) -> int:
    if text is None:
        return 0
    value = int(text.lstrip("+-"), 0)
    if text.startswith("-") or sign == "-":
        return -value
    return value


def _aarch64_register_width(register: str) -> int | None:
    if register.startswith("w"):
        return 4
    if register.startswith("x") or register in {"sp", "fp", "lr"}:
        return 8
    return None


def has_any_memory_access(instruction: ExtractedInstruction) -> bool:
    """Return True if the instruction text suggests memory access of any form.

    This is a broad check that returns True even for memory access forms that
    ``extract_memory_operands`` cannot yet parse (e.g. ``push``/``pop``,
    ``ldp``/``stp``, indexed addressing).  Callers use it to distinguish
    "no memory access at all" from "memory access exists but is unsupported".
    """
    arch = instruction.arch.strip().lower()
    mnemonic = instruction.mnemonic.strip().lower()
    op_str_lower = instruction.op_str.lower()
    if arch == "aarch64":
        if mnemonic in {
            "ldr",
            "str",
            "ldur",
            "stur",
            "ldp",
            "stp",
            "ldnp",
            "stnp",
        }:
            return True
        if "[" in op_str_lower or "]" in op_str_lower:
            return True
    elif arch == "x86-64":
        if mnemonic in {"push", "pop", "pusha", "popa"}:
            return True
        if mnemonic == "lea":
            return False
        if "[" in op_str_lower or "]" in op_str_lower or "ptr" in op_str_lower:
            return True
    return False


def _x86_width(op_text: str, value_register: str) -> int | None:
    lower = op_text.lower()
    if "qword" in lower:
        return 8
    if "dword" in lower:
        return 4
    if "word" in lower and "dword" not in lower and "qword" not in lower:
        return 2
    if "byte" in lower:
        return 1
    if value_register.startswith("r") and len(value_register) >= 3:
        return 8
    if value_register.startswith("e"):
        return 4
    if value_register.endswith("w"):
        return 2
    if value_register.endswith("b") or value_register in {
        "al",
        "ah",
        "bl",
        "bh",
        "cl",
        "ch",
        "dl",
        "dh",
    }:
        return 1
    return None
