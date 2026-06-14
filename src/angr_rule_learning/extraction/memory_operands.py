from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from angr_rule_learning.extraction.models import ExtractedInstruction


MemoryKind = Literal["read", "write"]


@dataclass(frozen=True)
class MemoryAddress:
    base: str
    displacement: int = 0

    def binding_text(self) -> str:
        if self.displacement == 0:
            return self.base
        op = "+" if self.displacement > 0 else "-"
        return f"{self.base} {op} {abs(self.displacement)}"


@dataclass(frozen=True)
class MemoryOperand:
    kind: MemoryKind
    width: int
    address: MemoryAddress
    text: str
    value_register: str


_AARCH64_MEM_RE = re.compile(
    r"(?P<value>[wx]\d+|sp|wsp|fp|x29|x30|lr)\s*,\s*"
    r"(?P<mem>\[(?P<base>[a-z0-9]+)"
    r"(?:\s*,\s*#(?P<disp>[+-]?(?:0x[0-9a-fA-F]+|\d+)))?\])",
    re.IGNORECASE,
)

_X86_MEM_RE = re.compile(
    r"(?P<mem>\[(?P<base>[a-z][a-z0-9]*)"
    r"(?:\s*(?P<sign>[+-])\s*(?P<disp>0x[0-9a-fA-F]+|\d+))?\])",
    re.IGNORECASE,
)


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
    if mnemonic not in {"ldr", "ldur", "str", "stur"}:
        return ()
    match = _AARCH64_MEM_RE.search(op_str)
    if match is None:
        return ()
    value = match.group("value").lower()
    width = _aarch64_register_width(value)
    if width is None:
        return ()
    return (
        MemoryOperand(
            kind="read" if mnemonic in {"ldr", "ldur"} else "write",
            width=width,
            address=MemoryAddress(
                base=match.group("base").lower(),
                displacement=_parse_displacement(match.group("disp"), "+"),
            ),
            text=match.group("mem"),
            value_register=value,
        ),
    )


def _extract_x86_64(mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]:
    if mnemonic != "mov":
        return ()
    parts = [part.strip() for part in op_str.split(",", maxsplit=1)]
    if len(parts) != 2:
        return ()
    left, right = parts
    left_mem = _X86_MEM_RE.search(left)
    right_mem = _X86_MEM_RE.search(right)
    if left_mem is not None and right_mem is not None:
        return ()
    if left_mem is None and right_mem is None:
        return ()
    if left_mem is not None:
        value_register = right.strip().lower()
        width = _x86_width(left, value_register)
        if width is None:
            return ()
        return (_x86_operand("write", width, left_mem, value_register),)
    value_register = left.strip().lower()
    width = _x86_width(op_str, value_register)
    if width is None:
        return ()
    return (_x86_operand("read", width, right_mem, value_register),)


def _x86_operand(
    kind: MemoryKind,
    width: int,
    match: re.Match[str],
    value_register: str,
) -> MemoryOperand:
    return MemoryOperand(
        kind=kind,
        width=width,
        address=MemoryAddress(
            base=match.group("base").lower(),
            displacement=_parse_displacement(
                match.group("disp"), match.group("sign") or "+"
            ),
        ),
        text=match.group("mem"),
        value_register=value_register,
    )


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
