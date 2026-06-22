from __future__ import annotations

import re

from angr_rule_learning.arch.memory import MemoryKind, MemoryOperand
from angr_rule_learning.verification.addressing import (
    AddressExpr,
    parse_address_binding,
)


_BRACKET_RE = re.compile(r"(?P<mem>\[[^\]]+\])", re.IGNORECASE)
_SEGMENT_OVERRIDE_RE = re.compile(r"(?:cs|ds|es|fs|gs|ss)\s*:\s*\[", re.IGNORECASE)
_RMW_MNEMONICS = frozenset({"add", "sub", "and", "or", "xor", "imul"})
_PUSH_POP_REG_RE = re.compile(r"^(?P<reg>[a-z][a-z0-9]+)$", re.IGNORECASE)
_PUSH_IMM_RE = re.compile(r"^(?P<imm>(?:0x[0-9a-fA-F]+|\d+))$", re.IGNORECASE)
_SP_ADDSUB_RE = re.compile(
    r"^rsp\s*,\s*(?P<imm>(?:0x[0-9a-fA-F]+|\d+))$",
    re.IGNORECASE,
)
_REGISTER_TOKEN_RE = re.compile(
    r"^(?:r(?:[0-9]+|[abcd]x|[sb]p|[sd]i)|e(?:[abcd]x|[sb]p|[sd]i)|"
    r"(?:[abcd][lh])|(?:[abcd]x)|(?:[sb]p)|(?:[sd]i)|r(?:8|9|1[0-5])[bwd]?)$",
    re.IGNORECASE,
)


class X8664MemoryRecognizer:
    def extract(self, mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]:
        if mnemonic in {"push", "pop"}:
            return _extract_push_pop(mnemonic, op_str)
        if mnemonic not in {"mov", "movsxd"} and mnemonic not in _RMW_MNEMONICS:
            return ()

        parts = [part.strip() for part in op_str.split(",", maxsplit=1)]
        if len(parts) != 2:
            return ()
        left, right = parts
        left_mem = _BRACKET_RE.search(left)
        right_mem = _BRACKET_RE.search(right)
        if left_mem is not None and right_mem is not None:
            return ()
        if mnemonic == "movsxd" and left_mem is not None:
            return ()
        if mnemonic in _RMW_MNEMONICS and left_mem is not None:
            return ()
        if left_mem is None and right_mem is None:
            return ()

        if left_mem is not None:
            if _SEGMENT_OVERRIDE_RE.search(left):
                return ()
            value_register, value_immediate = _register_or_immediate(right)
            width = _width(left, value_register or "")
            if width is None:
                return ()
            operand = _operand(
                "write",
                width,
                left_mem,
                value_register,
                value_immediate=value_immediate,
            )
            return (operand,) if operand is not None else ()

        if _SEGMENT_OVERRIDE_RE.search(right):
            return ()
        value_register = left.lower()
        if mnemonic == "movsxd":
            width = 4
        elif mnemonic in _RMW_MNEMONICS:
            width = _width(op_str, value_register) or _width(left, value_register)
        else:
            width = _width(op_str, value_register)
        if width is None:
            return ()
        operand = _operand("read", width, right_mem, value_register)
        return (operand,) if operand is not None else ()

    def has_access(self, mnemonic: str, op_str: str) -> bool:
        if mnemonic in {"push", "pop", "pusha", "popa"}:
            return True
        if mnemonic == "lea":
            return False
        lower = op_str.lower()
        return "[" in lower or "]" in lower or "ptr" in lower

    def stack_pointer_delta(self, mnemonic: str, op_str: str) -> int:
        if mnemonic == "push":
            match = _PUSH_POP_REG_RE.search(op_str)
            if match:
                return -(_push_pop_width(match.group("reg")) or 8)
            if _PUSH_IMM_RE.search(op_str):
                return -8
            return 0
        if mnemonic == "pop":
            match = _PUSH_POP_REG_RE.search(op_str)
            if match:
                return _push_pop_width(match.group("reg")) or 8
            return 0
        if mnemonic in {"add", "sub"}:
            match = _SP_ADDSUB_RE.match(op_str)
            if match:
                immediate = int(match.group("imm"), 0)
                return immediate if mnemonic == "add" else -immediate
        return 0


def _extract_push_pop(mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]:
    if mnemonic == "push":
        match = _PUSH_POP_REG_RE.match(op_str)
        if match is not None:
            register = match.group("reg").lower()
            width = _push_pop_width(register)
            if width is None:
                return ()
            return (
                MemoryOperand(
                    kind="write",
                    width=width,
                    address=AddressExpr(base="rsp", displacement=-width),
                    text="[rsp]",
                    value_register=register,
                ),
            )
        match = _PUSH_IMM_RE.match(op_str)
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

    match = _PUSH_POP_REG_RE.match(op_str)
    if match is None:
        return ()
    register = match.group("reg").lower()
    width = _push_pop_width(register)
    if width is None:
        return ()
    return (
        MemoryOperand(
            kind="read",
            width=width,
            address=AddressExpr(base="rsp"),
            text="[rsp]",
            value_register=register,
        ),
    )


def _operand(
    kind: MemoryKind,
    width: int,
    match: re.Match[str],
    value_register: str | None,
    *,
    value_immediate: str | None = None,
) -> MemoryOperand | None:
    address = _address_from_memory_text(match.group("mem"))
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


def _address_from_memory_text(memory_text: str) -> AddressExpr | None:
    inner = memory_text.strip()[1:-1].strip().lower()
    if inner.startswith("rip") or ":" in inner:
        return None
    normalized = re.sub(r"\s+", " ", inner).replace("*", " * ")
    normalized = re.sub(r"\s+", " ", normalized)
    try:
        return parse_address_binding(normalized)
    except ValueError:
        return None


def _register_or_immediate(text: str) -> tuple[str | None, str | None]:
    value = text.strip().lower()
    if _REGISTER_TOKEN_RE.match(value):
        return value, None
    return None, value


def _push_pop_width(register: str) -> int | None:
    register = register.strip().lower()
    if re.fullmatch(r"r(?:1[0-5]|[89]|[a-d]x|[sb]p|[sd]i)", register):
        return 8
    if re.fullmatch(r"(?:[a-d]x|[bcd]x|si|di|bp|sp)|r(?:1[0-5]|[89])w", register):
        return 2
    return None


def _width(op_text: str, value_register: str) -> int | None:
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


RECOGNIZER = X8664MemoryRecognizer()
