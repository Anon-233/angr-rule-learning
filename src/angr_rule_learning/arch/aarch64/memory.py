from __future__ import annotations

import re

from angr_rule_learning.arch.memory import MemoryKind, MemoryOperand
from angr_rule_learning.verification.addressing import AddressExpr


_VALUE_RE = r"(?P<value>[wx]\d+|sp|wsp|fp|x29|x30|lr)"
_BASE_RE = r"(?P<base>[a-z0-9]+)"
_INDEX_RE = r"(?P<index>x\d+)"

_MEM_RE = re.compile(
    rf"^{_VALUE_RE}\s*,\s*"
    rf"(?P<mem>\[{_BASE_RE}"
    rf"(?:\s*,\s*#(?P<disp>[+-]?(?:0x[0-9a-fA-F]+|\d+)))?\])$",
    re.IGNORECASE,
)
_INDEX_MEM_RE = re.compile(
    rf"^{_VALUE_RE}\s*,\s*"
    rf"(?P<mem>\[{_BASE_RE}\s*,\s*{_INDEX_RE}"
    rf"(?:\s*,\s*lsl\s*#(?P<shift>[0-3]))?\])$",
    re.IGNORECASE,
)
_PAIR_PRE_OR_OFFSET_RE = re.compile(
    r"^(?P<rt1>[a-z0-9]+)\s*,\s*(?P<rt2>[a-z0-9]+)\s*,\s*"
    r"(?P<mem>\[(?P<base>[a-z0-9]+)(?:\s*,\s*#(?P<offset>-?(?:0x[0-9a-fA-F]+|\d+)))?\])(?P<writeback>!)?$",
    re.IGNORECASE,
)
_PAIR_POST_RE = re.compile(
    r"^(?P<rt1>[a-z0-9]+)\s*,\s*(?P<rt2>[a-z0-9]+)\s*,\s*"
    r"(?P<mem>\[(?P<base>[a-z0-9]+)\]),\s*#(?P<offset>-?(?:0x[0-9a-fA-F]+|\d+))$",
    re.IGNORECASE,
)
_SP_ADDSUB_RE = re.compile(
    r"^sp\s*,\s*sp\s*,\s*#(?P<imm>(?:0x[0-9a-fA-F]+|\d+))$",
    re.IGNORECASE,
)


class AArch64MemoryRecognizer:
    def extract(self, mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]:
        if mnemonic in {"ldp", "stp", "ldnp", "stnp"}:
            return _extract_pair(mnemonic, op_str)
        if mnemonic not in {"ldr", "ldur", "ldrsw", "str", "stur"}:
            return ()

        match = _MEM_RE.match(op_str)
        if match is not None:
            value = match.group("value").lower()
            width = 4 if mnemonic == "ldrsw" else _register_width(value)
            if width is None:
                return ()
            return (
                MemoryOperand(
                    kind="read" if mnemonic in {"ldr", "ldur", "ldrsw"} else "write",
                    width=width,
                    address=AddressExpr(
                        base=match.group("base").lower(),
                        displacement=_parse_displacement(match.group("disp")),
                    ),
                    text=match.group("mem"),
                    value_register=value,
                ),
            )

        match = _INDEX_MEM_RE.match(op_str)
        if match is None:
            return ()
        value = match.group("value").lower()
        width = 4 if mnemonic == "ldrsw" else _register_width(value)
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

    def has_access(self, mnemonic: str, op_str: str) -> bool:
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
        lower = op_str.lower()
        return "[" in lower or "]" in lower

    def stack_pointer_delta(self, mnemonic: str, op_str: str) -> int:
        if mnemonic in {"stp", "stnp"}:
            match = _PAIR_PRE_OR_OFFSET_RE.match(op_str)
            if match and match.group("writeback"):
                return _parse_displacement(match.group("offset"))
            return 0
        if mnemonic in {"ldp", "ldnp"}:
            match = _PAIR_POST_RE.match(op_str)
            if match:
                return _parse_displacement(match.group("offset"))
            return 0
        if mnemonic in {"add", "sub"}:
            match = _SP_ADDSUB_RE.match(op_str)
            if match:
                immediate = int(match.group("imm"), 0)
                return immediate if mnemonic == "add" else -immediate
        return 0


def _extract_pair(mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]:
    is_store = mnemonic.startswith("st")
    is_nontemporal = mnemonic in {"stnp", "ldnp"}

    match = _PAIR_PRE_OR_OFFSET_RE.match(op_str)
    if match is not None:
        if is_nontemporal and match.group("writeback"):
            return ()
        rt1 = match.group("rt1").lower()
        rt2 = match.group("rt2").lower()
        base = match.group("base").lower()
        offset_text = match.group("offset")
        offset = _parse_displacement(offset_text)
        width = _register_width(rt1)
        if width is None:
            return ()
        kind: MemoryKind = "write" if is_store else "read"
        text1 = f"[{base}, #{offset}]" if offset_text else f"[{base}]"
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
                text=f"[{base}, #{offset + width}]",
                value_register=rt2,
            ),
        )

    match = _PAIR_POST_RE.match(op_str)
    if match is None or is_nontemporal:
        return ()
    rt1 = match.group("rt1").lower()
    rt2 = match.group("rt2").lower()
    base = match.group("base").lower()
    width = _register_width(rt1)
    if width is None:
        return ()
    kind = "write" if is_store else "read"
    return (
        MemoryOperand(
            kind=kind,
            width=width,
            address=AddressExpr(base=base),
            text=f"[{base}]",
            value_register=rt1,
        ),
        MemoryOperand(
            kind=kind,
            width=width,
            address=AddressExpr(base=base, displacement=width),
            text=f"[{base}, #{width}]",
            value_register=rt2,
        ),
    )


def _parse_displacement(text: str | None) -> int:
    if text is None:
        return 0
    return int(text, 0)


def _register_width(register: str) -> int | None:
    if register.startswith("w"):
        return 4
    if register.startswith("x") or register in {"sp", "fp", "lr"}:
        return 8
    return None


RECOGNIZER = AArch64MemoryRecognizer()
