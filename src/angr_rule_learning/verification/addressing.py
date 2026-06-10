from __future__ import annotations

from dataclasses import dataclass
import re


ADDRESS_RE = re.compile(
    r"^\s*(?P<register>[A-Za-z][A-Za-z0-9_]*)"
    r"\s*(?:(?P<op>[+-])\s*(?P<offset>0x[0-9a-fA-F]+|\d+))?\s*$"
)


@dataclass(frozen=True)
class AddressBinding:
    register: str
    offset: int = 0


def parse_address_binding(expression: str) -> AddressBinding:
    match = ADDRESS_RE.match(expression)
    if match is None:
        raise ValueError(f"unsupported address expression: {expression}")
    register = match.group("register").lower()
    offset_text = match.group("offset")
    if offset_text is None:
        return AddressBinding(register)
    offset = int(offset_text, 0)
    if match.group("op") == "-":
        offset = -offset
    return AddressBinding(register, offset)
