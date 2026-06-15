from __future__ import annotations

import re
from dataclasses import dataclass


_REGISTER_RE = r"[A-Za-z][A-Za-z0-9_]*"
_INTEGER_RE = r"0x[0-9a-fA-F]+|\d+"

_BASE_RE = re.compile(rf"^\s*(?P<base>{_REGISTER_RE})\s*$")
_BASE_DISP_RE = re.compile(
    rf"^\s*(?P<base>{_REGISTER_RE})\s*"
    rf"(?P<op>[+-])\s*(?P<disp>{_INTEGER_RE})\s*$"
)
_INDEX_RE = re.compile(
    rf"^\s*(?P<base>{_REGISTER_RE})\s*\+\s*"
    rf"(?P<index>{_REGISTER_RE})"
    rf"(?:\s*\*\s*(?P<scale>{_INTEGER_RE}))?"
    rf"(?:\s*(?P<op>[+-])\s*(?P<disp>{_INTEGER_RE}))?\s*$"
)


@dataclass(frozen=True)
class AddressExpr:
    base: str | None
    index: str | None = None
    scale: int = 1
    displacement: int = 0
    width: int = 64

    def __post_init__(self) -> None:
        base = self.base.strip().lower() if self.base is not None else None
        index = self.index.strip().lower() if self.index is not None else None
        object.__setattr__(self, "base", base)
        object.__setattr__(self, "index", index)
        if base is None:
            raise ValueError("address base register is required")
        if index is None and self.scale != 1:
            raise ValueError("scale requires index")
        if self.scale not in {1, 2, 4, 8}:
            raise ValueError("unsupported address scale")
        if self.width != 64:
            raise ValueError("only 64-bit addresses are supported")

    def registers(self) -> tuple[str, ...]:
        result = [self.base] if self.base is not None else []
        if self.index is not None:
            result.append(self.index)
        return tuple(result)

    def canonical(self) -> str:
        parts = [self.base]
        if self.index is not None:
            if self.scale == 1:
                parts.append(self.index)
            else:
                parts.append(f"{self.index} * {self.scale}")
        text = " + ".join(part for part in parts if part)
        if self.displacement > 0:
            text = f"{text} + {self.displacement}"
        elif self.displacement < 0:
            text = f"{text} - {abs(self.displacement)}"
        return text

    def solve_base_for_slot(self, slot_base: int, index_value: int = 0) -> int:
        return slot_base - index_value * self.scale - self.displacement


def parse_address_binding(expression: str) -> AddressExpr:
    expr = expression.strip().lower()
    for parser in (_parse_base, _parse_base_disp, _parse_indexed):
        parsed = parser(expr)
        if parsed is not None:
            return parsed
    raise ValueError(f"unsupported address expression: {expression}")


def _parse_base(expr: str) -> AddressExpr | None:
    match = _BASE_RE.match(expr)
    if match is None:
        return None
    return AddressExpr(base=match.group("base"))


def _parse_base_disp(expr: str) -> AddressExpr | None:
    match = _BASE_DISP_RE.match(expr)
    if match is None:
        return None
    return AddressExpr(
        base=match.group("base"),
        displacement=_signed_int(match.group("disp"), match.group("op")),
    )


def _parse_indexed(expr: str) -> AddressExpr | None:
    match = _INDEX_RE.match(expr)
    if match is None:
        return None
    scale_text = match.group("scale")
    scale = int(scale_text, 0) if scale_text is not None else 1
    disp_text = match.group("disp")
    displacement = 0
    if disp_text is not None:
        displacement = _signed_int(disp_text, match.group("op"))
    return AddressExpr(
        base=match.group("base"),
        index=match.group("index"),
        scale=scale,
        displacement=displacement,
    )


def _signed_int(text: str, sign: str | None) -> int:
    value = int(text, 0)
    return -value if sign == "-" else value
