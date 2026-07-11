from __future__ import annotations

import re
from angr_rule_learning.addressing import AddressExpr as SharedAddressExpr


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


class AddressExpr(SharedAddressExpr[str, int]):
    """Concrete 64-bit machine address specialization."""

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.base is None:
            raise ValueError("address base register is required")
        object.__setattr__(self, "base", self.base.strip().lower())
        if self.index is not None:
            object.__setattr__(self, "index", self.index.strip().lower())
        if self.scale is not None and self.scale not in {1, 2, 4, 8}:
            raise ValueError("unsupported address scale")
        if self.scale == 1:
            object.__setattr__(self, "scale", None)
        if self.displacement == 0:
            object.__setattr__(self, "displacement", None)


type ConcreteAddressExpr = AddressExpr


def address_scale(expression: ConcreteAddressExpr) -> int:
    return expression.scale if expression.scale is not None else 1


def address_displacement(expression: ConcreteAddressExpr) -> int:
    return expression.displacement if expression.displacement is not None else 0


def canonical_address(expression: ConcreteAddressExpr) -> str:
    if expression.base is None:
        raise ValueError("address base register is required")
    parts = [expression.base]
    if expression.index is not None:
        scale = address_scale(expression)
        parts.append(
            expression.index if scale == 1 else f"{expression.index} * {scale}"
        )
    text = " + ".join(parts)
    displacement = address_displacement(expression)
    if displacement > 0:
        text = f"{text} + {displacement}"
    elif displacement < 0:
        text = f"{text} - {abs(displacement)}"
    return text


def solve_base_for_slot(
    expression: ConcreteAddressExpr, slot_base: int, index_value: int = 0
) -> int:
    return (
        slot_base
        - index_value * address_scale(expression)
        - address_displacement(expression)
    )


def parse_address_binding(expression: str) -> ConcreteAddressExpr:
    expr = expression.strip().lower()
    for parser in (_parse_base, _parse_base_disp, _parse_indexed):
        parsed = parser(expr)
        if parsed is not None:
            return parsed
    raise ValueError(f"unsupported address expression: {expression}")


def _parse_base(expr: str) -> ConcreteAddressExpr | None:
    match = _BASE_RE.match(expr)
    if match is None:
        return None
    return AddressExpr(base=match.group("base"))


def _parse_base_disp(expr: str) -> ConcreteAddressExpr | None:
    match = _BASE_DISP_RE.match(expr)
    if match is None:
        return None
    return AddressExpr(
        base=match.group("base"),
        displacement=_signed_int(match.group("disp"), match.group("op")),
    )


def _parse_indexed(expr: str) -> ConcreteAddressExpr | None:
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
