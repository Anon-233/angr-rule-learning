"""Structured immediate expressions used by the rule AST."""

from __future__ import annotations

import re
from dataclasses import dataclass


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
    value: ImmExpr

    def to_text(self) -> str:
        return f"-{self.value.to_text()}"

    def imm_ids(self) -> set[int]:
        return self.value.imm_ids()


@dataclass(frozen=True)
class BitOrExpr:
    left: ImmExpr
    right: ImmExpr

    def to_text(self) -> str:
        return f"{self.left.to_text()} | {self.right.to_text()}"

    def imm_ids(self) -> set[int]:
        return self.left.imm_ids() | self.right.imm_ids()


@dataclass(frozen=True)
class ShiftLeftExpr:
    left: ImmExpr
    right: ImmExpr

    def to_text(self) -> str:
        return f"({self.left.to_text()} << {self.right.to_text()})"

    def imm_ids(self) -> set[int]:
        return self.left.imm_ids() | self.right.imm_ids()


@dataclass(frozen=True)
class Log2Expr:
    value: ImmExpr

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
        return {int(match.group(1)) for match in IMM_PLACEHOLDER_RE.finditer(self.text)}


type ImmExpr = (
    ImmRefExpr | IntExpr | NegExpr | BitOrExpr | ShiftLeftExpr | Log2Expr | RawImmExpr
)


IMM_PLACEHOLDER_RE = re.compile(r"\bimm(\d+)\b")


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
    raise ValueError(f"unsupported immediate expression: {text!r}")


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
