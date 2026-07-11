from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


type WritebackMode = Literal["none", "pre", "post"]


@dataclass(frozen=True)
class AddressExpr[RegisterT, ImmediateT]:
    """Architecture-neutral effective-address structure.

    The model deliberately leaves register and immediate representation to
    its caller.  Extraction uses concrete register names and integers while
    the rule AST uses typed operand nodes.  ISA adapters own syntax-specific
    validation and formatting.
    """

    base: RegisterT | None
    index: RegisterT | None = None
    scale: ImmediateT | None = None
    shift: ImmediateT | None = None
    displacement: ImmediateT | None = None
    writeback: WritebackMode = "none"

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

    def registers(self) -> tuple[RegisterT, ...]:
        result = [self.base] if self.base is not None else []
        if self.index is not None:
            result.append(self.index)
        return tuple(result)
