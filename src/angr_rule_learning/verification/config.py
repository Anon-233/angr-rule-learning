from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationConfig:
    max_successors: int = 1
    emit_events: bool = False
    memory_base: int = 0x70000000
    memory_stride: int = 0x1000

    def __post_init__(self) -> None:
        if self.max_successors < 1:
            raise ValueError("max_successors must be positive")
        if self.memory_stride < 1:
            raise ValueError("memory_stride must be positive")
        if self.memory_base < 0:
            raise ValueError("memory_base must be non-negative")
