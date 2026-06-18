from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from angr_rule_learning.arch.registry import canonical_arch_name


@dataclass(frozen=True)
class WindowLimits:
    guest_min: int = 1
    guest_max: int = 2
    host_min: int = 1
    host_max: int = 3

    def __post_init__(self) -> None:
        if self.guest_min < 1 or self.host_min < 1:
            raise ValueError("window minimums must be positive")
        if self.guest_max < self.guest_min:
            raise ValueError("guest window maximum must be >= minimum")
        if self.host_max < self.host_min:
            raise ValueError("host window maximum must be >= minimum")

    def stage_order(self) -> tuple[tuple[int, int], ...]:
        pairs = [
            (guest_size, host_size)
            for guest_size in range(self.guest_min, self.guest_max + 1)
            for host_size in range(self.host_min, self.host_max + 1)
        ]
        return tuple(
            sorted(pairs, key=lambda pair: (pair[0] + pair[1], pair[0], pair[1]))
        )


@dataclass(frozen=True)
class CompileOptions:
    clang: str = "clang"
    optimization: str = "0"
    debug: bool = True
    common_flags: tuple[str, ...] = ("-ffreestanding", "-fno-builtin")
    guest_flags: tuple[str, ...] = ()
    host_flags: tuple[str, ...] = ()

    def command_flags_for_side(self, side: str) -> tuple[str, ...]:
        flags: list[str] = []
        if self.debug:
            flags.append("-g")
        flags.append(f"-O{self.optimization}")
        flags.extend(self.common_flags)
        if side == "guest":
            flags.extend(self.guest_flags)
        elif side == "host":
            flags.extend(self.host_flags)
        else:
            raise ValueError(f"unsupported compile side: {side}")
        return tuple(flags)


@dataclass(frozen=True)
class ExtractionConfig:
    source: Path
    work_dir: Path
    guest_arch: str = "aarch64"
    host_arch: str = "x86-64"
    compile_options: CompileOptions = field(default_factory=CompileOptions)
    window_limits: WindowLimits = field(default_factory=WindowLimits)

    def __post_init__(self) -> None:
        object.__setattr__(self, "guest_arch", canonical_arch_name(self.guest_arch))
        object.__setattr__(self, "host_arch", canonical_arch_name(self.host_arch))
