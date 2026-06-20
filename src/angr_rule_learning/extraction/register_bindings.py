from __future__ import annotations

from dataclasses import dataclass, field

from angr_rule_learning.extraction.liveness import WindowSurface
from angr_rule_learning.extraction.memory_surfaces import MemorySurface
from angr_rule_learning.extraction.models import WindowPair


RegisterPairs = tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class BindingProblem:
    pair: WindowPair
    guest_surface: WindowSurface
    host_surface: WindowSurface
    memory_surface: MemorySurface


@dataclass(frozen=True)
class RegisterBindingResult:
    input_registers: RegisterPairs = field(default_factory=tuple)
    output_registers: RegisterPairs = field(default_factory=tuple)
    skip_reason: str | None = None
    skip_detail: str | None = None
    fallback_detail: str | None = None


class RegisterBindingSolver:
    def solve(self, problem: BindingProblem) -> RegisterBindingResult:
        guest_surface = problem.guest_surface
        host_surface = problem.host_surface
        if (
            len(guest_surface.inputs) != len(host_surface.inputs)
            or len(guest_surface.outputs) != len(host_surface.outputs)
            or guest_surface.kind != host_surface.kind
        ):
            return RegisterBindingResult(skip_reason="ambiguous_register_surface")
        return RegisterBindingResult(
            input_registers=tuple(
                zip(guest_surface.inputs, host_surface.inputs, strict=True)
            ),
            output_registers=tuple(
                zip(guest_surface.outputs, host_surface.outputs, strict=True)
            ),
        )
