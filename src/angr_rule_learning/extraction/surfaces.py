from __future__ import annotations

from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.liveness import (
    LivenessIndex,
    WindowSurfaceInferer,
)
from angr_rule_learning.extraction.memory_surfaces import (
    infer_memory_surface,
)
from angr_rule_learning.extraction.models import (
    InstructionWindow,
    WindowPair,
)
from angr_rule_learning.verification.candidate import (
    Clobbers,
    CodeFragment,
    VerificationCandidate,
)


class SurfaceInferer:
    def __init__(
        self,
        diagnostics: MiningDiagnostics,
        liveness: LivenessIndex,
    ) -> None:
        self._diagnostics = diagnostics
        self._surface_inferer = WindowSurfaceInferer(liveness)

    def infer(self, pair: WindowPair) -> VerificationCandidate | None:
        if _has_unsupported_control_flow(pair.guest) or _has_unsupported_control_flow(
            pair.host
        ):
            self._diagnostics.record_window_skipped("unsupported_control_flow_surface")
            return None

        memory_surface = infer_memory_surface(pair)
        if memory_surface.skip_reason is not None:
            self._diagnostics.record_window_skipped(
                memory_surface.skip_reason,
                detail=memory_surface.skip_detail,
            )
            return None

        guest_surface = self._surface_inferer.infer(pair.guest)
        host_surface = self._surface_inferer.infer(pair.host)

        if memory_surface.spec.slots and all(
            surface.skip_reason == "no_verifiable_surface"
            for surface in (guest_surface, host_surface)
        ):
            guest_inputs: tuple[str, ...] = ()
            host_inputs: tuple[str, ...] = ()
            guest_outputs: tuple[str, ...] = ()
            host_outputs: tuple[str, ...] = ()
            surface_kind = "memory"
        else:
            for surface in (guest_surface, host_surface):
                if surface.skip_reason is not None:
                    self._diagnostics.record_window_skipped(surface.skip_reason)
                    return None
            if len(guest_surface.inputs) != len(host_surface.inputs) or len(
                guest_surface.outputs
            ) != len(host_surface.outputs):
                self._diagnostics.record_window_skipped("ambiguous_register_surface")
                return None
            if guest_surface.kind != host_surface.kind:
                self._diagnostics.record_window_skipped("ambiguous_register_surface")
                return None
            guest_inputs = guest_surface.inputs
            host_inputs = host_surface.inputs
            guest_outputs = guest_surface.outputs
            host_outputs = host_surface.outputs
            surface_kind = guest_surface.kind

        input_registers = tuple(zip(guest_inputs, host_inputs, strict=True))
        input_registers = _merge_register_pairs(
            input_registers, memory_surface.input_registers
        )

        candidate = VerificationCandidate(
            candidate_id=_candidate_id(pair),
            guest=CodeFragment(
                pair.guest.instructions[0].arch,
                pair.guest.address,
                pair.guest.code_hex,
                pair.guest.instruction_count,
            ),
            host=CodeFragment(
                pair.host.instructions[0].arch,
                pair.host.address,
                pair.host.code_hex,
                pair.host.instruction_count,
            ),
            input_registers=input_registers,
            output_registers=tuple(zip(guest_outputs, host_outputs, strict=True)),
            output_flags=(),
            memory=memory_surface.spec,
            preconditions=(),
            clobbers=Clobbers(),
        )
        self._diagnostics.record_window_emitted(
            pair.guest.instruction_count,
            pair.host.instruction_count,
            ("memory",)
            if surface_kind == "memory"
            else (
                ("branch",)
                if surface_kind == "branch" and not guest_outputs
                else ("register",)
            ),
        )
        return candidate


def _candidate_id(pair: WindowPair) -> str:
    return (
        f"{pair.region_id}:"
        f"g{pair.guest.instructions[0].address:x}"
        f"-{pair.guest.instructions[-1].end_address:x}:"
        f"h{pair.host.instructions[0].address:x}"
        f"-{pair.host.instructions[-1].end_address:x}"
    )


_UNSUPPORTED_CONTROL_FLOW = {
    "aarch64": frozenset(("b", "bl", "br", "blr", "ret")),
    "x86-64": frozenset(("jmp", "ret", "call")),
}


def _has_unsupported_control_flow(window: InstructionWindow) -> bool:
    for inst in window.instructions:
        mnemonic = inst.mnemonic.lower()
        arch = inst.arch
        if arch in _UNSUPPORTED_CONTROL_FLOW:
            if mnemonic in _UNSUPPORTED_CONTROL_FLOW[arch]:
                return True
    return False


def _merge_register_pairs(
    left: tuple[tuple[str, str], ...],
    right: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    result: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for pair in left + right:
        if pair not in seen:
            seen.add(pair)
            result.append(pair)
    return tuple(result)
