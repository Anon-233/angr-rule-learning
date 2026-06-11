from __future__ import annotations

from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.liveness import (
    LivenessIndex,
    WindowSurfaceInferer,
)
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    WindowPair,
)
from angr_rule_learning.verification.candidate import (
    Clobbers,
    CodeFragment,
    MemorySpec,
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

        if _has_memory_access(pair.guest) or _has_memory_access(pair.host):
            self._diagnostics.record_window_skipped("unsupported_memory_surface")
            return None

        guest_surface = self._surface_inferer.infer(pair.guest)
        host_surface = self._surface_inferer.infer(pair.host)
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
            input_registers=tuple(
                zip(guest_surface.inputs, host_surface.inputs, strict=True)
            ),
            output_registers=tuple(
                zip(guest_surface.outputs, host_surface.outputs, strict=True)
            ),
            output_flags=(),
            memory=MemorySpec(),
            preconditions=(),
            clobbers=Clobbers(),
        )
        self._diagnostics.record_window_emitted(
            pair.guest.instruction_count,
            pair.host.instruction_count,
            ("branch",)
            if guest_surface.kind == "branch" and not guest_surface.outputs
            else ("register",),
        )
        return candidate


def _ordered_unique(values) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def _has_terminal_conditional_branch(pair: WindowPair) -> bool:
    return _is_conditional(pair.guest.instructions[-1]) and _is_conditional(
        pair.host.instructions[-1]
    )


def _is_conditional(instruction: ExtractedInstruction) -> bool:
    mnemonic = instruction.mnemonic.lower()
    if instruction.arch == "aarch64":
        return mnemonic.startswith(("b.", "cbz", "cbnz", "tbz", "tbnz"))
    if instruction.arch == "x86-64":
        return mnemonic.startswith("j") and mnemonic != "jmp"
    return False


def _candidate_id(pair: WindowPair) -> str:
    return (
        f"{pair.region_id}:"
        f"g{pair.guest.instructions[0].address:x}"
        f"-{pair.guest.instructions[-1].end_address:x}:"
        f"h{pair.host.instructions[0].address:x}"
        f"-{pair.host.instructions[-1].end_address:x}"
    )


def _has_memory_access(window: InstructionWindow) -> bool:
    for inst in window.instructions:
        if inst.arch == "aarch64":
            if inst.mnemonic.lower().startswith(
                ("ldr", "str", "ldp", "stp", "ldur", "stur")
            ):
                return True
            if "[" in inst.op_str or "]" in inst.op_str:
                return True
        elif inst.arch == "x86-64":
            if inst.mnemonic.lower() in ("push", "pop"):
                return True
            op_str_lower = inst.op_str.lower()
            if "[" in op_str_lower or "]" in op_str_lower or "ptr" in op_str_lower:
                return True
    return False


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


_FLAG_REGISTERS = frozenset(("nzcv", "rflags"))


def _has_flag_surface(window: InstructionWindow) -> bool:
    for inst in window.instructions:
        for reg in inst.read_registers:
            if reg in _FLAG_REGISTERS:
                return True
        for reg in inst.write_registers:
            if reg in _FLAG_REGISTERS:
                return True
    return False
