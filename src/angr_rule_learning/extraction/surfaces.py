from __future__ import annotations

from angr_rule_learning.arch.registers import (
    is_fixed_role_register,
    register_bit_range,
    register_family,
)
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
from angr_rule_learning.extraction.register_bindings import (
    RegisterBindingResult,
    RegisterBindingSolver,
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
        binding_solver: RegisterBindingSolver | None = None,
    ) -> None:
        self._diagnostics = diagnostics
        self._surface_inferer = WindowSurfaceInferer(liveness)
        self._binding_solver = binding_solver or RegisterBindingSolver()

    def infer(self, pair: WindowPair) -> VerificationCandidate | None:
        control_flow_detail = _unsupported_control_flow_detail(pair.guest)
        if control_flow_detail is None:
            control_flow_detail = _unsupported_control_flow_detail(pair.host)
        if control_flow_detail is not None:
            self._diagnostics.record_window_skipped(
                "unsupported_control_flow_surface",
                detail=control_flow_detail,
            )
            return None

        fixed_role_detail = _unbound_fixed_role_detail(pair.guest)
        if fixed_role_detail is None:
            fixed_role_detail = _unbound_fixed_role_detail(pair.host)
        if fixed_role_detail is not None:
            self._diagnostics.record_window_skipped(
                "unbound_fixed_role_register",
                detail=fixed_role_detail,
            )
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
            bindings = RegisterBindingResult()
            surface_kind = "memory"
        else:
            for surface in (guest_surface, host_surface):
                if surface.skip_reason is not None:
                    self._diagnostics.record_window_skipped(surface.skip_reason)
                    return None
            bindings = self._binding_solver.solve(
                pair,
                guest_surface,
                host_surface,
            )
            if bindings.skip_reason is not None:
                self._diagnostics.record_window_skipped(bindings.skip_reason)
                return None
            surface_kind = guest_surface.kind

        input_registers = _merge_register_pairs(
            bindings.input_registers, memory_surface.input_registers
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
            output_registers=bindings.output_registers,
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
                if surface_kind == "branch" and not bindings.output_registers
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


def _unbound_fixed_role_detail(window: InstructionWindow) -> str | None:
    prior_writes: list[str] = []
    for inst in window.instructions:
        for read_reg in inst.read_registers:
            if not is_fixed_role_register(inst.arch, read_reg):
                continue
            if not any(
                _write_covers_read(inst.arch, write_reg, read_reg)
                for write_reg in prior_writes
            ):
                return f"{inst.arch}:{read_reg.lower()}"
        prior_writes.extend(inst.write_registers)
    return None


def _write_covers_read(arch: str, writer: str, reader: str) -> bool:
    if register_family(arch, writer) != register_family(arch, reader):
        return False
    writer_range = register_bit_range(arch, writer)
    reader_range = register_bit_range(arch, reader)
    if writer_range is None or reader_range is None:
        return False
    return writer_range[0] <= reader_range[0] and writer_range[1] >= reader_range[1]


def _unsupported_control_flow_detail(window: InstructionWindow) -> str | None:
    for inst in window.instructions:
        mnemonic = inst.mnemonic.lower()
        arch = inst.arch
        if arch == "aarch64":
            if mnemonic == "b":
                return "aarch64_unconditional_branch"
            if mnemonic in {"bl", "blr"}:
                return "aarch64_call"
            if mnemonic == "br":
                return "aarch64_indirect_branch"
            if mnemonic == "ret":
                return "aarch64_return"
        if arch == "x86-64":
            if mnemonic == "jmp":
                return "x86_64_unconditional_jump"
            if mnemonic == "call":
                return "x86_64_call"
            if mnemonic == "ret":
                return "x86_64_return"
    return None


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
