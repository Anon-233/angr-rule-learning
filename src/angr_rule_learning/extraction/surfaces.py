from __future__ import annotations

from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
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
    def __init__(self, diagnostics: MiningDiagnostics) -> None:
        self._diagnostics = diagnostics

    def infer(self, pair: WindowPair) -> VerificationCandidate | None:
        if _has_memory_access(pair.guest) or _has_memory_access(pair.host):
            self._diagnostics.record_window_skipped("unsupported_memory_surface")
            return None

        guest_reads = _ordered_unique(
            reg for inst in pair.guest.instructions for reg in inst.read_registers
        )
        host_reads = _ordered_unique(
            reg for inst in pair.host.instructions for reg in inst.read_registers
        )
        guest_writes = _ordered_unique(
            reg for inst in pair.guest.instructions for reg in inst.write_registers
        )
        host_writes = _ordered_unique(
            reg for inst in pair.host.instructions for reg in inst.write_registers
        )
        if len(guest_reads) != len(host_reads) or len(guest_writes) != len(host_writes):
            self._diagnostics.record_window_skipped("ambiguous_register_surface")
            return None
        if not guest_writes and not _has_terminal_conditional_branch(pair):
            self._diagnostics.record_window_skipped("no_verifiable_surface")
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
            input_registers=tuple(zip(guest_reads, host_reads, strict=True)),
            output_registers=tuple(zip(guest_writes, host_writes, strict=True)),
            output_flags=(),
            memory=MemorySpec(),
            preconditions=(),
            clobbers=Clobbers(),
        )
        self._diagnostics.record_window_emitted(
            pair.guest.instruction_count,
            pair.host.instruction_count,
            ("register",) if guest_writes else ("branch",),
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
            op_str_lower = inst.op_str.lower()
            if "[" in op_str_lower or "]" in op_str_lower or "ptr" in op_str_lower:
                return True
    return False
