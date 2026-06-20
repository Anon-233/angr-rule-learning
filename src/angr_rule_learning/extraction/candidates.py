from __future__ import annotations

from angr_rule_learning.extraction.memory_surfaces import MemorySurface
from angr_rule_learning.extraction.models import WindowPair
from angr_rule_learning.extraction.register_bindings import RegisterBindingResult
from angr_rule_learning.verification.candidate import (
    Clobbers,
    CodeFragment,
    VerificationCandidate,
)


def build_verification_candidate(
    pair: WindowPair,
    bindings: RegisterBindingResult,
    memory_surface: MemorySurface,
) -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id=candidate_id(pair),
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
        input_registers=_merge_register_pairs(
            bindings.input_registers, memory_surface.input_registers
        ),
        output_registers=bindings.output_registers,
        output_flags=(),
        memory=memory_surface.spec,
        preconditions=(),
        clobbers=Clobbers(),
    )


def candidate_id(pair: WindowPair) -> str:
    return (
        f"{pair.region_id}:"
        f"g{pair.guest.instructions[0].address:x}"
        f"-{pair.guest.instructions[-1].end_address:x}:"
        f"h{pair.host.instructions[0].address:x}"
        f"-{pair.host.instructions[-1].end_address:x}"
    )


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
