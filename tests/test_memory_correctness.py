import pytest

from angr_rule_learning.verification.addressing import parse_address_binding
from angr_rule_learning.verification.candidate import (
    AliasDeclaration,
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)
from angr_rule_learning.verification.config import VerificationConfig
from angr_rule_learning.verification.execution import FragmentExecutor
from angr_rule_learning.verification.memory import MemoryInitializer
from angr_rule_learning.verification.verifier import SemanticVerifier


def test_parse_address_binding_supports_register_plus_minus_constant() -> None:
    assert parse_address_binding("x1").base == "x1"
    assert parse_address_binding("x1").displacement == 0
    assert parse_address_binding("x1 + 4").displacement == 4
    assert parse_address_binding("rcx - 8").displacement == -8


def test_parse_address_binding_supports_register_index_addressing() -> None:
    expr = parse_address_binding("x1 + x2")
    assert expr.base == "x1"
    assert expr.index == "x2"
    assert expr.scale == 1


def test_memory_initializer_binds_register_for_positive_offset() -> None:
    candidate = VerificationCandidate(
        candidate_id="offset-load",
        guest=CodeFragment("aarch64", 0x10000, "20 04 40 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "8b 41 04", 1),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + 4", "rcx + 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    executor = FragmentExecutor()
    guest_state = executor.make_state(candidate.guest)
    host_state = executor.make_state(candidate.host)

    layout = MemoryInitializer(VerificationConfig()).initialize(
        candidate, guest_state, host_state
    )

    assert guest_state.solver.eval(guest_state.regs.x1) == layout.slot_base("mem0") - 4
    assert host_state.solver.eval(host_state.regs.rcx) == layout.slot_base("mem0") - 4


def test_conflicting_alias_declarations_report_error() -> None:
    candidate = VerificationCandidate(
        candidate_id="bad-alias",
        guest=CodeFragment("aarch64", 0x10000, "20 00 40 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "8b 01", 1),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4), MemorySlot("mem1", 4)),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
            alias=(
                AliasDeclaration(("mem0", "mem1"), "must_alias"),
                AliasDeclaration(("mem0", "mem1"), "disjoint"),
            ),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "error"
    assert report.checks[0].reason == "invalid_alias_declaration"


def test_disjoint_slots_do_not_overlap_when_stride_is_large_enough() -> None:
    candidate = VerificationCandidate(
        candidate_id="disjoint",
        guest=CodeFragment("aarch64", 0x10000, "20 00 40 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "8b 01", 1),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4), MemorySlot("mem1", 4)),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
            alias=(AliasDeclaration(("mem0", "mem1"), "disjoint"),),
        ),
    )
    executor = FragmentExecutor()
    guest_state = executor.make_state(candidate.guest)
    host_state = executor.make_state(candidate.host)

    layout = MemoryInitializer(VerificationConfig()).initialize(
        candidate, guest_state, host_state
    )

    assert layout.slot_base("mem1") - layout.slot_base("mem0") >= 4
