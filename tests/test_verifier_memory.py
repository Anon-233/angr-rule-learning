from __future__ import annotations

from angr_rule_learning.verification.candidate import (
    AliasDeclaration,
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)
from angr_rule_learning.verification.verifier import SemanticVerifier


AARCH64_LDR_W0_X1 = "20 00 40 b9"  # ldr w0, [x1]
X86_64_MOV_EAX_RCX_PTR = "8b 01"  # mov eax, [rcx]
X86_64_MOV_RAX_RCX_PTR = "48 8b 01"  # mov rax, [rcx]
AARCH64_STR_W0_X1 = "20 00 00 b9"  # str w0, [x1]
X86_64_MOV_RCX_PTR_EAX = "89 01"  # mov [rcx], eax


def _load_candidate(*, host_hex: str) -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id="load32",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_LDR_W0_X1, 1),
        host=CodeFragment("x86-64", 0x8048000, host_hex, 1),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )


def test_verifier_accepts_equivalent_load() -> None:
    report = SemanticVerifier().verify(_load_candidate(host_hex=X86_64_MOV_EAX_RCX_PTR))

    assert report.equivalent
    assert report.status == "pass"


def test_verifier_rejects_load_width_mismatch() -> None:
    report = SemanticVerifier().verify(_load_candidate(host_hex=X86_64_MOV_RAX_RCX_PTR))

    assert report.status == "fail"
    assert any(
        check.reason == "memory_access_width_mismatch" for check in report.checks
    )


def test_verifier_accepts_equivalent_store() -> None:
    candidate = VerificationCandidate(
        candidate_id="store32",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_STR_W0_X1, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_RCX_PTR_EAX, 1),
        input_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "write"),),
            accesses=(MemoryAccessExpectation("mem0", "write", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.equivalent
    assert report.status == "pass"


def test_verifier_accepts_must_alias_load_slots() -> None:
    candidate = VerificationCandidate(
        candidate_id="must-alias-load",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_LDR_W0_X1, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_EAX_RCX_PTR, 1),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4), MemorySlot("mem1", 4)),
            bindings=(
                MemoryBinding("mem0", "x1", "rdx", "read"),
                MemoryBinding("mem1", "x2", "rcx", "read"),
            ),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
            alias=(AliasDeclaration(("mem0", "mem1"), "must_alias"),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.equivalent
    assert report.status == "pass"


def test_verifier_rejects_host_read_address_mismatch() -> None:
    candidate = VerificationCandidate(
        candidate_id="host-read-addr-mismatch",
        guest=CodeFragment("aarch64", 0x10000, "20 00 40 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "8b 01", 1),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx + 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "fail"
    assert any(
        check.reason == "host_memory_address_mismatch" for check in report.checks
    )


def test_verifier_rejects_host_write_address_mismatch() -> None:
    candidate = VerificationCandidate(
        candidate_id="host-write-addr-mismatch",
        guest=CodeFragment("aarch64", 0x10000, "20 00 00 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "89 02", 1),
        input_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "write"),),
            accesses=(MemoryAccessExpectation("mem0", "write", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "fail"
    assert any(
        check.reason == "host_memory_address_mismatch" for check in report.checks
    )


def test_verifier_accepts_equivalent_load_with_positive_offset() -> None:
    candidate = VerificationCandidate(
        candidate_id="load32-offset",
        guest=CodeFragment("aarch64", 0x10000, "20 04 40 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "8b 41 04", 1),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(
                MemoryBinding("mem0", "x1 + 4", "rcx + 4", "read"),
            ),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass"


def test_verifier_reports_unsupported_index_scale_address_expression() -> None:
    candidate = VerificationCandidate(
        candidate_id="unsupported-index-scale",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_LDR_W0_X1, 1),
        host=CodeFragment(
            "x86-64", 0x8048000, X86_64_MOV_EAX_RCX_PTR, 1
        ),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(
                MemoryBinding(
                    "mem0", "x1", "rcx + rdx * 4", "read"
                ),
            ),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "unsupported"
    assert "unsupported_address_expression" in report.unsupported_features
