from angr_rule_learning.verification.candidate import (
    CodeFragment,
    VerificationCandidate,
)
from angr_rule_learning.verification.verifier import SemanticVerifier


AARCH64_CMP_X0_X1_B_EQ = "1f 00 01 eb 40 00 00 54"
X86_64_CMP_RAX_RCX_JE = "48 39 c8 74 02"
X86_64_CMP_RAX_RCX_JNE = "48 39 c8 75 02"
AARCH64_B_EQ_THEN_CMP = "40 00 00 54 1f 00 01 eb"


def _candidate(
    host_hex: str,
    *,
    guest_hex: str = AARCH64_CMP_X0_X1_B_EQ,
) -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id="branch-guard",
        guest=CodeFragment("aarch64", 0x10000, guest_hex, 2),
        host=CodeFragment("x86-64", 0x8048000, host_hex, 2),
        input_registers=(("x0", "rax"), ("x1", "rcx")),
    )


def test_verifier_accepts_equivalent_terminal_branch_guard() -> None:
    report = SemanticVerifier().verify(_candidate(X86_64_CMP_RAX_RCX_JE))

    assert report.status == "pass"
    assert any(
        check.kind == "branch" and check.status == "pass" for check in report.checks
    )


def test_verifier_rejects_mismatched_terminal_branch_guard() -> None:
    report = SemanticVerifier().verify(_candidate(X86_64_CMP_RAX_RCX_JNE))

    assert report.status == "fail"
    assert any(
        check.kind == "branch" and check.reason == "branch_guard_mismatch"
        for check in report.checks
    )


def test_verifier_reports_non_terminal_branch_as_unsupported() -> None:
    report = SemanticVerifier().verify(
        _candidate(X86_64_CMP_RAX_RCX_JE, guest_hex=AARCH64_B_EQ_THEN_CMP)
    )

    assert report.status == "unsupported"
    assert any(
        check.reason == "non_terminal_branch_unsupported" for check in report.checks
    )


# -- end of original branch tests --


# cmp x0, x1; ldr w0, [x1]; b.eq
AARCH64_CMP_LDR_BEQ = "1f 00 01 eb 20 00 40 b9 40 00 00 54"
# cmp rax, rcx; mov eax, [rcx]; je
X86_64_CMP_MOV_RCX_PTR_JE = "48 39 c8 8b 01 74 02"


def test_verifier_branch_with_host_memory_address_mismatch_fails() -> None:
    from angr_rule_learning.verification.candidate import (
        MemoryAccessExpectation,
        MemoryBinding,
        MemorySlot,
        MemorySpec,
    )

    candidate = VerificationCandidate(
        candidate_id="branch-mem-addr-mismatch",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_CMP_LDR_BEQ, 3),
        host=CodeFragment("x86-64", 0x8048000, X86_64_CMP_MOV_RCX_PTR_JE, 3),
        input_registers=(("x0", "rax"), ("x1", "rcx")),
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


def test_verifier_branch_with_output_flags_checks_explicitly() -> None:
    candidate = VerificationCandidate(
        candidate_id="branch-with-flags",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_CMP_X0_X1_B_EQ, 2),
        host=CodeFragment("x86-64", 0x8048000, X86_64_CMP_RAX_RCX_JE, 2),
        input_registers=(("x0", "rax"), ("x1", "rcx")),
        output_flags=(("nzcv.z", "zf"),),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status != "error"
    has_flag_check = any(check.kind == "flag" for check in report.checks)
    assert has_flag_check, (
        "branch candidate with output_flags must have explicit flag check"
    )


X86_64_JMP_CMP_JE = "eb 04 48 39 c8 74 02"
AARCH64_B_CMP_BEQ = "08 00 00 14 1f 00 01 eb 40 00 00 54"


def test_verifier_reports_non_terminal_x86_jmp_as_unsupported() -> None:
    candidate = VerificationCandidate(
        candidate_id="non-term-jmp",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_CMP_X0_X1_B_EQ, 2),
        host=CodeFragment("x86-64", 0x8048000, X86_64_JMP_CMP_JE, 3),
        input_registers=(("x0", "rax"), ("x1", "rcx")),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "unsupported"
    assert any(
        check.reason == "non_terminal_branch_unsupported" for check in report.checks
    )


def test_verifier_reports_non_terminal_aarch64_b_as_unsupported() -> None:
    candidate = VerificationCandidate(
        candidate_id="non-term-b",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_B_CMP_BEQ, 3),
        host=CodeFragment("x86-64", 0x8048000, X86_64_CMP_RAX_RCX_JE, 2),
        input_registers=(("x0", "rax"), ("x1", "rcx")),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "unsupported"
    assert any(
        check.reason == "non_terminal_branch_unsupported" for check in report.checks
    )


X86_64_TERMINAL_JMP = "eb 02"
AARCH64_TERMINAL_B = "01 00 00 14"


def test_verifier_reports_terminal_x86_jmp_as_unsupported() -> None:
    candidate = VerificationCandidate(
        candidate_id="terminal-jmp",
        guest=CodeFragment("aarch64", 0x10000, "d503201f", 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_TERMINAL_JMP, 1),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "unsupported"
    assert any(
        check.reason == "unconditional_branch_unsupported" for check in report.checks
    )


def test_verifier_reports_terminal_aarch64_b_as_unsupported() -> None:
    candidate = VerificationCandidate(
        candidate_id="terminal-b",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_TERMINAL_B, 1),
        host=CodeFragment("x86-64", 0x8048000, "90", 1),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "unsupported"
    assert any(
        check.reason == "unconditional_branch_unsupported" for check in report.checks
    )
