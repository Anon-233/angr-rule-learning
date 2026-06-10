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
