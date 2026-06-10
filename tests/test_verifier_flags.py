from angr_rule_learning.verification.candidate import (
    CodeFragment,
    VerificationCandidate,
)
from angr_rule_learning.verification.verifier import SemanticVerifier


AARCH64_CMP_X1_X2 = "3f 00 02 eb"
X86_64_CMP_RCX_RDX = "48 39 d1"


def _candidate(flags: tuple[tuple[str, str], ...]) -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id="cmp-flags",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_CMP_X1_X2, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_CMP_RCX_RDX, 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_flags=flags,
    )


def test_verifier_accepts_equivalent_zero_flag() -> None:
    report = SemanticVerifier().verify(_candidate((("nzcv.z", "zf"),)))

    assert report.status == "pass"
    assert report.checks[0].kind == "flag"
    assert report.checks[0].status == "pass"


def test_verifier_reports_unsupported_flag() -> None:
    report = SemanticVerifier().verify(_candidate((("nzcv.z", "pf"),)))

    assert report.status == "unsupported"
    assert report.checks[0].kind == "flag"
    assert report.checks[0].reason == "unsupported_flag"


def test_verifier_reports_x86_flag_on_aarch64_as_unsupported() -> None:
    candidate = VerificationCandidate(
        candidate_id="x86-flag-on-aarch64",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_CMP_X1_X2, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_CMP_RCX_RDX, 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_flags=(("zf", "zf"),),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "unsupported"
    assert any(check.reason == "unsupported_flag" for check in report.checks)
