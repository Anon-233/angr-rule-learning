from angr_rule_learning.verification.candidate import (
    CodeFragment,
    VerificationCandidate,
)
from angr_rule_learning.verification.config import VerificationConfig
from angr_rule_learning.verification.verifier import SemanticVerifier


def test_verifier_reports_unknown_output_register_as_error() -> None:
    candidate = VerificationCandidate(
        candidate_id="bad-register",
        guest=CodeFragment("aarch64", 0x10000, "20 00 02 8b", 1),
        host=CodeFragment("x86-64", 0x8048000, "48 8d 04 11", 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("not_a_register", "rax"),),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "error"
    assert report.checks[0].kind == "execution"
    assert report.checks[0].status == "error"
    assert report.checks[0].reason == "verifier_internal_error"


def test_config_defaults_to_collecting_all_checks() -> None:
    config = VerificationConfig()

    assert config.fail_fast is False
