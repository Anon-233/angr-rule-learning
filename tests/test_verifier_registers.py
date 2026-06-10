from angr_rule_learning.verification.candidate import (
    CodeFragment,
    VerificationCandidate,
)
from angr_rule_learning.verification.verifier import SemanticVerifier


AARCH64_ADD_X0_X1_X2 = "20 00 02 8b"
X86_64_LEA_RAX_RCX_RDX = "48 8d 04 11"
X86_64_MOV_RAX_RCX = "48 89 c8"


def _candidate(host_hex: str) -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id="add-registers",
        guest=CodeFragment(
            arch="aarch64",
            address=0x10000,
            code_hex=AARCH64_ADD_X0_X1_X2,
            instruction_count=1,
        ),
        host=CodeFragment(
            arch="x86-64",
            address=0x8048000,
            code_hex=host_hex,
            instruction_count=1,
        ),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("x0", "rax"),),
    )


def test_verifier_accepts_equivalent_register_outputs() -> None:
    result = SemanticVerifier().verify(_candidate(X86_64_LEA_RAX_RCX_RDX))

    assert result.status == "pass"
    assert result.equivalent
    assert result.checks[0].kind == "register"
    assert result.checks[0].status == "pass"
    assert result.checks[0].guest == "x0"
    assert result.checks[0].host == "rax"


def test_verifier_rejects_register_mismatch_with_counterexample() -> None:
    result = SemanticVerifier().verify(_candidate(X86_64_MOV_RAX_RCX))

    assert result.status == "fail"
    assert not result.equivalent
    assert result.checks[0].kind == "register"
    assert result.checks[0].status == "fail"
    assert result.checks[0].reason == "register_mismatch"
    assert "x2" in result.checks[0].counterexample
