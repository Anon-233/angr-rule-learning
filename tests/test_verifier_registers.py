from angr_rule_learning.models import CodeFragment, VerificationRequest
from angr_rule_learning.verifier import AngrSemanticVerifier


AARCH64_ADD_X0_X1_X2 = "20 00 02 8b"
X86_64_LEA_RAX_RCX_RDX = "48 8d 04 11"
X86_64_MOV_RAX_RCX = "48 89 c8"


def _request(host_hex: str) -> VerificationRequest:
    return VerificationRequest(
        guest=CodeFragment(
            arch="aarch64",
            address=0x10000,
            code_hex=AARCH64_ADD_X0_X1_X2,
            instruction_count=1,
            def_regs=("x0",),
        ),
        host=CodeFragment(
            arch="x86-64",
            address=0x8048000,
            code_hex=host_hex,
            instruction_count=1,
            def_regs=("rax",),
        ),
        init_map=(("x1", "rcx"), ("x2", "rdx")),
    )


def test_verifier_accepts_equivalent_register_outputs() -> None:
    result = AngrSemanticVerifier().verify(_request(X86_64_LEA_RAX_RCX_RDX))

    assert result.equivalent
    assert result.register_checks[0].status == "pass"
    assert result.register_checks[0].guest_reg == "x0"
    assert result.register_checks[0].host_reg == "rax"


def test_verifier_rejects_register_counterexample() -> None:
    result = AngrSemanticVerifier().verify(_request(X86_64_MOV_RAX_RCX))

    assert not result.equivalent
    assert result.register_checks[0].status == "fail"
    assert "x2" in result.counterexample
