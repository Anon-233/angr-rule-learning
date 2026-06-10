import logging
import subprocess
import sys

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


def test_verifier_reports_non_empty_preconditions_as_unsupported() -> None:
    result = SemanticVerifier().verify(
        VerificationCandidate(
            candidate_id="preconditioned-add",
            guest=CodeFragment("aarch64", 0x10000, AARCH64_ADD_X0_X1_X2, 1),
            host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_RAX_RCX, 1),
            input_registers=(("x1", "rcx"), ("x2", "rdx")),
            output_registers=(("x0", "rax"),),
            preconditions=("x2 == 0",),
        )
    )

    assert result.status == "unsupported"
    assert result.unsupported_features == ("preconditions",)


def test_execution_suppresses_unavailable_unicorn_engine_noise() -> None:
    logger = logging.getLogger("angr.state_plugins.unicorn_engine")

    assert logger.getEffectiveLevel() >= logging.CRITICAL


def test_importing_verifier_does_not_emit_unicorn_engine_error() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from angr_rule_learning.verification.verifier import SemanticVerifier",
        ],
        capture_output=True,
        check=True,
        text=True,
    )

    assert "unicorn support disabled" not in result.stderr
