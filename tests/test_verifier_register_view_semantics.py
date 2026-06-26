"""End-to-end tests for register view semantics through SemanticVerifier.

These tests exercise the real verifier path — lifting, execution, and
relation checking — to prove that ``reg64(i32_regN)`` partial equality
is correctly modelled.
"""

from __future__ import annotations

import claripy

from angr_rule_learning.verification.candidate import (
    CodeFragment,
    VerificationCandidate,
)
from angr_rule_learning.verification.verifier import SemanticVerifier


# ── Machine-code constants ──────────────────────────────────────────────

# add w0, w1, w2   (AArch64, 32-bit)
AARCH64_ADD_W0_W1_W2 = "20 00 02 0b"

# lea eax, [rdi + rsi]   (x86-64, 32-bit destination)
X86_64_LEA_EAX_RDI_RSI = "8d 04 37"

# lea rdi, [rdi + rsi]   (x86-64, 64-bit destination)
X86_64_LEA_RDI_RDI_RSI = "48 8d 3c 37"


# ── Helpers ─────────────────────────────────────────────────────────────


def _candidate(
    guest_hex: str,
    host_hex: str,
    guest_arch: str,
    host_arch: str,
    *,
    inputs: tuple[tuple[str, str], ...] = (),
    outputs: tuple[tuple[str, str], ...] = (),
) -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id="test-regview",
        guest=CodeFragment(
            arch=guest_arch,
            address=0x10000,
            code_hex=guest_hex,
            instruction_count=1,
        ),
        host=CodeFragment(
            arch=host_arch,
            address=0x8048000,
            code_hex=host_hex,
            instruction_count=1,
        ),
        input_registers=inputs,
        output_registers=outputs,
    )


# ── Pass tests ──────────────────────────────────────────────────────────


def test_aarch64_to_x86_64_lea_pass():
    """AArch64 add w0,w1,w2 vs x86-64 lea eax,[rdi+rsi] — pass.

    Semantic 32-bit inputs flow through 64-bit host address registers;
    the verifier must accept this because the low 32 bits match.
    """
    candidate = _candidate(
        AARCH64_ADD_W0_W1_W2,
        X86_64_LEA_EAX_RDI_RSI,
        "aarch64",
        "x86-64",
        inputs=(("w1", "edi"), ("w2", "esi")),
        outputs=(("w0", "eax"),),
    )
    result = SemanticVerifier().verify(candidate)

    assert result.status == "pass", (
        f"expected pass, got {result.status}: {result.checks}"
    )
    assert result.equivalent


def test_x86_64_to_aarch64_lea_pass():
    """x86-64 lea eax,[rdi+rsi] vs AArch64 add w0,w1,w2 — pass.

    Reverse direction: the same semantic surface should verify in
    either translation direction.
    """
    candidate = _candidate(
        X86_64_LEA_EAX_RDI_RSI,
        AARCH64_ADD_W0_W1_W2,
        "x86-64",
        "aarch64",
        inputs=(("edi", "w1"), ("esi", "w2")),
        outputs=(("eax", "w0"),),
    )
    result = SemanticVerifier().verify(candidate)

    assert result.status == "pass", (
        f"expected pass, got {result.status}: {result.checks}"
    )
    assert result.equivalent


# ── High-bit counterexample test ────────────────────────────────────────


def test_64bit_output_diverges_due_to_fresh_high_bits():
    """Guest 32-bit add vs Host 64-bit lea with fresh high bits → fail.

    Guest computes a 32-bit result (w0).  Host computes a 64-bit
    result (rdi) whose upper 32 bits depend on fresh/unconstrained
    values from the widened inputs.  The SMT solver must find a
    counterexample where the zero-extended guest value differs from
    the full 64-bit host value.
    """
    candidate = _candidate(
        AARCH64_ADD_W0_W1_W2,
        X86_64_LEA_RDI_RDI_RSI,
        "aarch64",
        "x86-64",
        inputs=(("w1", "edi"), ("w2", "esi")),
        outputs=(("w0", "rdi"),),
    )
    result = SemanticVerifier().verify(candidate)

    assert result.status == "fail", (
        f"expected fail due to fresh high bits, got {result.status}"
    )
    assert not result.equivalent
    # The counterexample should reference host-side fresh-bit symbols.
    register_checks = [c for c in result.checks if c.kind == "register"]
    assert len(register_checks) == 1
    check = register_checks[0]
    assert check.reason == "register_mismatch"
    # At least one counterexample entry should reference a widened
    # view register (named "..._view_hi").
    ce = check.counterexample
    assert ce, "counterexample must not be empty"
    view_hi_keys = [k for k in ce if "_view_hi" in k]
    assert view_hi_keys, (
        f"counterexample should include fresh high-bit symbols, got keys: {sorted(ce)}"
    )


# ── Initialization-level test ───────────────────────────────────────────


def test_initialize_registers_tracks_fresh_high_bits():
    """_initialize_input_registers returns fresh high-bit symbols.

    When an input register is a sub-register (edi → rdi family), the
    returned symbol map must include the fresh high-bit BVS so that
    counterexamples can reference it.
    """
    from angr_rule_learning.verification.execution import FragmentExecutor

    executor = FragmentExecutor()
    guest_state = executor.make_state(
        CodeFragment("aarch64", 0x1000, AARCH64_ADD_W0_W1_W2, 1)
    )
    host_state = executor.make_state(
        CodeFragment("x86-64", 0x8048000, X86_64_LEA_EAX_RDI_RSI, 1)
    )

    symbols = SemanticVerifier._initialize_input_registers(
        guest_state,
        host_state,
        ((("w1", "edi"), ("w2", "esi"))),
    )

    # The symbols dict should contain the widened fresh high bits.
    view_hi_keys = [k for k in symbols if "_view_hi" in k]
    assert view_hi_keys, f"expected fresh high-bit symbols, got keys: {sorted(symbols)}"
    for key in view_hi_keys:
        sym = symbols[key]
        assert isinstance(sym, claripy.ast.BV)
        assert sym.symbolic
