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
AARCH64_LDR_W0_X1_X2_LSL2 = "207862b8"
X86_64_MOV_EAX_RCX_RDX_SCALE4 = "8b0491"
X86_64_MOV_EAX_RCX_RDX_SCALE8 = "8b04d1"


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
            bindings=(MemoryBinding("mem0", "x1 + 4", "rcx + 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass"


def test_verifier_rejects_inconsistent_binding_vs_instruction() -> None:
    """Binding claims host uses rcx+rdx*4 but instruction only uses [rcx]."""
    candidate = VerificationCandidate(
        candidate_id="inconsistent-binding",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_LDR_W0_X1, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_EAX_RCX_PTR, 1),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx + rdx * 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "fail"
    assert any(
        check.reason == "host_memory_address_mismatch" for check in report.checks
    )


def test_verifier_accepts_equivalent_indexed_load() -> None:
    candidate = VerificationCandidate(
        candidate_id="indexed-load32",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_LDR_W0_X1_X2_LSL2, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_EAX_RCX_RDX_SCALE4, 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + x2 * 4", "rcx + rdx * 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass"


def test_verifier_rejects_wrong_index_scale() -> None:
    candidate = VerificationCandidate(
        candidate_id="indexed-load32-wrong-scale",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_LDR_W0_X1_X2_LSL2, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_EAX_RCX_RDX_SCALE8, 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + x2 * 4", "rcx + rdx * 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "fail"
    assert any(
        check.reason == "host_memory_address_mismatch" for check in report.checks
    )


def test_verifier_rejects_binding_scale_mismatch_under_shared_inputs() -> None:
    """Binding says guest x1+x2*4 but host rcx+rdx*8 with paired inputs.

    Under shared inputs (x1==rcx, x2==rdx) the effective addresses differ
    because the scale factors differ.  The verifier must NOT independently
    compute different base values for x1 and rcx to make both sides hit the
    slot — that would silently pass a semantically wrong pairing.
    """
    candidate = VerificationCandidate(
        candidate_id="indexed-binding-scale-mismatch",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_LDR_W0_X1_X2_LSL2, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_EAX_RCX_RDX_SCALE8, 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(
                MemoryBinding(
                    "mem0",
                    "x1 + x2 * 4",
                    "rcx + rdx * 8",
                    "read",
                ),
            ),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "fail"
    assert any(
        check.reason
        in {
            "guest_memory_address_mismatch",
            "host_memory_address_mismatch",
            "register_mismatch",
        }
        for check in report.checks
    )


AARCH64_ADD_W8_W1_1_STR_W8_X9 = "28040011280100b9"
X86_64_LEA_EAX_ESI_1_MOV_RDI_EAX = "8d46018907"


def test_verifier_rejects_store_with_internally_defined_value_missing_producer_source() -> (
    None
):
    """When a store value is internally defined but the producer's external
    source registers are not included as inputs, the verifier must fail
    because the source registers get independent symbolic values."""
    candidate = VerificationCandidate(
        candidate_id="missing-producer-source",
        guest=CodeFragment("aarch64", 0x1000, AARCH64_ADD_W8_W1_1_STR_W8_X9, 2),
        host=CodeFragment("x86-64", 0x2000, X86_64_LEA_EAX_ESI_1_MOV_RDI_EAX, 2),
        input_registers=(("x9", "rdi"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x9", "rdi", "write"),),
            accesses=(MemoryAccessExpectation("mem0", "write", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "fail"
    assert any(
        check.reason
        in {
            "guest_memory_write_value_mismatch",
            "host_memory_write_value_mismatch",
            "memory_write_value_mismatch",
        }
        for check in report.checks
    )


def test_verifier_accepts_store_with_internally_defined_value_and_producer_source() -> (
    None
):
    """When the producer's external source registers ARE included as inputs,
    the verifier pairs them and both sides compute the same store value."""
    candidate = VerificationCandidate(
        candidate_id="with-producer-source",
        guest=CodeFragment("aarch64", 0x1000, AARCH64_ADD_W8_W1_1_STR_W8_X9, 2),
        host=CodeFragment("x86-64", 0x2000, X86_64_LEA_EAX_ESI_1_MOV_RDI_EAX, 2),
        input_registers=(("x9", "rdi"), ("w1", "esi")),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x9", "rdi", "write"),),
            accesses=(MemoryAccessExpectation("mem0", "write", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass"


def test_verifier_reports_unsupported_for_unparseable_address_expression() -> None:
    """Unsupported address expressions must reach the verifier and return
    unsupported_address_expression, not throw at candidate construction."""
    candidate = VerificationCandidate(
        candidate_id="unparseable-expr",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_LDR_W0_X1, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_EAX_RCX_PTR, 1),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx + rdx * 4 + r8", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "unsupported"
    assert "unsupported_address_expression" in report.unsupported_features


AARCH64_STR_W0_SP12 = "e00f00b9"  # str w0, [sp, #12]
X86_64_MOV_RBP_MINUS4_EDI = "897dfc"  # mov [rbp-4], edi
AARCH64_STR_W0_SP12_STR_W1_SP8 = "e00f00b9e10b00b9"  # str w0,[sp,#12]; str w1,[sp,#8]
X86_64_MOV_RBP_MINUS4_EDI_MOV_RBP_MINUS8_ESI = "897dfc8975f8"
AARCH64_STR_W0_SP12_TWICE = "e00f00b9e00f00b9"
X86_64_MOV_RBP_MINUS4_EDI_TWICE = "897dfc897dfc"


def test_verifier_accepts_frame_relative_store_with_different_base_offsets() -> None:
    candidate = VerificationCandidate(
        candidate_id="frame-store32",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_STR_W0_SP12, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_RBP_MINUS4_EDI, 1),
        input_registers=(("w0", "edi"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "sp + 12", "rbp - 4", "write"),),
            accesses=(MemoryAccessExpectation("mem0", "write", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass"


def test_verifier_accepts_consistent_two_slot_frame_relative_stores() -> None:
    candidate = VerificationCandidate(
        candidate_id="frame-two-store32",
        guest=CodeFragment(
            "aarch64",
            0x10000,
            AARCH64_STR_W0_SP12_TWICE,
            2,
        ),
        host=CodeFragment(
            "x86-64",
            0x8048000,
            X86_64_MOV_RBP_MINUS4_EDI_TWICE,
            2,
        ),
        input_registers=(("w0", "edi"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4), MemorySlot("mem1", 4)),
            bindings=(
                MemoryBinding("mem0", "sp + 12", "rbp - 4", "write"),
                MemoryBinding("mem1", "sp + 12", "rbp - 4", "write"),
            ),
            accesses=(
                MemoryAccessExpectation("mem0", "write", 4),
                MemoryAccessExpectation("mem1", "write", 4),
            ),
            alias=(AliasDeclaration(("mem0", "mem1"), "must_alias"),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass"


def test_verifier_accepts_distinct_two_slot_frame_relative_stores() -> None:
    candidate = VerificationCandidate(
        candidate_id="frame-two-distinct-store32",
        guest=CodeFragment("aarch64", 0x10000, "e00f00b9e10b00b9", 2),
        host=CodeFragment("x86-64", 0x8048000, "897dfc8975f8", 2),
        input_registers=(("w0", "edi"), ("w1", "esi")),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4), MemorySlot("mem1", 4)),
            bindings=(
                MemoryBinding("mem0", "sp + 12", "rbp - 4", "write"),
                MemoryBinding("mem1", "sp + 8", "rbp - 8", "write"),
            ),
            accesses=(
                MemoryAccessExpectation("mem0", "write", 4),
                MemoryAccessExpectation("mem1", "write", 4),
            ),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass"


def test_verifier_rejects_inconsistent_frame_relative_layout() -> None:
    candidate = VerificationCandidate(
        candidate_id="frame-inconsistent-store32",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_STR_W0_SP12_TWICE, 2),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_RBP_MINUS4_EDI_TWICE, 2),
        input_registers=(("w0", "edi"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4), MemorySlot("mem1", 4)),
            bindings=(
                MemoryBinding("mem0", "sp + 12", "rbp - 4", "write"),
                MemoryBinding("mem1", "sp + 12", "rbp - 8", "write"),
            ),
            accesses=(
                MemoryAccessExpectation("mem0", "write", 4),
                MemoryAccessExpectation("mem1", "write", 4),
            ),
            alias=(AliasDeclaration(("mem0", "mem1"), "must_alias"),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status in {"fail", "unsupported"}


# ── semantic-slot matching with real machine code ───────────────────────

# stp x0, x1, [sp, #-0x10]!
_STP_X0_X1_SP_PRE = "e007bfa9"
# push rsi; push rdi
_PUSH_RSI_RDI = "5657"
# ldp x0, x1, [sp], #0x10
_LDP_X0_X1_SP_POST = "e007c1a8"
# pop rsi; pop rdi
_POP_RSI_RDI = "5e5f"


def test_stp_pre_index_push_push_passes_by_slot() -> None:
    """stp x0,x1,[sp,#-0x10]! ↔ push rsi;push rdi.

    After reorder by address: x0@sp-16↔rdi@rsp-16, x1@sp-8↔rsi@rsp-8."""
    candidate = VerificationCandidate(
        candidate_id="stp-push-slot",
        guest=CodeFragment("aarch64", 0x10000, _STP_X0_X1_SP_PRE, 1),
        host=CodeFragment("x86-64", 0x8048000, _PUSH_RSI_RDI, 2),
        input_registers=(("x0", "rdi"), ("x1", "rsi")),
        output_registers=(("sp", "rsp"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 8), MemorySlot("mem1", 8)),
            bindings=(
                MemoryBinding("mem0", "sp - 16", "rsp - 16", "write"),
                MemoryBinding("mem1", "sp - 8", "rsp - 8", "write"),
            ),
            accesses=(
                MemoryAccessExpectation("mem0", "write", 8),
                MemoryAccessExpectation("mem1", "write", 8),
            ),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass", (
        f"unexpected status {report.status}: {report.checks}"
    )


def test_ldp_post_index_pop_pop_passes_by_slot() -> None:
    """ldp x0,x1,[sp],#0x10 ↔ pop rsi;pop rdi.

    After slot-based reorder: x0@sp↔rsi@rsp, x1@sp+8↔rdi@rsp+8."""
    candidate = VerificationCandidate(
        candidate_id="ldp-pop-slot",
        guest=CodeFragment("aarch64", 0x10000, _LDP_X0_X1_SP_POST, 1),
        host=CodeFragment("x86-64", 0x8048000, _POP_RSI_RDI, 2),
        output_registers=(("x0", "rsi"), ("x1", "rdi"), ("sp", "rsp")),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 8), MemorySlot("mem1", 8)),
            bindings=(
                MemoryBinding("mem0", "sp", "rsp", "read"),
                MemoryBinding("mem1", "sp + 8", "rsp + 8", "read"),
            ),
            accesses=(
                MemoryAccessExpectation("mem0", "read", 8),
                MemoryAccessExpectation("mem1", "read", 8),
            ),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass", (
        f"unexpected status {report.status}: {report.checks}"
    )


# ── multi-event memory slot fallback ───────────────────────────────────


def test_multi_slot_stp_push_pass_has_full_coverage() -> None:
    """The 2-slot stp->push test exercises ordered->slot fallback.
    Verifies that all memory checks are present (no partial result)."""
    candidate = VerificationCandidate(
        candidate_id="multi-slot-full-coverage",
        guest=CodeFragment("aarch64", 0x10000, _STP_X0_X1_SP_PRE, 1),
        host=CodeFragment("x86-64", 0x8048000, _PUSH_RSI_RDI, 2),
        input_registers=(("x0", "rdi"), ("x1", "rsi")),
        output_registers=(("sp", "rsp"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 8), MemorySlot("mem1", 8)),
            bindings=(
                MemoryBinding("mem0", "sp - 16", "rsp - 16", "write"),
                MemoryBinding("mem1", "sp - 8", "rsp - 8", "write"),
            ),
            accesses=(
                MemoryAccessExpectation("mem0", "write", 8),
                MemoryAccessExpectation("mem1", "write", 8),
            ),
        ),
    )
    report = SemanticVerifier().verify(candidate)
    assert report.status == "pass"
    mem_checks = [c for c in report.checks if c.kind == "memory"]
    assert len(mem_checks) == 2
    assert all(c.status == "pass" for c in mem_checks)


def _mock_solver_eval(val):
    """Return concrete value so slot matching can evaluate addresses."""
    if hasattr(val, "args") and len(val.args) > 0:
        return val.args[0]
    return 0


class _MockState:
    def __init__(self):
        self.solver = self
        self.constraints = ()

    def eval(self, expr):
        if hasattr(expr, "args") and len(expr.args) > 0:
            return expr.args[0]
        return 0


class _MockSolver:
    def eval(self, expr):
        return _mock_solver_eval(expr)


def test_three_slot_swapped_passes_by_slot_match() -> None:
    """Guest events: mem0, mem1, mem2 in order.
    Host events:  mem0, mem2, mem1 (swapped).
    Ordered: pair 0 matches, pair 1 addr mismatch → slot fallback → 3 pass."""
    import claripy
    from angr_rule_learning.verification.context import CheckContext
    from angr_rule_learning.verification.memory import MemoryEvent, MemoryLayout
    from angr_rule_learning.verification.memory_checks import check_memory_events

    bases = {"mem0": 0x1000, "mem1": 0x2000, "mem2": 0x3000}
    layout = MemoryLayout(bases)
    state = _MockState()

    cand = VerificationCandidate(
        candidate_id="3slot-swap",
        guest=CodeFragment("aarch64", 0x10000, "0000", 1),
        host=CodeFragment("x86-64", 0x20000, "0000", 1),
        memory=MemorySpec(
            slots=(
                MemorySlot("mem0", 8),
                MemorySlot("mem1", 8),
                MemorySlot("mem2", 8),
            ),
            accesses=(
                MemoryAccessExpectation("mem0", "write", 8),
                MemoryAccessExpectation("mem1", "write", 8),
                MemoryAccessExpectation("mem2", "write", 8),
            ),
            bindings=(
                MemoryBinding("mem0", "x0", "rcx", "write"),
                MemoryBinding("mem1", "x1", "rdx", "write"),
                MemoryBinding("mem2", "x2", "r8", "write"),
            ),
        ),
    )
    ctx = CheckContext(
        candidate=cand,
        guest_state=state,
        host_state=state,
        symbols={},
        memory_layout=layout,
        memory_events=(
            # Guest: mem0, mem1, mem2 in order.
            MemoryEvent(
                "guest",
                "write",
                claripy.BVV(0x1000, 64),
                claripy.BVV(1, 64),
                8,
                "Iend_LE",
            ),
            MemoryEvent(
                "guest",
                "write",
                claripy.BVV(0x2000, 64),
                claripy.BVV(2, 64),
                8,
                "Iend_LE",
            ),
            MemoryEvent(
                "guest",
                "write",
                claripy.BVV(0x3000, 64),
                claripy.BVV(3, 64),
                8,
                "Iend_LE",
            ),
            # Host: mem0, mem2, mem1 — swapped.
            MemoryEvent(
                "host",
                "write",
                claripy.BVV(0x1000, 64),
                claripy.BVV(1, 64),
                8,
                "Iend_LE",
            ),
            MemoryEvent(
                "host",
                "write",
                claripy.BVV(0x3000, 64),
                claripy.BVV(3, 64),
                8,
                "Iend_LE",
            ),
            MemoryEvent(
                "host",
                "write",
                claripy.BVV(0x2000, 64),
                claripy.BVV(2, 64),
                8,
                "Iend_LE",
            ),
        ),
    )
    checks = check_memory_events(ctx)
    mem_checks = [c for c in checks if c.kind == "memory"]
    assert len(mem_checks) == 3
    assert all(c.status == "pass" for c in mem_checks)


def test_three_slot_swapped_value_mismatch_fails() -> None:
    """Same setup but host mem1 value changed.  Slot match re-pairs
    correctly but value check on the mismatched slot must fail."""
    import claripy
    from angr_rule_learning.verification.context import CheckContext
    from angr_rule_learning.verification.memory import MemoryEvent, MemoryLayout
    from angr_rule_learning.verification.memory_checks import check_memory_events

    bases = {"mem0": 0x1000, "mem1": 0x2000, "mem2": 0x3000}
    layout = MemoryLayout(bases)
    state = _MockState()

    cand = VerificationCandidate(
        candidate_id="3slot-vmismatch",
        guest=CodeFragment("aarch64", 0x10000, "0000", 1),
        host=CodeFragment("x86-64", 0x20000, "0000", 1),
        memory=MemorySpec(
            slots=(
                MemorySlot("mem0", 8),
                MemorySlot("mem1", 8),
                MemorySlot("mem2", 8),
            ),
            accesses=(
                MemoryAccessExpectation("mem0", "write", 8),
                MemoryAccessExpectation("mem1", "write", 8),
                MemoryAccessExpectation("mem2", "write", 8),
            ),
            bindings=(
                MemoryBinding("mem0", "x0", "rcx", "write"),
                MemoryBinding("mem1", "x1", "rdx", "write"),
                MemoryBinding("mem2", "x2", "r8", "write"),
            ),
        ),
    )
    ctx = CheckContext(
        candidate=cand,
        guest_state=state,
        host_state=state,
        symbols={},
        memory_layout=layout,
        memory_events=(
            MemoryEvent(
                "guest",
                "write",
                claripy.BVV(0x1000, 64),
                claripy.BVV(1, 64),
                8,
                "Iend_LE",
            ),
            MemoryEvent(
                "guest",
                "write",
                claripy.BVV(0x2000, 64),
                claripy.BVV(2, 64),
                8,
                "Iend_LE",
            ),
            MemoryEvent(
                "guest",
                "write",
                claripy.BVV(0x3000, 64),
                claripy.BVV(3, 64),
                8,
                "Iend_LE",
            ),
            MemoryEvent(
                "host",
                "write",
                claripy.BVV(0x1000, 64),
                claripy.BVV(1, 64),
                8,
                "Iend_LE",
            ),
            MemoryEvent(
                "host",
                "write",
                claripy.BVV(0x3000, 64),
                claripy.BVV(3, 64),
                8,
                "Iend_LE",
            ),
            # Host mem1 has wrong value (999 instead of 2).
            MemoryEvent(
                "host",
                "write",
                claripy.BVV(0x2000, 64),
                claripy.BVV(999, 64),
                8,
                "Iend_LE",
            ),
        ),
    )
    checks = check_memory_events(ctx)
    assert any(
        c.reason == "memory_write_value_mismatch" and c.status == "fail" for c in checks
    )
