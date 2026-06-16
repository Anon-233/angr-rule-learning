from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    SourceLocation,
    WindowPair,
)
from angr_rule_learning.rules.generalize import RuleDiagnostics, RuleGeneralizer
from angr_rule_learning.verification.candidate import (
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)
from angr_rule_learning.verification.report import CheckResult, VerificationReport


def _inst(arch: str, address: int, mnemonic: str, op_str: str) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic=mnemonic,
        op_str=op_str,
        function="sample",
        source=SourceLocation("sample.c", 1),
    )


def _pair(guest: ExtractedInstruction, host: ExtractedInstruction) -> WindowPair:
    return WindowPair(
        "sample:sample.c:1:0",
        (1, 1),
        InstructionWindow("sample:sample.c:1:0", "guest", (guest,)),
        InstructionWindow("sample:sample.c:1:0", "host", (host,)),
    )


def _pass(candidate_id: str) -> VerificationReport:
    return VerificationReport(
        candidate_id,
        "pass",
        checks=(CheckResult("memory", "pass", "mem0", "mem0"),),
    )


def test_generalizes_load_memory_registers_without_addr_placeholder() -> None:
    candidate = VerificationCandidate(
        candidate_id="mem-load",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "01020304", 1),
        input_registers=(("x1", "rcx"),),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    pair = _pair(
        _inst("aarch64", 0x1000, "ldr", "w0, [x1]"),
        _inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx]"),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _pass(candidate.candidate_id)
    )

    assert rule is not None
    assert rule.guest_lines == ("ldr i32_reg1, [i64_reg2]",)
    assert rule.host_lines == ("mov i32_reg1, dword ptr [i64_reg2]",)


def test_generalizes_memory_displacement_with_shared_immediate() -> None:
    candidate = VerificationCandidate(
        candidate_id="mem-load-disp",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "01020304", 1),
        input_registers=(("x1", "rcx"),),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + 8", "rcx + 8", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    pair = _pair(
        _inst("aarch64", 0x1000, "ldr", "w0, [x1, #8]"),
        _inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx + 8]"),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _pass(candidate.candidate_id)
    )

    assert rule is not None
    assert rule.guest_lines == ("ldr i32_reg1, [i64_reg2, #imm1]",)
    assert rule.host_lines == ("mov i32_reg1, dword ptr [i64_reg2 + imm1]",)


def test_generalizes_indexed_memory_keeps_scale_literals() -> None:
    candidate = VerificationCandidate(
        candidate_id="mem-load-indexed",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "01020304", 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + x2 * 4", "rcx + rdx * 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    pair = _pair(
        _inst("aarch64", 0x1000, "ldr", "w0, [x1, x2, lsl #2]"),
        _inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx + rdx*4]"),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _pass(candidate.candidate_id)
    )

    assert rule is not None
    assert rule.guest_lines == ("ldr i32_reg1, [i64_reg2, i64_reg3, lsl #2]",)
    assert rule.host_lines == ("mov i32_reg1, dword ptr [i64_reg2 + i64_reg3*4]",)
    assert "addr64" not in "\n".join(rule.guest_lines + rule.host_lines)


def test_generalizes_frame_relative_memory_registers_from_bindings() -> None:
    window = _pair(
        _inst("aarch64", 0x1000, "stur", "w0, [x29, #-4]"),
        _inst("x86-64", 0x2000, "mov", "dword ptr [rbp - 4], eax"),
    )
    candidate = VerificationCandidate(
        candidate_id="frame-memory-store",
        guest=CodeFragment("aarch64", 0x1000, "a8c31fb8", 1),
        host=CodeFragment("x86-64", 0x2000, "8945fc", 1),
        input_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x29 - 4", "rbp - 4", "write"),),
            accesses=(MemoryAccessExpectation("mem0", "write", 4),),
        ),
    )
    report = VerificationReport(
        candidate_id="frame-memory-store",
        status="pass",
        checks=(CheckResult("memory", "pass", "mem0", "mem0"),),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, window, candidate, report)

    assert rule is not None
    assert "fp64" in rule.guest_lines[0]
    assert "fp64" in rule.host_lines[0]
    assert "i32_reg1" in rule.guest_lines[0]
    assert "i32_reg1" in rule.host_lines[0]
