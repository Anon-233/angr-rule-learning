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


def test_generalizes_load_memory_address_placeholder() -> None:
    candidate = VerificationCandidate(
        candidate_id="mem-load",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "01020304", 1),
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
    assert rule.guest_lines == ("ldr i32_reg1, [addr64_1]",)
    assert rule.host_lines == ("mov i32_reg1, dword ptr [addr64_1]",)


def test_generalizes_store_memory_address_placeholder() -> None:
    candidate = VerificationCandidate(
        candidate_id="mem-store",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "01020304", 1),
        input_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + 4", "rcx + 4", "write"),),
            accesses=(MemoryAccessExpectation("mem0", "write", 4),),
        ),
    )
    pair = _pair(
        _inst("aarch64", 0x1000, "str", "w0, [x1, #4]"),
        _inst("x86-64", 0x2000, "mov", "dword ptr [rcx + 4], eax"),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _pass(candidate.candidate_id)
    )

    assert rule is not None
    assert rule.guest_lines == ("str i32_reg1, [addr64_1]",)
    assert rule.host_lines == ("mov dword ptr [addr64_1], i32_reg1",)
