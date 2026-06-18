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
    assert "ldr i32_reg1, [i64_reg2, i64_reg3, lsl #imm1]" in rule.guest_lines[0]
    assert "mov i32_reg1, dword ptr [i64_reg2 + i64_reg3*imm2]" in rule.host_lines[0]
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
    assert rule.guest_lines == ("stur i32_reg1, [fp64, #-imm1]",)
    assert rule.host_lines == ("mov dword ptr [fp64 - imm1], i32_reg1",)


def test_negative_hex_immediate_shares_same_placeholder_and_leaves_no_residue() -> None:
    window = _pair(
        _inst("aarch64", 0x1000, "ldur", "w0, [x29, #-0xc]"),
        _inst("x86-64", 0x2000, "mov", "eax, dword ptr [rbp - 0xc]"),
    )
    candidate = VerificationCandidate(
        candidate_id="frame-hex-load",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "05060708", 1),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x29 - 12", "rbp - 12", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    report = VerificationReport(
        candidate_id="frame-hex-load",
        status="pass",
        checks=(CheckResult("memory", "pass", "mem0", "mem0"),),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, window, candidate, report)

    assert rule is not None
    guest_line = rule.guest_lines[0]
    host_line = rule.host_lines[0]
    # No "xc" residue from malformed hex match.
    assert "xc" not in guest_line
    assert "xc" not in host_line
    # Guest has negative sign preserved.
    assert "#-imm" in guest_line
    # Both sides share the same immediate placeholder for the displacement.
    assert "imm1" in guest_line
    assert "imm1" in host_line
    assert "fp64" in guest_line
    assert "fp64" in host_line


def test_skips_frame_rule_with_mismatched_displacement_immediates() -> None:
    window = _pair(
        _inst("aarch64", 0x1000, "ldur", "w0, [x29, #-4]"),
        _inst("x86-64", 0x2000, "mov", "esi, dword ptr [rbp - 8]"),
    )
    candidate = VerificationCandidate(
        candidate_id="frame-mismatch-disp",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "05060708", 1),
        output_registers=(("w0", "esi"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x29 - 4", "rbp - 8", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    report = VerificationReport(
        candidate_id="frame-mismatch-disp",
        status="pass",
        checks=(CheckResult("memory", "pass", "mem0", "mem0"),),
    )
    diagnostics = RuleDiagnostics(collect_details=True)

    rule = RuleGeneralizer(diagnostics).generate(1, window, candidate, report)

    assert rule is None
    assert diagnostics.skip_reasons.get("unpaired_host_immediate", 0) >= 1


def test_still_generalizes_frame_rule_with_shared_displacement_immediate() -> None:
    window = _pair(
        _inst("aarch64", 0x1000, "ldur", "w0, [x29, #-4]"),
        _inst("x86-64", 0x2000, "mov", "eax, dword ptr [rbp - 4]"),
    )
    candidate = VerificationCandidate(
        candidate_id="frame-shared-disp",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "05060708", 1),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x29 - 4", "rbp - 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    report = VerificationReport(
        candidate_id="frame-shared-disp",
        status="pass",
        checks=(CheckResult("memory", "pass", "mem0", "mem0"),),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, window, candidate, report)

    assert rule is not None
    guest_line = rule.guest_lines[0]
    host_line = rule.host_lines[0]
    assert "imm1" in guest_line
    assert "imm1" in host_line
    assert "#-imm" in guest_line


def test_generalizes_internal_guest_temporary_for_rmw_memory_window() -> None:
    # 2×1 RMW window: guest needs ldr+add, host does add [mem] in one instruction.
    # Same guest register (w8) appears as both input and output — the real
    # pipeline pattern where eax is both source and dest in add eax, [mem].
    guest_ldr = ExtractedInstruction(
        arch="aarch64",
        address=0x1000,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic="ldr",
        op_str="w9, [x1, #8]",
        function="f",
        source=SourceLocation("sample.c", 1),
        read_registers=("x1",),
        write_registers=("w9",),
    )
    guest_add = ExtractedInstruction(
        arch="aarch64",
        address=0x1004,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic="add",
        op_str="w8, w8, w9",
        function="f",
        source=SourceLocation("sample.c", 1),
        read_registers=("w8", "w9"),
        write_registers=("w8",),
    )
    host_add = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="add",
        op_str="eax, dword ptr [rcx + 8]",
        function="f",
        source=SourceLocation("sample.c", 1),
        read_registers=("eax", "rcx"),
        write_registers=("eax",),
    )
    window = WindowPair(
        "sample:sample.c:1:0",
        (2, 1),
        InstructionWindow("sample:sample.c:1:0", "guest", (guest_ldr, guest_add)),
        InstructionWindow("sample:sample.c:1:0", "host", (host_add,)),
    )
    candidate = VerificationCandidate(
        candidate_id="rmw-temp32",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 2),
        host=CodeFragment("x86-64", 0x2000, "05060708", 1),
        input_registers=(("x1", "rcx"), ("w8", "eax")),
        output_registers=(("w8", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + 8", "rcx + 8", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    report = VerificationReport(
        candidate_id="rmw-temp32",
        status="pass",
        checks=(CheckResult("memory", "pass", "mem0", "mem0"),),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, window, candidate, report)

    assert rule is not None
    assert rule.guest_lines == (
        "ldr tmp1, [i64_reg2, #imm1]",
        "add i32_reg1, i32_reg1, tmp1",
    )
    assert rule.host_lines == ("add i32_reg1, dword ptr [i64_reg2 + imm1]",)


def test_derives_large_immediate_from_bitwise_immediate_construction() -> None:
    """mov + movk → movabs: host 64-bit immediate derived from guest pair."""
    window = WindowPair(
        "sample:sample.c:1:0",
        (2, 1),
        InstructionWindow(
            "sample:sample.c:1:0",
            "guest",
            (
                ExtractedInstruction(
                    arch="aarch64",
                    address=0x1000,
                    size=4,
                    code_bytes=b"\x01\x02\x03\x04",
                    mnemonic="mov",
                    op_str="x0, #0x1234",
                    function="f",
                    source=SourceLocation("sample.c", 1),
                ),
                ExtractedInstruction(
                    arch="aarch64",
                    address=0x1004,
                    size=4,
                    code_bytes=b"\x01\x02\x03\x04",
                    mnemonic="movk",
                    op_str="x0, #0x5678, lsl #48",
                    function="f",
                    source=SourceLocation("sample.c", 1),
                ),
            ),
        ),
        InstructionWindow(
            "sample:sample.c:1:0",
            "host",
            (
                ExtractedInstruction(
                    arch="x86-64",
                    address=0x2000,
                    size=10,
                    code_bytes=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a",
                    mnemonic="movabs",
                    op_str="rax, 0x5678000000001234",
                    function="f",
                    source=SourceLocation("sample.c", 1),
                ),
            ),
        ),
    )
    candidate = VerificationCandidate(
        candidate_id="mov-movk-abs",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 2),
        host=CodeFragment("x86-64", 0x2000, "05060708", 1),
        output_registers=(("x0", "rax"),),
    )
    report = VerificationReport(
        candidate_id="mov-movk-abs",
        status="pass",
        checks=(CheckResult("register", "pass", "x0", "rax"),),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(1, window, candidate, report)

    assert rule is not None
    # Guest: two separate 16-bit immediates, plus parameterised shift.
    assert "imm1" in rule.guest_lines[0]
    assert "imm2" in rule.guest_lines[1]
    assert "lsl #imm3" in rule.guest_lines[1]
    # Host: derived expression uses immN for shift amount.
    assert "imm4" not in rule.host_lines[0]
    expected = "movabs i64_reg1, ${(imm2 << imm3) | imm1}"
    assert rule.host_lines[0] == expected, (
        f"\n  got: {rule.host_lines[0]}\n want: {expected}"
    )
