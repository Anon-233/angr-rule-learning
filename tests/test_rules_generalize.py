import pytest

from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    SourceLocation,
    WindowPair,
)
from angr_rule_learning.rules.ast import (
    GuestRegViewOp,
    ImmOp,
    Instruction,
    LitOp,
    MetaOp,
    RegOp,
    RegTextOp,
)
from angr_rule_learning.rules.generalize import (
    _annotate_dead_writes,
    _build_placeholder_map,
    _verify_host_registers_bound,
    _verify_fixed_role_sources_in_ast,
    _writer_covers_consumer,
    GeneratedRule,
    RuleDiagnostics,
    RuleGeneralizer,
    _RuleSkip,
    _generalize_instructions_with_roles,
    _instructions_to_ast,
    _replace_immediates_ast,
    _validate_no_remaining_registers,
    consolidate_rules,
)
from angr_rule_learning.verification.candidate import (
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)
from angr_rule_learning.verification.report import CheckResult, VerificationReport


def test_immop_neg_serializes_as_hash_minus_imm() -> None:
    assert ImmOp(id=1, neg=True, aarch64_hash=True).to_text() == "#-imm1"
    assert ImmOp(id=2, neg=True, aarch64_hash=False).to_text() == "-imm2"
    assert ImmOp(id=3, neg=False, aarch64_hash=True).to_text() == "#imm3"


def test_reverse_immediate_syntax_follows_each_architecture() -> None:
    guest, host = _replace_immediates_ast(
        (Instruction("add", (LitOp("eax"), LitOp("7"))),),
        "x86-64",
        (Instruction("add", (LitOp("w0"), LitOp("w0"), LitOp("#7"))),),
        "aarch64",
    )

    assert guest[0].to_text() == "add eax, imm1"
    assert host[0].to_text() == "add w0, w0, #imm1"


def test_writer_coverage_uses_explicit_architecture() -> None:
    assert _writer_covers_consumer("x86-64", "ecx", "cl")
    assert not _writer_covers_consumer("x86-64", "ch", "cl")
    assert _writer_covers_consumer("aarch64", "x1", "w1")


def test_guest_fixed_role_is_detected_with_guest_architecture() -> None:
    candidate = VerificationCandidate(
        candidate_id="reverse-fixed-role",
        guest=CodeFragment("x86-64", 0x1000, "0102", 1),
        host=CodeFragment("aarch64", 0x2000, "01020304", 1),
        input_registers=(("cl", "w1"),),
    )

    with pytest.raises(_RuleSkip) as excinfo:
        _build_placeholder_map(candidate, "x86-64", "aarch64")

    assert excinfo.value.reason == "unsupported_rule_shape"


def test_host_fixed_role_cannot_be_used_as_input_mapping() -> None:
    candidate = VerificationCandidate(
        candidate_id="host-fixed-role-input",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "0102", 1),
        input_registers=(("w1", "cl"),),
    )

    with pytest.raises(_RuleSkip) as excinfo:
        _build_placeholder_map(candidate, "aarch64", "x86-64")

    assert excinfo.value.reason == "unsupported_rule_shape"


def test_guest_fixed_role_view_source_is_emitted_for_reverse_shift() -> None:
    pair = _window_pair(
        (
            _inst(
                "x86-64",
                0x1000,
                "shl",
                "eax, cl",
                write_registers=("eax", "rflags"),
                read_registers=("eax", "cl"),
            ),
        ),
        (
            _inst(
                "aarch64",
                0x2000,
                "lsl",
                "w0, w0, w1",
                write_registers=("w0",),
                read_registers=("w0", "w1"),
            ),
        ),
    )
    candidate = VerificationCandidate(
        candidate_id="guest-fixed-role-view-shift",
        guest=CodeFragment("x86-64", 0x1000, "d3 e0", 1),
        host=CodeFragment("aarch64", 0x2000, "00000000", 1),
        input_registers=(("eax", "w0"), ("ecx", "w1")),
        output_registers=(("eax", "w0"),),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _passing_report(candidate.candidate_id)
    )

    assert rule is not None
    assert rule.guest_lines == ("shl i32_reg1, cl",)
    assert rule.host_lines == ("lsl i32_reg1, i32_reg1, lo8(guest.rcx)",)


def test_reverse_fixed_role_shift_keeps_ecx_literal_producer() -> None:
    pair = _window_pair(
        (
            _inst(
                "x86-64",
                0x1000,
                "mov",
                "ecx, edx",
                write_registers=("ecx",),
                read_registers=("edx",),
            ),
            _inst(
                "x86-64",
                0x1002,
                "mov",
                "eax, esi",
                write_registers=("eax",),
                read_registers=("esi",),
            ),
            _inst(
                "x86-64",
                0x1004,
                "shl",
                "eax, cl",
                write_registers=("eax", "rflags"),
                read_registers=("eax", "cl"),
            ),
        ),
        (
            _inst(
                "aarch64",
                0x2000,
                "lsl",
                "w0, w1, w2",
                write_registers=("w0",),
                read_registers=("w1", "w2"),
            ),
        ),
    )
    candidate = VerificationCandidate(
        candidate_id="reverse-fixed-role-shift",
        guest=CodeFragment("x86-64", 0x1000, "89 d1 89 f0 d3 e0", 3),
        host=CodeFragment("aarch64", 0x2000, "2000221a", 1),
        input_registers=(("esi", "w1"), ("edx", "w2")),
        output_registers=(("eax", "w0"),),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _passing_report(candidate.candidate_id)
    )

    assert rule is not None
    assert rule.guest_lines == (
        "mov ecx, i32_reg3",
        "mov i32_reg1, i32_reg2",
        "shl i32_reg1, cl",
    )
    assert rule.host_lines == ("lsl i32_reg1, i32_reg2, i32_reg3",)
    assert "i32_tmp" not in "\n".join((*rule.guest_lines, *rule.host_lines))


def _inst(
    arch: str,
    address: int,
    mnemonic: str,
    op_str: str,
    code_hex: str = "01020304",
    write_registers: tuple[str, ...] = (),
    read_registers: tuple[str, ...] = (),
) -> ExtractedInstruction:
    code = bytes.fromhex(code_hex)
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=len(code),
        code_bytes=code,
        mnemonic=mnemonic,
        op_str=op_str,
        function="sample",
        source=SourceLocation("sample.c", 1),
        write_registers=write_registers,
        read_registers=read_registers,
    )


def _window_pair(
    guest_instructions: tuple[ExtractedInstruction, ...],
    host_instructions: tuple[ExtractedInstruction, ...],
) -> WindowPair:
    return WindowPair(
        region_id="sample:sample.c:1:0",
        stage=(len(guest_instructions), len(host_instructions)),
        guest=InstructionWindow("sample:sample.c:1:0", "guest", guest_instructions),
        host=InstructionWindow("sample:sample.c:1:0", "host", host_instructions),
    )


def _candidate(
    *,
    inputs: tuple[tuple[str, str], ...] = (),
    outputs: tuple[tuple[str, str], ...] = (),
) -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id="sample:sample.c:1:0:g0:h0",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "010203", 1),
        input_registers=inputs,
        output_registers=outputs,
    )


def _passing_report(
    candidate_id: str = "sample:sample.c:1:0:g0:h0",
) -> VerificationReport:
    return VerificationReport(
        candidate_id,
        "pass",
        checks=(CheckResult("register", "pass", "w8", "eax"),),
    )


def test_generalizes_output_register_before_input_registers() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "add", "w8, w0, w1"),),
        (_inst("x86-64", 0x2000, "lea", "eax, [edi + esi]"),),
    )
    candidate = _candidate(
        inputs=(("w0", "edi"), ("w1", "esi")), outputs=(("w8", "eax"),)
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is not None
    assert rule.rule_id == 1
    assert rule.candidate_id == candidate.candidate_id
    assert rule.guest_lines == ("add i32_reg1, i32_reg2, i32_reg3",)
    assert rule.host_lines == ("lea i32_reg1, [i32_reg2 + i32_reg3]",)
    assert diagnostics.to_json()["rules_emitted"] == 1


def test_generalizes_multi_instruction_windows() -> None:
    pair = _window_pair(
        (
            _inst("aarch64", 0x1000, "mov", "w8, w0"),
            _inst("aarch64", 0x1004, "add", "w8, w8, #1"),
        ),
        (
            _inst("x86-64", 0x2000, "mov", "eax, edi"),
            _inst("x86-64", 0x2003, "add", "eax, 1"),
        ),
    )
    candidate = _candidate(inputs=(("w0", "edi"),), outputs=(("w8", "eax"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is not None
    assert rule.guest_lines == (
        "mov i32_reg1, i32_reg2",
        "add i32_reg1, i32_reg1, #imm1",
    )
    assert rule.host_lines == ("mov i32_reg1, i32_reg2", "add i32_reg1, imm1")


def test_replacement_is_token_aware() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "add", "x10, x1, x10"),),
        (_inst("x86-64", 0x2000, "add", "r10, rcx"),),
    )
    candidate = _candidate(inputs=(("x1", "rcx"),), outputs=(("x10", "r10"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is not None
    assert rule.guest_lines == ("add i64_reg1, i64_reg2, i64_reg1",)
    assert rule.host_lines == ("add i64_reg1, i64_reg2",)


def test_allowed_zero_register_literals_may_remain() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "orr", "w8, wzr, w0"),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("w0", "edi"),), outputs=(("w8", "eax"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is not None
    assert rule.guest_lines == ("orr i32_reg1, wzr, i32_reg2",)


def test_skips_mismatched_register_classes() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "mov", "x8, x0"),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("x0", "edi"),), outputs=(("x8", "eax"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is None
    assert diagnostics.to_json()["skip_reasons"] == {"register_class_mismatch": 1}


def test_skips_unknown_register_classes() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "mov", "badreg, w0"),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("w0", "edi"),), outputs=(("badreg", "eax"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is None
    assert diagnostics.to_json()["skip_reasons"] == {"unknown_register_class": 1}


def test_skips_unmapped_physical_registers_left_in_assembly() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "add", "w8, w0, w2"),),
        (_inst("x86-64", 0x2000, "add", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("w0", "edi"),), outputs=(("w8", "eax"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is None
    assert diagnostics.to_json()["skip_reasons"] == {"unmapped_register_surface": 1}


def test_nonpassing_reports_are_not_considered_for_rule_output() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "mov", "w8, w0"),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("w0", "edi"),), outputs=(("w8", "eax"),))
    diagnostics = RuleDiagnostics()
    report = VerificationReport(
        candidate.candidate_id,
        "fail",
        checks=(
            CheckResult(
                "register",
                "fail",
                "w8",
                "eax",
                reason="register_mismatch",
            ),
        ),
    )

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, report)

    assert rule is None
    assert diagnostics.to_json() == {
        "rules_considered": 0,
        "rules_emitted": 0,
        "rules_skipped": 0,
        "rules_subsumed": 0,
        "skip_reasons": {},
    }


def test_generalizer_uses_candidate_arch_not_hardcoded_defaults() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "add", "w8, w0, w1"),),
        (_inst("x86-64", 0x2000, "lea", "eax, [edi + esi]"),),
    )
    candidate = VerificationCandidate(
        candidate_id="sample:sample.c:1:0:g0:h0",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("amd64", 0x2000, "010203", 1),
        input_registers=(("w0", "edi"), ("w1", "esi")),
        output_registers=(("w8", "eax"),),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is not None
    assert "i32_reg" in rule.guest_lines[0]
    assert "i32_reg" in rule.host_lines[0]
    assert diagnostics.to_json()["rules_emitted"] == 1


def test_generalizer_allows_two_address_input_output_pair() -> None:
    diagnostics = RuleDiagnostics()
    generalizer = RuleGeneralizer(diagnostics)
    window = _window_pair(
        (_inst("aarch64", 0x1000, "add", "w8, w0, w8"),),
        (_inst("x86-64", 0x2000, "add", "eax, ecx"),),
    )
    candidate = _candidate(
        inputs=(("w8", "eax"), ("w0", "ecx")),
        outputs=(("w8", "eax"),),
    )
    report = _passing_report(candidate.candidate_id)

    rule = generalizer.generate(1, window, candidate, report)

    assert rule is not None
    assert rule.guest_lines == ("add i32_reg1, i32_reg2, i32_reg1",)
    assert rule.host_lines == ("add i32_reg1, i32_reg2",)
    assert diagnostics.rules_emitted == 1


def test_rule_diagnostics_omits_details_by_default() -> None:
    diagnostics = RuleDiagnostics()
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "mov", "x8, x0"),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("x0", "edi"),), outputs=(("x8", "eax"),))

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is None
    payload = diagnostics.to_json()
    assert payload["skip_reasons"] == {"register_class_mismatch": 1}
    assert "skipped_rules" not in payload


def test_rule_diagnostics_records_detailed_skip_when_enabled() -> None:
    diagnostics = RuleDiagnostics(collect_details=True)
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "mov", "x8, x0"),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("x0", "edi"),), outputs=(("x8", "eax"),))

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is None
    payload = diagnostics.to_json(include_details=True)
    assert payload["skip_reasons"] == {"register_class_mismatch": 1}
    assert payload["skipped_rules"] == [
        {
            "candidate_id": candidate.candidate_id,
            "reason": "register_class_mismatch",
            "guest_lines": ["mov x8, x0"],
            "host_lines": ["mov eax, edi"],
            "input_registers": [["x0", "edi"]],
            "output_registers": [["x8", "eax"]],
            "memory_bindings": [],
        }
    ]


def test_generalizer_coalesces_host_pre_and_post_carriers_by_guest_family() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "add", "w0, w1, w0"),),
        (_inst("x86-64", 0x2000, "lea", "eax, [edi + esi]"),),
    )
    candidate = _candidate(
        inputs=(("w0", "edi"), ("w1", "esi")),
        outputs=(("w0", "eax"),),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is not None
    assert rule.guest_lines == ("add i32_reg1, i32_reg2, i32_reg3",)
    assert rule.host_lines == ("lea i32_reg1, [i32_reg3 + i32_reg2]",)


def test_generalizer_role_split_prevents_coalescing_distinct_guest_regs() -> None:
    """When a guest register (w8) appears in both output and input pairs
    with *different* host registers (eax for output, ecx for input),
    the input role gets a separate placeholder so the distinct guest
    source operand (w0, paired with eax) can safely share the output's
    placeholder without conflating w8's two roles.

    Host-side role-split detection also gives w0 its own placeholder
    because host "eax" is shared between output and input pairs, which
    prevents accidental aliasing through register-view resolution."""
    diagnostics = RuleDiagnostics()
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "add", "w8, w0, w8"),),
        (_inst("x86-64", 0x2000, "add", "eax, ecx"),),
    )
    candidate = _candidate(
        inputs=(("w0", "eax"), ("w8", "ecx")),
        outputs=(("w8", "eax"),),
    )

    rule = RuleGeneralizer(diagnostics).generate(
        1,
        pair,
        candidate,
        _passing_report(candidate.candidate_id),
    )

    assert rule is not None
    # w0 gets its own placeholder (i32_reg2) because host "eax" is
    # shared across output and input pairs — side-symmetric role split.
    assert rule.guest_lines == ("add i32_reg1, i32_reg2, i32_reg3",)
    assert rule.host_lines == ("add i32_reg1, i32_reg3",)


def test_generalizer_uses_stack_pointer_placeholder_without_reg_suffix() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "sub", "sp, sp, #16"),),
        (_inst("x86-64", 0x2000, "sub", "rsp, 16"),),
    )
    candidate = _candidate(
        inputs=(("sp", "rsp"),),
        outputs=(("sp", "rsp"),),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1,
        pair,
        candidate,
        _passing_report(candidate.candidate_id),
    )

    assert rule is not None
    assert rule.guest_lines == ("sub sp64, sp64, #imm1",)
    assert rule.host_lines == ("sub sp64, imm1",)


def test_generalizer_handles_input_reusing_output_host_register() -> None:
    """When a guest input register maps to a host register that already
    has a placeholder from an output pair, the side-symmetric role-split
    detection gives the input guest its own placeholder so that
    register-view resolution cannot accidentally alias an output
    placeholder into an address view."""
    diagnostics = RuleDiagnostics()
    generalizer = RuleGeneralizer(diagnostics)
    window = _window_pair(
        (_inst("aarch64", 0x1000, "add", "w8, w0, w8"),),
        (_inst("x86-64", 0x2000, "add", "eax, ecx"),),
    )
    candidate = _candidate(
        inputs=(("w0", "eax"), ("w8", "ecx")),
        outputs=(("w8", "eax"),),
    )
    report = _passing_report(candidate.candidate_id)

    rule = generalizer.generate(1, window, candidate, report)
    assert rule is not None
    # w0 gets i32_reg2; w8 write gets i32_reg1; w8 read gets i32_reg3
    # (from guest-side role split).
    assert rule.guest_lines == ("add i32_reg1, i32_reg2, i32_reg3",)
    assert rule.host_lines == ("add i32_reg1, i32_reg3",)


def test_splits_guest_register_when_output_and_input_pair_differently() -> None:
    """When w0 appears as both output (paired with eax) and input (paired with
    edi), the two roles must get different placeholders so the host's explicit
    ``mov eax, edi`` is preserved."""
    guest_sub = ExtractedInstruction(
        arch="aarch64",
        address=0x1000,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic="sub",
        op_str="w0, w0, w1",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("w0",),
        read_registers=("w0", "w1"),
    )
    host_mov = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="eax, edi",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("eax",),
        read_registers=("edi",),
    )
    host_sub = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="sub",
        op_str="eax, esi",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("eax",),
        read_registers=("eax", "esi"),
    )
    window = WindowPair(
        "sample:sample.c:1:0",
        (1, 2),
        InstructionWindow("sample:sample.c:1:0", "guest", (guest_sub,)),
        InstructionWindow("sample:sample.c:1:0", "host", (host_mov, host_sub)),
    )
    candidate = VerificationCandidate(
        candidate_id="sample:sample.c:1:0:g0:h0",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "010203010203", 2),
        input_registers=(("w0", "edi"), ("w1", "esi")),
        output_registers=(("w0", "eax"),),
    )
    report = VerificationReport(
        candidate_id="sample:sample.c:1:0:g0:h0",
        status="pass",
        checks=(CheckResult("register", "pass", "w0", "eax"),),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(1, window, candidate, report)

    assert rule is not None
    # w0-as-output → i32_reg1; w0-as-input → i32_reg3; w1 → i32_reg2.
    assert rule.guest_lines == ("sub i32_reg1, i32_reg3, i32_reg2",)
    assert rule.host_lines == (
        "mov i32_reg1, i32_reg3",
        "sub i32_reg1, i32_reg2",
    )


def test_derives_tbz_mask_from_bit_position_shift() -> None:
    """tbz #3 → host ``and reg, 8``: mask = 1 << 3 expressed via derivation."""
    guest_tbz = ExtractedInstruction(
        arch="aarch64",
        address=0x1000,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic="tbz",
        op_str="w0, #3, #0x14",
        function="f",
        source=SourceLocation("sample.c", 1),
        read_registers=("w0",),
    )
    host_and = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="and",
        op_str="eax, 8",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("eax",),
        read_registers=("eax",),
    )
    host_cmp = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="cmp",
        op_str="eax, 0",
        function="f",
        source=SourceLocation("sample.c", 1),
        read_registers=("eax",),
    )
    host_je = ExtractedInstruction(
        arch="x86-64",
        address=0x2006,
        size=2,
        code_bytes=b"\x01\x02",
        mnemonic="je",
        op_str="0x14",
        function="f",
        source=SourceLocation("sample.c", 1),
    )
    window = WindowPair(
        "sample:sample.c:1:0",
        (1, 3),
        InstructionWindow("sample:sample.c:1:0", "guest", (guest_tbz,)),
        InstructionWindow("sample:sample.c:1:0", "host", (host_and, host_cmp, host_je)),
    )
    candidate = VerificationCandidate(
        candidate_id="sample:sample.c:1:0:g0:h0",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "0102030102030102", 3),
        input_registers=(("w0", "eax"),),
    )
    report = VerificationReport(
        candidate_id="sample:sample.c:1:0:g0:h0",
        status="pass",
        checks=(CheckResult("register", "pass", "w0", "eax"),),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(1, window, candidate, report)

    assert rule is not None
    # Non-zero bit position is parameterised.
    assert "#imm1" in rule.guest_lines[0]
    # Host mask derived from bit position.
    host_text = " ".join(rule.host_lines)
    assert "${(1 << imm1)}" in host_text


def test_consolidate_removes_literal_rule_subsumed_by_param_rule() -> None:
    literal_rule = GeneratedRule.from_text_lines(
        rule_id=1,
        candidate_id="a",
        guest_lines=("tbz i32_reg1, #0, #label1",),
        host_lines=("and i32_reg1, ${(1 << 0)}", "cmp i32_reg1, 0", "je label1"),
    )
    param_rule = GeneratedRule.from_text_lines(
        rule_id=2,
        candidate_id="b",
        guest_lines=("tbz i32_reg1, #imm1, #label1",),
        host_lines=("and i32_reg1, ${(1 << imm1)}", "cmp i32_reg1, 0", "je label1"),
    )

    result = consolidate_rules([literal_rule, param_rule])

    assert result == [param_rule]


def test_instructions_to_ast_produces_correct_operands() -> None:
    inst = _inst("aarch64", 0x1000, "ldr", "w0, [x1]")
    result = _instructions_to_ast((inst,))

    assert len(result) == 1
    parsed = result[0]
    assert isinstance(parsed, Instruction)
    assert parsed.mnemonic == "ldr"
    assert len(parsed.operands) == 2
    assert isinstance(parsed.operands[0], LitOp)
    assert parsed.operands[0].value == "w0"
    assert isinstance(parsed.operands[1], LitOp)
    assert parsed.operands[1].value == "[x1]"


def test_validate_remaining_registers_raises() -> None:
    inst = Instruction(mnemonic="mov", operands=(RegTextOp("x0"), RegTextOp("x1")))
    try:
        _validate_no_remaining_registers((inst,), "aarch64")
    except _RuleSkip as exc:
        assert exc.reason == "unmapped_register_surface"
    else:
        raise AssertionError("Expected _RuleSkip was not raised")


def test_validate_detects_concrete_register_in_brackets() -> None:
    """LitOp('[x1]') with 'x1' as known aarch64 register must raise _RuleSkip."""
    inst = Instruction("ldr", (LitOp("i32_reg1"), LitOp("[x1]")))
    with pytest.raises(_RuleSkip, match="unmapped_register_surface"):
        _validate_no_remaining_registers((inst,), "aarch64")


def test_validate_detects_concrete_register_in_complex_x86_address() -> None:
    """LitOp('[rcx + rdx*4]') with rcx/rdx known must raise."""
    inst = Instruction("mov", (LitOp("i32_reg1"), LitOp("[rcx + rdx*4]")))
    with pytest.raises(_RuleSkip, match="unmapped_register_surface"):
        _validate_no_remaining_registers((inst,), "x86-64")


def test_validate_allows_parameterized_operand() -> None:
    """LitOp('[i64_reg2]') must NOT raise."""
    inst = Instruction("ldr", (LitOp("i32_reg1"), LitOp("[i64_reg2]")))
    _validate_no_remaining_registers((inst,), "aarch64")  # no exception


def test_validate_allows_sp_in_brackets() -> None:
    """LitOp('[sp, #16]') with sp as allowed literal must NOT raise."""
    inst = Instruction("ldr", (LitOp("i32_reg1"), LitOp("[sp, #16]")))
    _validate_no_remaining_registers((inst,), "aarch64")  # no exception


def test_validate_allows_parameterized_memory_with_kw() -> None:
    """LitOp('dword ptr [i64_reg1 + i64_reg2*4]') must NOT raise."""
    inst = Instruction(
        "mov",
        (LitOp("i32_reg1"), LitOp("dword ptr [i64_reg1 + i64_reg2*4]")),
    )
    _validate_no_remaining_registers((inst,), "x86-64")  # no exception


def test_generalize_ast_replaces_registers() -> None:
    """AST generalization replaces LitOp operands with RegOp placeholders."""
    inst = Instruction(mnemonic="add", operands=(LitOp("w8"), LitOp("w0"), LitOp("w1")))
    mapping = {"w8": "i32_reg1", "w0": "i32_reg2", "w1": "i32_reg3"}
    extracted = (_inst("aarch64", 0x1000, "add", "w8, w0, w1"),)
    result = _generalize_instructions_with_roles(
        (inst,), extracted, mapping, {}, "aarch64", side="guest"
    )
    assert len(result) == 1
    ops = result[0].operands
    assert ops == (RegOp("i32", 32, 1), RegOp("i32", 32, 2), RegOp("i32", 32, 3))


def test_generalize_ast_role_split() -> None:
    """AST generalization applies role_split so write/read of same reg get
    different placeholders."""
    inst = Instruction(mnemonic="sub", operands=(LitOp("w0"), LitOp("w0"), LitOp("w1")))
    mapping = {"w1": "i32_reg2"}
    role_split = {("guest", "w0"): ("i32_reg1", "i32_reg3")}
    extracted = (
        _inst(
            "aarch64",
            0x1000,
            "sub",
            "w0, w0, w1",
            write_registers=("w0",),
            read_registers=("w0", "w1"),
        ),
    )
    result = _generalize_instructions_with_roles(
        (inst,), extracted, mapping, role_split, "aarch64", side="guest"
    )
    assert len(result) == 1
    ops = result[0].operands
    assert ops == (RegOp("i32", 32, 1), RegOp("i32", 32, 3), RegOp("i32", 32, 2))


def test_generalize_ast_ignores_role_split_for_other_side() -> None:
    """A host-side role split must not rewrite a same-named guest register."""
    inst = Instruction(mnemonic="mov", operands=(LitOp("eax"), LitOp("edi")))
    mapping = {"eax": "i32_reg1", "edi": "i32_reg2"}
    role_split = {("host", "eax"): ("i32_reg9", "i32_reg10")}
    extracted = (
        _inst(
            "x86-64",
            0x1000,
            "mov",
            "eax, edi",
            write_registers=("eax",),
            read_registers=("edi",),
        ),
    )

    result = _generalize_instructions_with_roles(
        (inst,), extracted, mapping, role_split, "x86-64", side="guest"
    )

    assert len(result) == 1
    assert result[0].operands == (RegOp("i32", 32, 1), RegOp("i32", 32, 2))


def test_dead_write_produces_meta_ops() -> None:
    inst = Instruction("mov", (RegOp("i32", 32, 1), RegOp("i32", 32, 2)))
    inst_with_save = Instruction(
        "mov",
        inst.operands,
        meta=(MetaOp(kind="save", regs=(RegOp("i32", 32, 1),)),),
    )
    assert inst_with_save.meta[0].kind == "save"
    assert inst_with_save.meta[0].regs == (RegOp("i32", 32, 1),)
    assert "save i32_reg1" in inst_with_save.to_text()


def test_dead_write_save_restore_is_not_emitted_on_guest_side() -> None:
    window = _window_pair(
        (
            _inst(
                "x86-64",
                0x1000,
                "mov",
                "ecx, edi",
                write_registers=("ecx",),
                read_registers=("edi",),
            ),
        ),
        (
            _inst(
                "aarch64",
                0x2000,
                "mov",
                "w8, w0",
                write_registers=("w8",),
                read_registers=("w0",),
            ),
        ),
    )
    candidate = VerificationCandidate(
        candidate_id="reverse-dead-write",
        guest=CodeFragment("x86-64", 0x1000, "0102", 1),
        host=CodeFragment("aarch64", 0x2000, "01020304", 1),
        input_registers=(("edi", "w0"), ("ecx", "w8")),
    )

    guest, _host = _annotate_dead_writes(
        _instructions_to_ast(window.guest.instructions),
        _instructions_to_ast(window.host.instructions),
        candidate,
        window,
        {
            "edi": "i32_reg1",
            "w0": "i32_reg1",
            "ecx": "ecx",
            "w8": "i32_reg2",
        },
        "x86-64",
        "aarch64",
    )

    assert guest[0].to_text() == "mov ecx, edi"


def test_is_branch_instruction():
    from angr_rule_learning.rules.generalize import _is_branch_instruction

    assert _is_branch_instruction(
        Instruction("tbz", (LitOp("w0"), LitOp("#0"), LitOp("#0x1234"))), "aarch64"
    )
    assert _is_branch_instruction(Instruction("je", (LitOp("0x1234"),)), "x86-64")
    assert not _is_branch_instruction(Instruction("add", (LitOp("w0"),)), "aarch64")


# ── post_meta / metadata execution order tests ──────────────────────────


def test_to_text_renders_post_meta_after_instruction() -> None:
    """post_meta lines appear after the instruction line, meta before it."""
    inst = Instruction(
        mnemonic="cmp",
        operands=(RegOp("i32", 32, 1), LitOp("0")),
        meta=(MetaOp(kind="save", regs=(RegOp("i32", 32, 1),)),),
        post_meta=(MetaOp(kind="restore", regs=(RegOp("i32", 32, 1),)),),
    )
    text = inst.to_text()
    lines = text.split("\n")
    assert lines == [
        "save i32_reg1",
        "cmp i32_reg1, 0",
        "restore i32_reg1",
    ]


def test_to_text_no_extra_newline_with_only_instruction() -> None:
    """An instruction with no meta or post_meta produces a single line."""
    inst = Instruction("add", (RegOp("i32", 32, 1), RegOp("i32", 32, 2)))
    assert inst.to_text() == "add i32_reg1, i32_reg2"


def test_post_meta_preserved_through_instruction_constructor() -> None:
    """Reconstructing an Instruction forwards post_meta."""
    original = Instruction(
        mnemonic="mov",
        operands=(RegOp("i32", 32, 1), LitOp("0")),
        post_meta=(MetaOp(kind="restore", regs=(RegOp("i32", 32, 1),)),),
    )
    rebuilt = Instruction(
        mnemonic=original.mnemonic,
        operands=original.operands,
        meta=original.meta,
        post_meta=original.post_meta,
    )
    assert rebuilt.post_meta == original.post_meta
    assert rebuilt.to_text() == original.to_text()


def test_single_dead_write_restore_on_post_meta() -> None:
    """When a dead-write register is written but never read, the restore
    goes on post_meta of the write instruction itself."""
    # The write register ("w8"/"eax") is paired in the input mapping but NOT
    # in the output mapping — that makes it a dead write (its value is
    # overwritten and never used as output).
    pair = _window_pair(
        (
            _inst(
                "aarch64",
                0x1000,
                "mov",
                "w8, w0",
                write_registers=("w8",),
                read_registers=("w0",),
            ),
        ),
        (
            _inst(
                "x86-64",
                0x2000,
                "mov",
                "eax, edi",
                write_registers=("eax",),
                read_registers=("edi",),
            ),
        ),
    )
    # w8/eax in inputs (so it's mapped) but not outputs (so it's dead)
    candidate = _candidate(
        inputs=(("w0", "edi"), ("w8", "eax")),
        outputs=(),
    )
    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is not None
    # The host should have the mov instruction with save on meta
    # and restore on post_meta of the same instruction.
    host_insts = rule.rule.host
    assert len(host_insts) == 1
    # save on meta
    assert any(m.kind == "save" for m in host_insts[0].meta)
    # restore on post_meta (not on meta)
    assert any(m.kind == "restore" for m in host_insts[0].post_meta)
    assert not any(m.kind == "restore" for m in host_insts[0].meta)


def test_dead_write_second_write_updates_last_access() -> None:
    """Same register family written twice — restore goes on second write's post_meta."""
    pair = _window_pair(
        (
            _inst(
                "aarch64",
                0x1000,
                "mov",
                "w8, w0",
                write_registers=("w8",),
                read_registers=("w0",),
            ),
            _inst(
                "aarch64",
                0x1004,
                "add",
                "w8, w8, w1",
                write_registers=("w8",),
                read_registers=("w8", "w1"),
            ),
        ),
        (
            _inst(
                "x86-64",
                0x2000,
                "mov",
                "eax, edi",
                write_registers=("eax",),
                read_registers=("edi",),
            ),
            _inst(
                "x86-64",
                0x2003,
                "add",
                "eax, esi",
                write_registers=("eax",),
                read_registers=("eax", "esi"),
            ),
        ),
    )
    candidate = _candidate(
        inputs=(("w0", "edi"), ("w1", "esi"), ("w8", "eax")), outputs=()
    )
    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is not None
    host_insts = rule.rule.host
    assert len(host_insts) == 2
    # restore on second instruction's post_meta (not first's)
    assert any(m.kind == "restore" for m in host_insts[1].post_meta)
    assert not any(m.kind == "restore" for m in host_insts[0].post_meta)


def test_dead_write_subsequent_write_updates_last_access() -> None:
    """Same-reg dead write twice: restore on second (last access)."""
    pair = _window_pair(
        (
            _inst(
                "aarch64",
                0x1000,
                "mov",
                "w8, w0",
                write_registers=("w8",),
                read_registers=("w0",),
            ),
            _inst(
                "aarch64",
                0x1004,
                "add",
                "w8, w8, w1",
                write_registers=("w8",),
                read_registers=("w8", "w1"),
            ),
        ),
        (
            _inst(
                "x86-64",
                0x2000,
                "mov",
                "eax, edi",
                write_registers=("eax",),
                read_registers=("edi",),
            ),
            _inst(
                "x86-64",
                0x2003,
                "add",
                "eax, eax, esi",
                write_registers=("eax",),
                read_registers=("eax", "esi"),
            ),
        ),
    )
    candidate = _candidate(
        inputs=(("w0", "edi"), ("w1", "esi"), ("w8", "eax")), outputs=()
    )
    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is not None
    host_insts = rule.rule.host
    assert len(host_insts) == 2
    assert any(m.kind == "save" for m in host_insts[0].meta)
    assert any(m.kind == "restore" for m in host_insts[1].post_meta), (
        "restore should be on second instruction's post_meta"
    )
    assert not any(m.kind == "restore" for m in host_insts[0].post_meta)


def test_host_lines_are_flat_no_embedded_newlines() -> None:
    """GeneratedRule.host_lines returns individual lines with no embedded newlines."""
    pair = _window_pair(
        (
            _inst(
                "aarch64",
                0x1000,
                "mov",
                "w8, w0",
                write_registers=("w8",),
                read_registers=("w0",),
            ),
        ),
        (
            _inst(
                "x86-64",
                0x2000,
                "mov",
                "eax, edi",
                write_registers=("eax",),
                read_registers=("edi",),
            ),
        ),
    )
    candidate = _candidate(inputs=(("w0", "edi"), ("w8", "eax")), outputs=())
    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is not None
    for line in rule.host_lines:
        assert "\n" not in line, f"host_line has embedded newline: {line!r}"
    for line in rule.guest_lines:
        assert "\n" not in line, f"guest_line has embedded newline: {line!r}"


def test_immediate_replacement_preserves_metadata() -> None:
    """_replace_immediates_ast preserves meta and post_meta on instructions
    that don't have operand changes."""
    from angr_rule_learning.rules.generalize import _replace_immediates_ast

    save_meta = (MetaOp(kind="save", regs=(RegOp("i32", 32, 1),)),)
    restore_post = (MetaOp(kind="restore", regs=(RegOp("i32", 32, 1),)),)
    inst = Instruction(
        mnemonic="and",
        operands=(RegOp("i32", 32, 1), LitOp("1")),
        meta=save_meta,
        post_meta=restore_post,
    )
    guest_insts: tuple[Instruction, ...] = (inst,)
    host_insts: tuple[Instruction, ...] = (
        Instruction("and", (RegOp("i32", 32, 1), LitOp("1"))),
    )
    g_result, h_result = _replace_immediates_ast(
        guest_insts, "aarch64", host_insts, "x86-64"
    )
    assert len(g_result) == 1
    assert g_result[0].meta == save_meta
    assert g_result[0].post_meta == restore_post


def test_post_meta_preserved_in_alpha_equivalence() -> None:
    """Alpha-equivalence distinguishes sequences by post_meta presence."""
    from angr_rule_learning.rules.ast import instruction_sequences_alpha_equal

    a = (
        Instruction(
            "mov",
            (RegOp("i32", 32, 1), LitOp("0")),
            post_meta=(MetaOp(kind="restore", regs=(RegOp("i32", 32, 1),)),),
        ),
    )
    b = (
        Instruction(
            "mov",
            (RegOp("i32", 32, 1), LitOp("0")),
            post_meta=(MetaOp(kind="restore", regs=(RegOp("i32", 32, 1),)),),
        ),
    )
    c = (Instruction("mov", (RegOp("i32", 32, 1), LitOp("0"))),)
    assert instruction_sequences_alpha_equal(a, b)
    assert not instruction_sequences_alpha_equal(a, c)


# ── Alpha-equivalence tests ─────────────────────────────────────────────


def test_alpha_equal_same_structure_different_numbering():
    """Two rules with consistent renumbering must compare equal."""
    from angr_rule_learning.rules.ast import Rule, rule_alpha_equal

    a = Rule(
        1,
        "a",
        guest=(
            Instruction(
                "add",
                (RegOp("i32", 32, 1), RegOp("i32", 32, 2), RegOp("i32", 32, 3)),
            ),
        ),
        host=(
            Instruction(
                "lea",
                (RegOp("i32", 32, 1), LitOp("[i32_reg2 + i32_reg3]")),
            ),
        ),
    )
    b = Rule(
        2,
        "b",
        guest=(
            Instruction(
                "add",
                (RegOp("i32", 32, 10), RegOp("i32", 32, 20), RegOp("i32", 32, 30)),
            ),
        ),
        host=(
            Instruction(
                "lea",
                (RegOp("i32", 32, 10), LitOp("[i32_reg20 + i32_reg30]")),
            ),
        ),
    )
    assert rule_alpha_equal(a, b)


def test_alpha_not_equal_different_alias_structure():
    """add reg1, reg1, reg2 vs add reg1, reg2, reg1 must NOT compare equal."""
    from angr_rule_learning.rules.ast import (
        instruction_sequences_alpha_equal,
    )

    a_insts = (
        Instruction(
            "add",
            (RegOp("i32", 32, 1), RegOp("i32", 32, 1), RegOp("i32", 32, 2)),
        ),
    )
    b_insts = (
        Instruction(
            "add",
            (RegOp("i32", 32, 1), RegOp("i32", 32, 2), RegOp("i32", 32, 1)),
        ),
    )
    assert not instruction_sequences_alpha_equal(a_insts, b_insts)


def test_alpha_not_equal_different_immediate_binding():
    """Guest has imm1, host has imm2 not derivable from guest -- structures differ."""
    from angr_rule_learning.rules.ast import Rule, rule_alpha_equal

    a = Rule(
        1,
        "a",
        guest=(Instruction("add", (RegOp("i32", 32, 1), ImmOp(id=1))),),
        host=(Instruction("add", (RegOp("i32", 32, 1), ImmOp(id=1))),),
    )
    b = Rule(
        2,
        "b",
        guest=(Instruction("add", (RegOp("i32", 32, 1), ImmOp(id=1))),),
        host=(Instruction("add", (RegOp("i32", 32, 1), ImmOp(id=2))),),
    )
    assert not rule_alpha_equal(a, b)


def test_dedup_keeps_both_add_variants():
    r"""add reg1, reg1, reg2 and add reg1, reg2, reg1 must both be emitted."""
    # Variant 1: add w8, w8, w0  -->  add i32_reg1, i32_reg1, i32_reg2
    add_v1 = _inst(
        "aarch64",
        0x1000,
        "add",
        "w8, w8, w0",
        write_registers=("w8",),
        read_registers=("w8", "w0"),
    )
    pair1 = _window_pair(
        (add_v1,),
        (
            _inst(
                "x86-64",
                0x2000,
                "lea",
                "eax, [eax + edi]",
                write_registers=("eax",),
                read_registers=("eax", "edi"),
            ),
        ),
    )
    candidate1 = _candidate(
        inputs=(("w8", "eax"), ("w0", "edi")),
        outputs=(("w8", "eax"),),
    )

    # Variant 2: add w8, w0, w8  -->  add i32_reg1, i32_reg2, i32_reg1
    add_v2 = _inst(
        "aarch64",
        0x1000,
        "add",
        "w8, w0, w8",
        write_registers=("w8",),
        read_registers=("w0", "w8"),
    )
    pair2 = _window_pair(
        (add_v2,),
        (
            _inst(
                "x86-64",
                0x2000,
                "lea",
                "eax, [edi + eax]",
                write_registers=("eax",),
                read_registers=("edi", "eax"),
            ),
        ),
    )
    candidate2 = _candidate(
        inputs=(("w8", "eax"), ("w0", "edi")),
        outputs=(("w8", "eax"),),
    )

    # Separate generalizers so internal dedup state doesn't interfere.
    gen1 = RuleGeneralizer(RuleDiagnostics())
    gen2 = RuleGeneralizer(RuleDiagnostics())

    r1 = gen1.generate(
        1,
        pair1,
        candidate1,
        _passing_report(candidate1.candidate_id),
    )
    r2 = gen2.generate(
        2,
        pair2,
        candidate2,
        _passing_report(candidate2.candidate_id),
    )

    assert r1 is not None, "First variant should be emitted"
    assert r2 is not None, "Second variant should be emitted"

    from angr_rule_learning.rules.ast import instruction_sequences_alpha_equal

    assert not instruction_sequences_alpha_equal(r1.rule.guest, r2.rule.guest), (
        "Variant guest sequences should not be alpha-equivalent"
    )


def test_label_alpha_equal_same_ids_across_sides():
    """Labels with same original ID across Guest/Host are alpha-equivalent
    under consistent renumbering."""
    from angr_rule_learning.rules.ast import LabelOp, Rule, rule_alpha_equal

    a = Rule(
        1,
        "a",
        guest=(Instruction("b", (RegOp("i32", 32, 1), LabelOp(id=1))),),
        host=(Instruction("jmp", (LabelOp(id=1),)),),
    )
    b = Rule(
        2,
        "b",
        guest=(Instruction("b", (RegOp("i32", 32, 5), LabelOp(id=5))),),
        host=(Instruction("jmp", (LabelOp(id=5),)),),
    )
    assert rule_alpha_equal(a, b)


def test_label_hash_prefix_is_syntax_not_identity():
    """#label1 without hash and label1 with hash share identity but differ
    in syntax attribute."""
    from angr_rule_learning.rules.ast import LabelOp, Rule, rule_alpha_equal

    a = Rule(
        1,
        "a",
        guest=(
            Instruction("b", (RegOp("i32", 32, 1), LabelOp(id=1, aarch64_hash=True))),
        ),
        host=(Instruction("jmp", (LabelOp(id=1, aarch64_hash=True),)),),
    )
    b = Rule(
        2,
        "b",
        guest=(Instruction("b", (RegOp("i32", 32, 1), LabelOp(id=1))),),
        host=(Instruction("jmp", (LabelOp(id=1),)),),
    )
    # Hash prefix differs — not alpha-equivalent
    assert not rule_alpha_equal(a, b)


def test_label_host_swap_not_equal():
    """Guest label1→Host label1 vs Guest label1→Host label2 are NOT equal."""
    from angr_rule_learning.rules.ast import LabelOp, Rule, rule_alpha_equal

    a = Rule(
        1,
        "a",
        guest=(Instruction("b", (RegOp("i32", 32, 1), LabelOp(id=1))),),
        host=(Instruction("je", (LabelOp(id=1),)),),
    )
    b = Rule(
        2,
        "b",
        guest=(Instruction("b", (RegOp("i32", 32, 1), LabelOp(id=1))),),
        host=(Instruction("je", (LabelOp(id=2),)),),
    )
    assert not rule_alpha_equal(a, b)


# ── Immediate derivation tests (Task 3) ───────────────────────────────────


def test_rejects_unrelated_add_chain_as_derivation() -> None:
    """Guest has eor #3; eor #5. Host has mov reg, 8. 3+5=8 is coincidental."""
    guest_eor1 = ExtractedInstruction(
        arch="aarch64",
        address=0x1000,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic="eor",
        op_str="w0, w0, #3",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("w0",),
        read_registers=("w0",),
    )
    guest_eor2 = ExtractedInstruction(
        arch="aarch64",
        address=0x1004,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic="eor",
        op_str="w0, w0, #5",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("w0",),
        read_registers=("w0",),
    )
    host_mov = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="eax, 8",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("eax",),
    )
    window = WindowPair(
        "sample:sample.c:1:0",
        (2, 1),
        InstructionWindow("sample:sample.c:1:0", "guest", (guest_eor1, guest_eor2)),
        InstructionWindow("sample:sample.c:1:0", "host", (host_mov,)),
    )
    candidate = VerificationCandidate(
        candidate_id="eor-add-coincidental",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 2),
        host=CodeFragment("x86-64", 0x2000, "010203", 1),
        output_registers=(("w0", "eax"),),
    )
    report = VerificationReport(
        candidate_id="eor-add-coincidental",
        status="pass",
        checks=(CheckResult("register", "pass", "w0", "eax"),),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, window, candidate, report)

    assert rule is None
    assert diagnostics.skip_reasons.get("unpaired_host_immediate", 0) >= 1


def test_non_memory_rule_rejects_host_only_immediate() -> None:
    """A pure register rule with host-only immediate must be skipped."""
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "add", "w8, w8, #3"),),
        (_inst("x86-64", 0x2000, "add", "eax, 5"),),
    )
    candidate = _candidate(
        inputs=(("w8", "eax"),),
        outputs=(("w8", "eax"),),
    )
    report = _passing_report(candidate.candidate_id)
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, report)

    assert rule is None
    assert diagnostics.skip_reasons.get("unpaired_host_immediate", 0) >= 1


def test_indexed_scale_derives_from_guest_shift() -> None:
    """Guest lsl #2, host *4 — host MUST derive as ${(1 << imm1)} not have
    independent imm2."""
    guest_ldr = ExtractedInstruction(
        arch="aarch64",
        address=0x1000,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic="ldr",
        op_str="w0, [x1, x2, lsl #2]",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("w0",),
        read_registers=("x1", "x2"),
    )
    host_mov = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="eax, dword ptr [rcx + rdx*4]",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("eax",),
        read_registers=("rcx", "rdx"),
    )
    window = WindowPair(
        "sample:sample.c:1:0",
        (1, 1),
        InstructionWindow("sample:sample.c:1:0", "guest", (guest_ldr,)),
        InstructionWindow("sample:sample.c:1:0", "host", (host_mov,)),
    )
    candidate = VerificationCandidate(
        candidate_id="indexed-scale-derivation",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "010203", 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + x2 * 4", "rcx + rdx * 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    report = VerificationReport(
        candidate_id="indexed-scale-derivation",
        status="pass",
        checks=(CheckResult("memory", "pass", "mem0", "mem0"),),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, window, candidate, report)

    assert rule is not None
    host_line = rule.host_lines[0]
    # Host scale must derive from guest shift: *${(1 << imm1)} not *imm2.
    assert "*${(1 << imm1)}" in host_line, f"unexpected host line: {host_line}"
    assert "*imm2" not in host_line, (
        f"host should not have independent imm2: {host_line}"
    )


def test_scale_derivation_uses_span_not_operand_search() -> None:
    """When the same immediate value appears as both *scale and +displacement
    in a host memory operand, only the *-adjacent occurrence is derivable.
    The unproven displacement occurrence returns None."""
    from angr_rule_learning.rules.ast import Instruction as AstInst
    from angr_rule_learning.rules.derivation import (
        DerivationContext,
        _derive_index_scale,
    )

    # Guest has lsl #imm1 where imm1=2 (shift), value = 1<<2 = 4.
    # After immediate replacement Phase 1 the guest text already has immN.
    guest_inst = AstInst.from_text("ldr w0, [x1, x2, lsl #imm1]")
    # Host has imm2 *scale (=4) and imm2 displacement (=4) — same value,
    # same immId.  The text is already post-Phase-1 with placeholders.
    host_inst = AstInst.from_text("mov eax, dword ptr [rcx + rdx*imm2 + imm2]")

    ctx = DerivationContext(
        guest_insts=(guest_inst,),
        host_insts=(host_inst,),
        guest_arch="aarch64",
        host_arch="x86-64",
        value_by_id={"1": 2, "2": 4},
    )

    # Span is relative to the operand text, not the full instruction.
    operand_text = host_inst.operands[1].to_text()
    # Find the span of the *-adjacent "imm2".
    scale_start = operand_text.index("*imm2") + 1  # after "*"
    scale_span = (scale_start, scale_start + 4)

    # Scale occurrence adjacent to "*" — should derive.
    result = _derive_index_scale(ctx, "2", 0, 1, scale_span)
    assert result is not None
    assert "(1 << imm1)" in result

    # Find the span of the displacement "imm2" (not adjacent to "*").
    disp_start = operand_text.index("+ imm2") + 2  # after "+ "
    disp_span = (disp_start, disp_start + 4)

    # Displacement occurrence NOT adjacent to "*" — should return None.
    result_disp = _derive_index_scale(ctx, "2", 0, 1, disp_span)
    assert result_disp is None


def test_fixed_role_cl_rejected_without_rcx_producer() -> None:
    """cl is a fixed-role register.  Without a host instruction that
    writes to the RCX family the Guest→Host binding is invisible in the
    emitted rule — the rule must be rejected."""
    guest_lsl = ExtractedInstruction(
        arch="aarch64",
        address=0x1000,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic="lsl",
        op_str="w0, w0, w1",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("w0",),
        read_registers=("w0", "w1"),
    )
    host_shl = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    window = WindowPair(
        "sample:sample.c:1:0",
        (1, 1),
        InstructionWindow("sample:sample.c:1:0", "guest", (guest_lsl,)),
        InstructionWindow("sample:sample.c:1:0", "host", (host_shl,)),
    )
    candidate = VerificationCandidate(
        candidate_id="shift-no-producer",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "010203", 1),
        input_registers=(("w0", "eax"), ("w1", "cl")),
        output_registers=(("w0", "eax"),),
    )
    report = _passing_report(candidate.candidate_id)
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, window, candidate, report)

    assert rule is None
    # Rejected because cl has no RCX-family producer in the Host window.
    assert diagnostics.skip_reasons.get("unbound_fixed_role_register", 0) >= 1


def test_fixed_role_cl_allowed_with_rcx_producer() -> None:
    """When the Host window has mov ecx, ... before shl ..., cl,
    the Guest→Host binding is explicit and the rule is valid."""
    guest_lsl = ExtractedInstruction(
        arch="aarch64",
        address=0x1000,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic="lsl",
        op_str="w0, w0, w1",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("w0",),
        read_registers=("w0", "w1"),
    )
    host_mov = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="ecx, esi",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("ecx",),
        read_registers=("esi",),
    )
    host_shl = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x04\x05\x06",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 3),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    window = WindowPair(
        "sample:sample.c:1:0",
        (1, 2),
        InstructionWindow("sample:sample.c:1:0", "guest", (guest_lsl,)),
        InstructionWindow("sample:sample.c:1:0", "host", (host_mov, host_shl)),
    )
    candidate = VerificationCandidate(
        candidate_id="shift-with-producer",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "010203040506", 2),
        input_registers=(("w0", "eax"), ("w1", "esi")),
        output_registers=(("w0", "eax"),),
    )
    report = _passing_report(candidate.candidate_id)

    rule = RuleGeneralizer(RuleDiagnostics()).generate(1, window, candidate, report)

    assert rule is not None
    # ecx stays as a literal (not generalized to i32_tmpN), preserving
    # the RCX-family link to cl.  i32_reg2 (for w1/esi) is the source.
    host_text = "\n".join(rule.host_lines)
    assert "mov ecx, i32_reg2" in host_text
    assert "shl i32_reg1, cl" in host_text


def test_fixed_role_producer_after_use_is_rejected() -> None:
    """A write to RCX family AFTER cl is read cannot serve as producer."""
    host_mov = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    host_ecx = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x04\x05\x06",
        mnemonic="mov",
        op_str="ecx, esi",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("ecx",),
        read_registers=("esi",),
    )
    window = WindowPair(
        "s",
        (1, 2),
        InstructionWindow(
            "s",
            "guest",
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "lsl",
                    "w0, w0, w1",
                    write_registers=("w0",),
                    read_registers=("w0", "w1"),
                ),
            ),
        ),
        InstructionWindow("s", "host", (host_mov, host_ecx)),
    )
    candidate = _candidate(
        inputs=(("w0", "eax"), ("w1", "esi")), outputs=(("w0", "eax"),)
    )
    diagnostics = RuleDiagnostics()
    rule = RuleGeneralizer(diagnostics).generate(
        1, window, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is None
    assert diagnostics.skip_reasons.get("unbound_fixed_role_register", 0) >= 1


def test_fixed_role_no_tmp_to_cl_output() -> None:
    """Emitted rule must not contain a plain i32_tmpN feeding into cl."""
    host_mov = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="ecx, esi",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("ecx",),
        read_registers=("esi",),
    )
    host_shl = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x04\x05\x06",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    window = WindowPair(
        "s",
        (1, 2),
        InstructionWindow(
            "s",
            "guest",
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "lsl",
                    "w0, w0, w1",
                    write_registers=("w0",),
                    read_registers=("w0", "w1"),
                ),
            ),
        ),
        InstructionWindow("s", "host", (host_mov, host_shl)),
    )
    candidate = _candidate(
        inputs=(("w0", "eax"), ("w1", "esi")), outputs=(("w0", "eax"),)
    )
    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, window, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is not None
    host_text = "\n".join(rule.host_lines)
    # ecx must be a literal, not a generic tmpN.
    assert "ecx" in host_text
    assert "_tmp" not in host_text


def test_fixed_role_ch_write_does_not_cover_cl() -> None:
    """mov ch, ... does not define the cl bit range (bits 0-7 vs 8-15)."""
    host_mov = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="ch, sil",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("ch",),
        read_registers=("sil",),
    )
    host_shl = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x04\x05\x06",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    window = WindowPair(
        "s",
        (1, 2),
        InstructionWindow(
            "s",
            "guest",
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "lsl",
                    "w0, w0, w1",
                    write_registers=("w0",),
                    read_registers=("w0", "w1"),
                ),
            ),
        ),
        InstructionWindow("s", "host", (host_mov, host_shl)),
    )
    candidate = _candidate(
        inputs=(("w0", "eax"), ("w1", "esi")), outputs=(("w0", "eax"),)
    )
    diagnostics = RuleDiagnostics()
    rule = RuleGeneralizer(diagnostics).generate(
        1, window, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is None
    assert diagnostics.skip_reasons.get("unbound_fixed_role_register", 0) >= 1


def test_fixed_role_mov_ecx_ecx_without_producer_is_rejected() -> None:
    """mov ecx, ecx reads old RCX; without a prior producer, reject."""
    host_mov = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="ecx, ecx",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("ecx",),
        read_registers=("ecx",),
    )
    host_shl = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x04\x05\x06",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    window = WindowPair(
        "s",
        (1, 2),
        InstructionWindow(
            "s",
            "guest",
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "lsl",
                    "w0, w0, w1",
                    write_registers=("w0",),
                    read_registers=("w0", "w1"),
                ),
            ),
        ),
        InstructionWindow("s", "host", (host_mov, host_shl)),
    )
    # ecx is NOT in the input registers — mov ecx,ecx reads old RCX
    # from outside the window, and no prior producer can be traced.
    candidate = _candidate(inputs=(("w0", "eax"),), outputs=(("w0", "eax"),))
    diagnostics = RuleDiagnostics()
    rule = RuleGeneralizer(diagnostics).generate(
        1, window, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is None
    assert diagnostics.skip_reasons.get("unbound_fixed_role_register", 0) >= 1


def test_fixed_role_ecx_as_input_is_rejected() -> None:
    """w1↔ecx as candidate input: ecx is in the fixed-role family so
    it cannot serve as provenance source without an explicit producer."""
    host_mov = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="ecx, ecx",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("ecx",),
        read_registers=("ecx",),
    )
    host_shl = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x04\x05\x06",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    window = WindowPair(
        "s",
        (1, 2),
        InstructionWindow(
            "s",
            "guest",
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "lsl",
                    "w0, w0, w1",
                    write_registers=("w0",),
                    read_registers=("w0", "w1"),
                ),
            ),
        ),
        InstructionWindow("s", "host", (host_mov, host_shl)),
    )
    candidate = _candidate(
        inputs=(("w0", "eax"), ("w1", "ecx")), outputs=(("w0", "eax"),)
    )
    diagnostics = RuleDiagnostics()
    rule = RuleGeneralizer(diagnostics).generate(
        1, window, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is None
    assert diagnostics.skip_reasons.get("unbound_fixed_role_register", 0) >= 1


def test_fixed_role_add_ecx_esi_no_old_source_is_rejected() -> None:
    """add ecx, esi reads old ecx; no prior producer → reject."""
    host_add = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="add",
        op_str="ecx, esi",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("ecx", "rflags"),
        read_registers=("ecx", "esi"),
    )
    host_shl = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x04\x05\x06",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    window = WindowPair(
        "s",
        (1, 2),
        InstructionWindow(
            "s",
            "guest",
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "lsl",
                    "w0, w0, w1",
                    write_registers=("w0",),
                    read_registers=("w0", "w1"),
                ),
            ),
        ),
        InstructionWindow("s", "host", (host_add, host_shl)),
    )
    candidate = _candidate(
        inputs=(("w0", "eax"), ("w1", "esi")), outputs=(("w0", "eax"),)
    )
    diagnostics = RuleDiagnostics()
    rule = RuleGeneralizer(diagnostics).generate(
        1, window, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is None
    assert diagnostics.skip_reasons.get("unbound_fixed_role_register", 0) >= 1


def test_fixed_role_cross_family_chain_accepted() -> None:
    """mov edx,esi; mov ecx,edx; shl ...,cl: cross-family (rsi→rdx→rcx)
    chain is accepted because esi is a mapped non-fixed input."""
    host_mov_edx = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="edx, esi",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("edx",),
        read_registers=("esi",),
    )
    host_mov_ecx = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x04\x05\x06",
        mnemonic="mov",
        op_str="ecx, edx",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("ecx",),
        read_registers=("edx",),
    )
    host_shl = ExtractedInstruction(
        arch="x86-64",
        address=0x2006,
        size=3,
        code_bytes=b"\x07\x08\x09",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 3),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    window = WindowPair(
        "s",
        (1, 3),
        InstructionWindow(
            "s",
            "guest",
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "lsl",
                    "w0, w0, w1",
                    write_registers=("w0",),
                    read_registers=("w0", "w1"),
                ),
            ),
        ),
        InstructionWindow("s", "host", (host_mov_edx, host_mov_ecx, host_shl)),
    )
    candidate = _candidate(
        inputs=(("w0", "eax"), ("w1", "esi")), outputs=(("w0", "eax"),)
    )
    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, window, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is not None
    host_text = "\n".join(rule.host_lines)
    assert "cl" in host_text
    assert "i32_reg2" in host_text


def test_fixed_role_mov_ecx_edx_with_edx_input_accepted() -> None:
    """mov ecx, edx; shl eax, cl where edx is mapped input (w1↔edx).
    The writer (mov ecx,edx) traces through edx to the external input.
    edx is not in the fixed-role family so it is a valid source."""
    host_mov = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="ecx, edx",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("ecx",),
        read_registers=("edx",),
    )
    host_shl = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x04\x05\x06",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    window = WindowPair(
        "s",
        (1, 2),
        InstructionWindow(
            "s",
            "guest",
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "lsl",
                    "w0, w0, w1",
                    write_registers=("w0",),
                    read_registers=("w0", "w1"),
                ),
            ),
        ),
        InstructionWindow("s", "host", (host_mov, host_shl)),
    )
    candidate = _candidate(
        inputs=(("w0", "eax"), ("w1", "edx")), outputs=(("w0", "eax"),)
    )
    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, window, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is not None
    host_text = "\n".join(rule.host_lines)
    assert "i32_reg2" in host_text


def test_fixed_role_save_restore_uses_full_rcx() -> None:
    """Save/restore for fixed-role producers must use rcx, not ecx."""
    host_mov = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="ecx, esi",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("ecx",),
        read_registers=("esi",),
    )
    host_shl = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x04\x05\x06",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    window = WindowPair(
        "s",
        (1, 2),
        InstructionWindow(
            "s",
            "guest",
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "lsl",
                    "w0, w0, w1",
                    write_registers=("w0",),
                    read_registers=("w0", "w1"),
                ),
            ),
        ),
        InstructionWindow("s", "host", (host_mov, host_shl)),
    )
    candidate = _candidate(
        inputs=(("w0", "eax"), ("w1", "esi")), outputs=(("w0", "eax"),)
    )
    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, window, candidate, _passing_report(candidate.candidate_id)
    )
    assert rule is not None
    host_text = "\n".join(rule.host_lines)
    assert "save rcx" in host_text
    assert "restore rcx" in host_text
    assert "save ecx" not in host_text
    assert "restore ecx" not in host_text


def test_collect_sources_edx_via_mov_returns_esi() -> None:
    """mov edx,esi; mov ecx,edx; shl eax,cl:
    _trace_fixed_role_sources("edx", before_idx=1) must return {esi}
    because mov edx,esi is the backward writer for edx."""
    from angr_rule_learning.rules.generalize import _trace_fixed_role_sources

    mov_edx = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="edx, esi",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("edx",),
        read_registers=("esi",),
    )
    mov_ecx = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x04\x05\x06",
        mnemonic="mov",
        op_str="ecx, edx",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("ecx",),
        read_registers=("edx",),
    )
    shl = ExtractedInstruction(
        arch="x86-64",
        address=0x2006,
        size=3,
        code_bytes=b"\x07\x08\x09",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 3),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    sources = _trace_fixed_role_sources(
        "edx",
        1,
        (mov_edx, mov_ecx, shl),
        "x86-64",
        inputs=frozenset({"edx", "esi"}),
    )
    assert sources == frozenset({"esi"})
    assert "edx" not in sources


def test_collect_sources_add_edx_esi_returns_both() -> None:
    """add edx,esi is RMW: old edx and esi are both sources."""
    from angr_rule_learning.rules.generalize import _trace_fixed_role_sources

    add = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="add",
        op_str="edx, esi",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("edx", "rflags"),
        read_registers=("edx", "esi"),
    )
    shl = ExtractedInstruction(
        arch="x86-64",
        address=0x2003,
        size=3,
        code_bytes=b"\x04\x05\x06",
        mnemonic="shl",
        op_str="eax, cl",
        function="f",
        source=SourceLocation("sample.c", 2),
        write_registers=("eax",),
        read_registers=("eax", "cl"),
    )
    sources = _trace_fixed_role_sources(
        "edx",
        1,
        (add, shl),
        "x86-64",
        inputs=frozenset({"edx", "esi"}),
    )
    assert sources == frozenset({"edx", "esi"})


def test_verify_sources_rejects_placeholder_not_in_ast() -> None:
    """AST only contains i32_reg20 but source requires i32_reg2."""
    from angr_rule_learning.rules.ast import Instruction as AstInst

    inst = AstInst.from_text("mov i32_reg20, i32_reg1")
    with pytest.raises(_RuleSkip) as exc:
        _verify_fixed_role_sources_in_ast(
            (inst,),
            frozenset({"esi"}),
            {"esi": "i32_reg2"},
        )
    assert exc.value.reason == "unbound_fixed_role_register"


def test_verify_sources_rejects_missing_mapping() -> None:
    """Source register has no mapping entry — must reject."""
    from angr_rule_learning.rules.ast import Instruction as AstInst

    inst = AstInst.from_text("mov i32_reg2, i32_reg1")
    with pytest.raises(_RuleSkip) as exc:
        _verify_fixed_role_sources_in_ast(
            (inst,),
            frozenset({"esi"}),
            {},
        )
    assert exc.value.reason == "unbound_fixed_role_register"


def test_verify_host_registers_rejects_unbound_typed_register() -> None:
    guest = (Instruction.from_text("add i32_reg1, i32_reg2"),)
    host = (Instruction.from_text("add i32_reg1, i32_reg3, i32_reg2"),)

    with pytest.raises(_RuleSkip) as exc:
        _verify_host_registers_bound(guest, host)

    assert exc.value.reason == "unbound_host_register"


def test_verify_host_registers_allows_host_internal_temporary() -> None:
    guest = (Instruction.from_text("mov i32_reg1, i32_reg2"),)
    host = (
        Instruction.from_text("mov i32_tmp1, i32_reg2"),
        Instruction.from_text("mov i32_reg1, i32_tmp1"),
    )

    _verify_host_registers_bound(guest, host)


def test_verify_host_registers_allows_host_fixed_role_placeholder() -> None:
    guest = (Instruction.from_text("push i64_reg1"),)
    host = (Instruction.from_text("str i64_reg1, [sp64, #-8]!"),)

    _verify_host_registers_bound(guest, host)


def test_verify_host_registers_checks_compound_operands_and_metadata() -> None:
    guest = (Instruction.from_text("ldr i32_reg1, [i64_reg2]"),)
    host = (
        Instruction(
            mnemonic="mov",
            operands=(RegTextOp("dword ptr [i64_reg3]"), RegOp("i32", 32, 1)),
            meta=(MetaOp("save", (RegOp("i32", 32, 4),)),),
        ),
    )

    with pytest.raises(_RuleSkip) as exc:
        _verify_host_registers_bound(guest, host)

    assert exc.value.reason == "unbound_host_register"


def test_no_untyped_temporaries_in_output() -> None:
    """All temporaries must carry type/width: i32_tmp1 not tmp1."""
    # Use the RMW memory window test pattern that generates internal temps.
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
        candidate_id="rmw-temp32-no-untyped",
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
        candidate_id="rmw-temp32-no-untyped",
        status="pass",
        checks=(CheckResult("memory", "pass", "mem0", "mem0"),),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, window, candidate, report)

    assert rule is not None
    import re

    untyped = re.compile(r"(?<![A-Za-z0-9_])tmp\d+")
    for line in rule.guest_lines:
        assert not untyped.search(line), f"guest line contains untyped tmp: {line!r}"
    for line in rule.host_lines:
        assert not untyped.search(line), f"host line contains untyped tmp: {line!r}"
    # Also verify the temp IS typed correctly (i32 for w9).
    assert "i32_tmp1" in rule.guest_lines[0], (
        f"expected i32_tmp1 in guest: {rule.guest_lines}"
    )


# ── Reverse-direction role split tests ──────────────────────────────────


def _candidate_with_arch(
    guest_arch: str,
    host_arch: str,
    *,
    inputs: tuple[tuple[str, str], ...] = (),
    outputs: tuple[tuple[str, str], ...] = (),
) -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id="sample:sample.c:1:0:g0:h0",
        guest=CodeFragment(guest_arch, 0x1000, "01020304", 1),
        host=CodeFragment(host_arch, 0x2000, "010203", 1),
        input_registers=inputs,
        output_registers=outputs,
    )


def test_reverse_add_keeps_output_and_input_placeholders_distinct():
    """x86-64→AArch64 add: host w0 in both output and input → role split.

    Without a host-side role split the output placeholder leaks into
    the guest address-source placeholders, producing the aliased form
    ``lea i32_reg1, [reg64(i32_reg1) + reg64(i32_reg2)]``.
    """
    pair = _window_pair(
        (
            _inst(
                "x86-64",
                0x1000,
                "lea",
                "eax, [rdi + rsi]",
                read_registers=("rdi", "rsi"),
                write_registers=("eax",),
            ),
        ),
        (
            _inst(
                "aarch64",
                0x2000,
                "add",
                "w0, w1, w0",
                read_registers=("w1", "w0"),
                write_registers=("w0",),
            ),
        ),
    )
    candidate = _candidate_with_arch(
        "x86-64",
        "aarch64",
        inputs=(("edi", "w0"), ("esi", "w1")),
        outputs=(("eax", "w0"),),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is not None
    # The output placeholder must NOT be reused as an address-source
    # placeholder with a reg64 view.
    guest_text = "\n".join(rule.guest_lines)
    host_text = "\n".join(rule.host_lines)

    # Check Guest side: output reg must not appear in reg64(...) view.
    import re

    guest_output_match = re.search(r"lea (i32_reg\d+)", guest_text)
    assert guest_output_match, f"could not find lea output in: {guest_text!r}"
    output_ph = guest_output_match.group(1)
    assert f"reg64({output_ph})" not in guest_text, (
        f"output placeholder {output_ph} leaked into address view: {guest_text!r}"
    )

    # Check Host side: w0 is both read and written → must have two
    # distinct placeholders (role split).
    host_placeholders = set(re.findall(r"i32_reg\d+", host_text))
    assert len(host_placeholders) >= 2, (
        f"host should have at least 2 distinct placeholders: {host_text!r}"
    )


# ── Reverse indexed-scale derivation test ───────────────────────────────


def test_reverse_indexed_scale_derivation():
    """x86-64→AArch64 indexed load: guest *immN scale → host lsl #${log2(immN)}.

    Guest: mov eax, dword ptr [rdi + rsi*4]
    Host:  ldr w0, [x0, x1, lsl #2]
    """
    guest_mov = ExtractedInstruction(
        arch="x86-64",
        address=0x1000,
        size=3,
        code_bytes=b"\x01\x02\x03",
        mnemonic="mov",
        op_str="eax, dword ptr [rdi + rsi*4]",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("eax",),
        read_registers=("rdi", "rsi"),
    )
    host_ldr = ExtractedInstruction(
        arch="aarch64",
        address=0x2000,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic="ldr",
        op_str="w0, [x0, x1, lsl #2]",
        function="f",
        source=SourceLocation("sample.c", 1),
        write_registers=("w0",),
        read_registers=("x0", "x1"),
    )
    window = WindowPair(
        "sample:sample.c:1:0",
        (1, 1),
        InstructionWindow("sample:sample.c:1:0", "guest", (guest_mov,)),
        InstructionWindow("sample:sample.c:1:0", "host", (host_ldr,)),
    )
    candidate = VerificationCandidate(
        candidate_id="reverse-indexed-scale",
        guest=CodeFragment("x86-64", 0x1000, "010203", 1),
        host=CodeFragment("aarch64", 0x2000, "01020304", 1),
        input_registers=(("rdi", "x0"), ("rsi", "x1")),
        output_registers=(("eax", "w0"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "rdi + rsi * 4", "x0 + x1 * 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    report = VerificationReport(
        candidate_id="reverse-indexed-scale",
        status="pass",
        checks=(
            CheckResult("memory", "pass", "mem0", "mem0"),
            CheckResult("register", "pass", "eax", "w0"),
        ),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, window, candidate, report)

    assert rule is not None, (
        f"rule should emit, skipped as: {dict(diagnostics.skip_reasons)}"
    )
    host_line = rule.host_lines[0]
    # Host shift must derive from guest scale: lsl #${log2(imm1)}.
    assert "${log2(imm1)}" in host_line, f"unexpected host line: {host_line}"
    assert "unpaired_host_immediate" not in diagnostics.skip_reasons, (
        "rule must not be skipped with unpaired_host_immediate"
    )


# ── RegViewOp AST and fingerprint tests ──────────────────────────────────


class TestRegViewOpRoundtrip:
    """Parse/write roundtrip and alpha-equivalence for RegViewOp."""

    @staticmethod
    def test_parse_regview_roundtrip():
        from angr_rule_learning.rules.ast import Instruction

        inst = Instruction.from_text(
            "lea i32_reg1, [reg64(i32_reg2) + reg64(i32_reg3)]"
        )
        assert inst.mnemonic == "lea"
        assert len(inst.operands) == 2

        # First operand: plain RegOp
        op0 = inst.operands[0]
        assert isinstance(op0, RegOp)  # noqa: F821
        assert op0.to_text() == "i32_reg1"

        # Second operand: LitOp with compound text
        text = inst.to_text()
        assert "reg64(i32_reg2)" in text
        assert "reg64(i32_reg3)" in text

    @staticmethod
    def test_parse_regview_standalone():
        from angr_rule_learning.rules.ast import parse_placeholder, RegViewOp

        rv = parse_placeholder("reg64(i32_reg1)")
        assert isinstance(rv, RegViewOp)
        assert rv.view_bits == 64
        assert rv.mode == "reg"
        assert rv.base.to_text() == "i32_reg1"
        assert rv.to_text() == "reg64(i32_reg1)"

    @staticmethod
    def test_parse_reg32_view_of_i64():
        from angr_rule_learning.rules.ast import parse_placeholder, RegViewOp

        rv = parse_placeholder("reg32(i64_reg1)")
        assert isinstance(rv, RegViewOp)
        assert rv.view_bits == 32
        assert rv.base.to_text() == "i64_reg1"
        assert rv.to_text() == "reg32(i64_reg1)"

    @staticmethod
    def test_regview_alpha_equivalent_same_structure():
        from angr_rule_learning.rules.ast import (
            Rule,
            rule_alpha_equal,
        )

        # Alpha-equivalence only canonicalises placeholder numbering
        # (i32_regN, etc.), not literal text like physical register names.
        # Guest sides must be identical; Host sides differ only in
        # placeholder numbering.
        guest = (Instruction.from_text("add w0, w1, w2"),)
        a = Rule(
            rule_id=1,
            candidate_id="a",
            guest=guest,
            host=(
                Instruction.from_text(
                    "lea i32_reg1, [reg64(i32_reg2) + reg64(i32_reg3)]"
                ),
            ),
        )
        b = Rule(
            rule_id=2,
            candidate_id="b",
            guest=guest,
            host=(
                Instruction.from_text(
                    "lea i32_reg10, [reg64(i32_reg11) + reg64(i32_reg12)]"
                ),
            ),
        )
        assert rule_alpha_equal(a, b)

    @staticmethod
    def test_regview_not_alpha_equivalent_to_plain_reg():
        from angr_rule_learning.rules.ast import (
            Rule,
            rule_alpha_equal,
        )

        guest = (Instruction.from_text("add w0, w1, w2"),)
        a = Rule(
            rule_id=1,
            candidate_id="a",
            guest=guest,
            host=(
                Instruction.from_text(
                    "lea i32_reg1, [reg64(i32_reg2) + reg64(i32_reg3)]"
                ),
            ),
        )
        b = Rule(
            rule_id=2,
            candidate_id="b",
            guest=guest,
            host=(Instruction.from_text("lea i32_reg1, [i32_reg2 + i32_reg3]"),),
        )
        assert not rule_alpha_equal(a, b)

    @staticmethod
    def test_regview_different_widths_not_alpha_equivalent():
        from angr_rule_learning.rules.ast import (
            Rule,
            rule_alpha_equal,
        )

        guest = (Instruction.from_text("add x0, x1, x2"),)
        # reg32 view of i64 vs reg64 view of i64 — different widths.
        a = Rule(
            rule_id=1,
            candidate_id="a",
            guest=guest,
            host=(
                Instruction.from_text(
                    "lea i64_reg1, [reg32(i64_reg2) + reg32(i64_reg3)]"
                ),
            ),
        )
        b = Rule(
            rule_id=2,
            candidate_id="b",
            guest=guest,
            host=(
                Instruction.from_text(
                    "lea i64_reg1, [reg64(i64_reg2) + reg64(i64_reg3)]"
                ),
            ),
        )
        assert not rule_alpha_equal(a, b)

    @staticmethod
    def test_parse_guest_physical_view_roundtrip():
        inst = Instruction.from_text("lsl i32_reg1, i32_reg1, lo8(guest.rcx)")

        assert isinstance(inst.operands[2], GuestRegViewOp)
        assert inst.operands[2].bits == 8
        assert inst.operands[2].scope == "guest"
        assert inst.operands[2].register == "rcx"
        assert inst.to_text() == "lsl i32_reg1, i32_reg1, lo8(guest.rcx)"

    @staticmethod
    def test_guest_physical_views_are_not_alpha_equivalent_across_registers():
        from angr_rule_learning.rules.ast import (
            Rule,
            rule_alpha_equal,
        )

        guest = (Instruction.from_text("shl i32_reg1, cl"),)
        a = Rule(
            rule_id=1,
            candidate_id="a",
            guest=guest,
            host=(Instruction.from_text("lsl i32_reg1, i32_reg1, lo8(guest.rcx)"),),
        )
        b = Rule(
            rule_id=2,
            candidate_id="b",
            guest=guest,
            host=(Instruction.from_text("lsl i32_reg1, i32_reg1, lo8(guest.rdx)"),),
        )

        assert not rule_alpha_equal(a, b)
