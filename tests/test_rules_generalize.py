import pytest

from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    SourceLocation,
    WindowPair,
)
from angr_rule_learning.rules.ast import (
    ImmOp,
    Instruction,
    LitOp,
    MetaOp,
    RegOp,
    RegTextOp,
)
from angr_rule_learning.rules.generalize import (
    GeneratedRule,
    RuleDiagnostics,
    RuleGeneralizer,
    _RuleSkip,
    _generalize_instructions_with_roles,
    _instructions_to_ast,
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


def test_generalizer_does_not_coalesce_by_host_carrier_alone() -> None:
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

    assert rule is None
    assert diagnostics.skip_reasons["unsupported_rule_shape"] == 1


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


def test_generalizer_rejects_conflicting_physical_register_mapping() -> None:
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

    assert generalizer.generate(1, window, candidate, report) is None
    assert diagnostics.skip_reasons["unsupported_rule_shape"] == 1


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
        (inst,), extracted, mapping, {}, "aarch64"
    )
    assert len(result) == 1
    ops = result[0].operands
    assert ops == (RegOp("i32", 32, 1), RegOp("i32", 32, 2), RegOp("i32", 32, 3))


def test_generalize_ast_role_split() -> None:
    """AST generalization applies role_split so write/read of same reg get
    different placeholders."""
    inst = Instruction(mnemonic="sub", operands=(LitOp("w0"), LitOp("w0"), LitOp("w1")))
    mapping = {"w1": "i32_reg2"}
    role_split = {"w0": ("i32_reg1", "i32_reg3")}
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
        (inst,), extracted, mapping, role_split, "aarch64"
    )
    assert len(result) == 1
    ops = result[0].operands
    assert ops == (RegOp("i32", 32, 1), RegOp("i32", 32, 3), RegOp("i32", 32, 2))


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


def test_insts_equal_compares_post_meta() -> None:
    """_insts_equal considers post_meta in structural comparison."""
    from angr_rule_learning.rules.ast import _insts_equal

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
    assert _insts_equal(a, b)
    assert not _insts_equal(a, c)


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
