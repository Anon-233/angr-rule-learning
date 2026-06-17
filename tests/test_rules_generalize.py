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
