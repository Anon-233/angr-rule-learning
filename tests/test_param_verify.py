from angr_rule_learning.param_verify import (
    ParameterizedRuleVerifier,
    ParameterizedVerifyRequest,
)
from angr_rule_learning.rules.ast import ImmOp, Instruction, LitOp, RegOp, Rule


def _rule(
    guest: tuple[Instruction, ...],
    host: tuple[Instruction, ...],
) -> Rule:
    return Rule(rule_id=1, candidate_id="test-rule", guest=guest, host=host)


def test_literal_mask_movzx_rule_passes() -> None:
    rule = _rule(
        guest=(
            Instruction(
                "and",
                (RegOp("i32", 32, 1), RegOp("i32", 32, 2), LitOp("#0xff")),
            ),
        ),
        host=(
            Instruction(
                "movzx",
                (RegOp("i32", 32, 1), LitOp("lo8(i32_reg2)")),
            ),
        ),
    )

    report = ParameterizedRuleVerifier().verify(ParameterizedVerifyRequest(rule))

    assert report.status == "pass"


def test_parameterized_mask_movzx_rule_fails() -> None:
    rule = _rule(
        guest=(
            Instruction(
                "and",
                (RegOp("i32", 32, 1), RegOp("i32", 32, 2), ImmOp(1, aarch64_hash=True)),
            ),
        ),
        host=(
            Instruction(
                "movzx",
                (RegOp("i32", 32, 1), LitOp("lo8(i32_reg2)")),
            ),
        ),
    )

    report = ParameterizedRuleVerifier().verify(ParameterizedVerifyRequest(rule))

    assert report.status == "fail"
    assert report.reason == "parameterized_register_mismatch"
    assert "imm1" in report.counterexample


def test_shared_add_immediate_rule_passes() -> None:
    rule = _rule(
        guest=(
            Instruction(
                "add",
                (RegOp("i32", 32, 1), RegOp("i32", 32, 2), ImmOp(1, aarch64_hash=True)),
            ),
        ),
        host=(
            Instruction(
                "mov",
                (RegOp("i32", 32, 1), RegOp("i32", 32, 2)),
            ),
            Instruction(
                "add",
                (RegOp("i32", 32, 1), ImmOp(1)),
            ),
        ),
    )

    report = ParameterizedRuleVerifier().verify(ParameterizedVerifyRequest(rule))

    assert report.status == "pass"


def test_shared_immediate_add_sub_rule_fails() -> None:
    rule = _rule(
        guest=(
            Instruction(
                "add",
                (RegOp("i32", 32, 1), RegOp("i32", 32, 2), ImmOp(1, aarch64_hash=True)),
            ),
        ),
        host=(
            Instruction(
                "mov",
                (RegOp("i32", 32, 1), RegOp("i32", 32, 2)),
            ),
            Instruction(
                "sub",
                (RegOp("i32", 32, 1), ImmOp(1)),
            ),
        ),
    )

    report = ParameterizedRuleVerifier().verify(ParameterizedVerifyRequest(rule))

    assert report.status == "fail"
    assert report.reason == "parameterized_register_mismatch"
    assert "imm1" in report.counterexample


def test_derived_shift_scale_rule_passes() -> None:
    rule = _rule(
        guest=(
            Instruction(
                "lsl",
                (RegOp("i32", 32, 1), RegOp("i32", 32, 2), ImmOp(1, aarch64_hash=True)),
            ),
        ),
        host=(
            Instruction(
                "imul",
                (
                    RegOp("i32", 32, 1),
                    RegOp("i32", 32, 2),
                    ImmOp(0, derived="${(1 << imm1)}"),
                ),
            ),
        ),
    )

    report = ParameterizedRuleVerifier().verify(ParameterizedVerifyRequest(rule))

    assert report.status == "pass"


def test_wrong_shift_scale_rule_fails() -> None:
    rule = _rule(
        guest=(
            Instruction(
                "lsl",
                (RegOp("i32", 32, 1), RegOp("i32", 32, 2), ImmOp(1, aarch64_hash=True)),
            ),
        ),
        host=(
            Instruction(
                "imul",
                (RegOp("i32", 32, 1), RegOp("i32", 32, 2), ImmOp(1)),
            ),
        ),
    )

    report = ParameterizedRuleVerifier().verify(ParameterizedVerifyRequest(rule))

    assert report.status == "fail"
    assert report.reason == "parameterized_register_mismatch"


def test_reg64_views_allow_equivalent_low_32_bit_lea() -> None:
    rule = _rule(
        guest=(Instruction.from_text("add i32_reg1, i32_reg2, i32_reg3"),),
        host=(
            Instruction.from_text("lea i32_reg1, [reg64(i32_reg2) + reg64(i32_reg3)]"),
        ),
    )

    report = ParameterizedRuleVerifier().verify(ParameterizedVerifyRequest(rule))

    assert report.status == "pass"


def test_reg64_views_do_not_constrain_high_bits_across_sides() -> None:
    rule = _rule(
        guest=(
            Instruction.from_text("add i64_reg1, reg64(i32_reg2), reg64(i32_reg3)"),
        ),
        host=(
            Instruction.from_text("lea i64_reg1, [reg64(i32_reg2) + reg64(i32_reg3)]"),
        ),
    )

    report = ParameterizedRuleVerifier().verify(ParameterizedVerifyRequest(rule))

    assert report.status == "fail"
    assert report.reason == "parameterized_register_mismatch"


def test_composed_shift_or_immediate_expression_passes() -> None:
    rule = _rule(
        guest=(
            Instruction.from_text("mov i32_reg1, imm1"),
            Instruction.from_text("lsl i32_reg1, i32_reg1, imm2"),
            Instruction.from_text("orr i32_reg1, i32_reg1, imm3"),
        ),
        host=(Instruction.from_text("mov i32_reg1, ${(imm1 << imm2) | imm3}"),),
    )

    report = ParameterizedRuleVerifier().verify(ParameterizedVerifyRequest(rule))

    assert report.status == "pass"
