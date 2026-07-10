from angr_rule_learning.rules.ast import (
    AddressExpr,
    BitOrExpr,
    ImmOp,
    ImmRefExpr,
    Instruction,
    MemoryOperand,
    NegExpr,
    RegOp,
    ShiftLeftExpr,
    collect_instruction_imm_ids,
    Rule,
    substitute_imm,
)


def test_derived_immediate_is_structured_expression() -> None:
    inst = Instruction.from_text("imul i32_reg1, i32_reg2, ${(1 << imm3)}")

    imm = inst.operands[2]

    assert isinstance(imm, ImmOp)
    assert isinstance(imm.derived, ShiftLeftExpr)
    assert imm.to_text() == "${(1 << imm3)}"
    assert collect_instruction_imm_ids((inst,)) == {"3"}


def test_x86_memory_operand_has_structured_address() -> None:
    inst = Instruction.from_text(
        "mov i32_reg1, dword ptr [ptr64_reg2 + i64_reg3*${(1 << imm1)} + imm2]"
    )

    mem = inst.operands[1]

    assert isinstance(mem, MemoryOperand)
    assert mem.syntax == "x86"
    assert mem.value_bits == 32
    assert isinstance(mem.address, AddressExpr)
    assert mem.address.base == RegOp("ptr64", 64, 2)
    assert mem.address.index == RegOp("i64", 64, 3)
    assert isinstance(mem.address.scale, ImmOp)
    assert isinstance(mem.address.scale.derived, ShiftLeftExpr)
    assert isinstance(mem.address.displacement, ImmOp)
    assert mem.address.displacement.id == 2
    assert collect_instruction_imm_ids((inst,)) == {"1", "2"}
    assert inst.to_text() == (
        "mov i32_reg1, dword ptr [ptr64_reg2 + i64_reg3*${(1 << imm1)} + imm2]"
    )


def test_x86_index_only_address_is_structured() -> None:
    inst = Instruction.from_text("lea i32_reg1, [reg64(i32_reg2)*8]")

    mem = inst.operands[1]

    assert isinstance(mem, MemoryOperand)
    assert mem.syntax == "x86"
    assert mem.address.base is None
    assert mem.address.index is not None
    assert mem.address.index.to_text() == "reg64(i32_reg2)"
    assert mem.address.scale is not None
    assert mem.address.scale.to_text() == "8"
    assert inst.to_text() == "lea i32_reg1, [reg64(i32_reg2)*8]"


def test_aarch64_memory_operand_has_structured_address() -> None:
    inst = Instruction.from_text("ldr i32_reg1, [ptr64_reg2, i64_reg3, lsl #imm1]")

    mem = inst.operands[1]

    assert isinstance(mem, MemoryOperand)
    assert mem.syntax == "aarch64"
    assert mem.value_bits is None
    assert mem.address.base == RegOp("ptr64", 64, 2)
    assert mem.address.index == RegOp("i64", 64, 3)
    assert isinstance(mem.address.shift, ImmOp)
    assert mem.address.shift.id == 1
    assert collect_instruction_imm_ids((inst,)) == {"1"}
    assert inst.to_text() == "ldr i32_reg1, [ptr64_reg2, i64_reg3, lsl #imm1]"


def test_aarch64_base_only_address_uses_explicit_arch_context() -> None:
    inst = Instruction.from_text("ldr i32_reg1, [ptr64_reg2]", arch="aarch64")

    memory = inst.operands[1]

    assert isinstance(memory, MemoryOperand)
    assert memory.syntax == "aarch64"
    assert memory.address.base == RegOp("ptr64", 64, 2)


def test_aarch64_unshifted_register_offset_is_an_index() -> None:
    inst = Instruction.from_text("ldr i32_reg1, [ptr64_reg2, i64_reg3]", arch="aarch64")

    memory = inst.operands[1]

    assert isinstance(memory, MemoryOperand)
    assert memory.address.index == RegOp("i64", 64, 3)
    assert memory.address.displacement is None


def test_log2_immediate_expression_is_structured() -> None:
    inst = Instruction.from_text(
        "ldr i32_reg1, [ptr64_reg2, i64_reg3, lsl #${log2(imm4)}]"
    )

    mem = inst.operands[1]

    assert isinstance(mem, MemoryOperand)
    assert isinstance(mem.address.shift, ImmOp)
    assert isinstance(mem.address.shift.derived, ImmRefExpr) is False
    assert mem.to_text() == "[ptr64_reg2, i64_reg3, lsl #${log2(imm4)}]"
    assert collect_instruction_imm_ids((inst,)) == {"4"}


def test_movk_derived_expression_is_fully_structured() -> None:
    inst = Instruction.from_text("mov i64_reg1, ${(imm1 << imm2) | imm3}")

    immediate = inst.operands[1]

    assert isinstance(immediate, ImmOp)
    assert isinstance(immediate.derived, BitOrExpr)
    assert isinstance(immediate.derived.left, ShiftLeftExpr)
    assert immediate.to_text() == "${(imm1 << imm2) | imm3}"
    assert collect_instruction_imm_ids((inst,)) == {"1", "2", "3"}


def test_memory_immediate_substitution_matches_exact_id() -> None:
    rule = Rule(
        rule_id=1,
        candidate_id="test",
        guest=(Instruction.from_text("mov i32_reg1, dword ptr [ptr64_reg2 + imm10]"),),
        host=(),
    )

    substituted = substitute_imm(rule, 1, "7")

    assert substituted.guest[0].to_text() == (
        "mov i32_reg1, dword ptr [ptr64_reg2 + imm10]"
    )


def test_negative_derived_displacement_preserves_sign() -> None:
    inst = Instruction.from_text("lea i64_reg1, [ptr64_reg2 - ${(1 << imm1)}]")

    memory = inst.operands[1]

    assert isinstance(memory, MemoryOperand)
    assert isinstance(memory.address.displacement, ImmOp)
    assert isinstance(memory.address.displacement.derived, NegExpr)
    assert inst.to_text() == "lea i64_reg1, [ptr64_reg2 - ${(1 << imm1)}]"


def test_negative_flag_normalizes_into_derived_expression() -> None:
    immediate = ImmOp(id=2, derived="${(1 << imm1)}", neg=True)

    assert isinstance(immediate.derived, NegExpr)
    assert immediate.neg is False
    assert immediate.to_text() == "-${(1 << imm1)}"


def test_negative_derived_immediate_round_trips_as_standalone_operand() -> None:
    inst = Instruction.from_text("mov i64_reg1, -${(1 << imm1)}")

    immediate = inst.operands[1]

    assert isinstance(immediate, ImmOp)
    assert isinstance(immediate.derived, NegExpr)
    assert inst.to_text() == "mov i64_reg1, -${(1 << imm1)}"
