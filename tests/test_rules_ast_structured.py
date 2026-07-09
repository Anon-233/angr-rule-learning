from angr_rule_learning.rules.ast import (
    AddressExpr,
    ImmOp,
    ImmRefExpr,
    Instruction,
    MemoryOperand,
    RegOp,
    ShiftLeftExpr,
    collect_instruction_imm_ids,
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
