import pytest

from angr_rule_learning.rules.ast import (
    AddressExpr,
    BitOrExpr,
    ImmOp,
    ImmRefExpr,
    Instruction,
    LitOp,
    MemoryOperand,
    MetaOp,
    NegExpr,
    RegOp,
    ReadWriteOp,
    ShiftLeftExpr,
    collect_instruction_imm_ids,
    collect_imm_ids,
    iter_instruction_operands,
    map_operand,
    Rule,
    rule_alpha_equal,
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


def test_x86_address_rejects_multiple_displacements() -> None:
    with pytest.raises(ValueError, match="multiple displacements"):
        Instruction.from_text(
            "mov i32_reg1, dword ptr [ptr64_reg2 + 4 + 8]",
            arch="x86-64",
        )


def test_address_expression_rejects_incoherent_fields() -> None:
    with pytest.raises(ValueError, match="requires an index"):
        AddressExpr(base=RegOp("ptr64", 64, 1), scale=LitOp("4"))

    with pytest.raises(ValueError, match="both scale and shift"):
        AddressExpr(
            base=RegOp("ptr64", 64, 1),
            index=RegOp("i64", 64, 2),
            scale=LitOp("4"),
            shift=LitOp("#2"),
        )


def test_memory_operand_rejects_syntax_incompatible_address() -> None:
    shifted = AddressExpr(
        base=RegOp("ptr64", 64, 1),
        index=RegOp("i64", 64, 2),
        shift=LitOp("#2"),
    )
    with pytest.raises(ValueError, match="x86 memory operand cannot use shift"):
        MemoryOperand(address=shifted, syntax="x86")

    scaled = AddressExpr(
        base=RegOp("ptr64", 64, 1),
        index=RegOp("i64", 64, 2),
        scale=LitOp("4"),
    )
    with pytest.raises(ValueError, match="aarch64 memory operand cannot use scale"):
        MemoryOperand(address=scaled, syntax="aarch64")

    indexed_and_displaced = AddressExpr(
        base=RegOp("ptr64", 64, 1),
        index=RegOp("i64", 64, 2),
        displacement=LitOp("#4"),
    )
    with pytest.raises(ValueError, match="index and displacement"):
        MemoryOperand(address=indexed_and_displaced, syntax="aarch64")


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


def test_aarch64_pre_index_writeback_is_structured() -> None:
    inst = Instruction.from_text(
        "stp i64_reg1, i64_reg2, [sp64, #-imm1]!", arch="aarch64"
    )

    memory = inst.operands[2]

    assert isinstance(memory, MemoryOperand)
    assert memory.address.writeback == "pre"
    assert isinstance(memory.address.displacement, ImmOp)
    assert inst.to_text() == "stp i64_reg1, i64_reg2, [sp64, #-imm1]!"


def test_aarch64_post_index_writeback_is_one_structured_operand() -> None:
    inst = Instruction.from_text(
        "ldp i64_reg1, i64_reg2, [sp64], #imm1", arch="aarch64"
    )

    assert len(inst.operands) == 3
    memory = inst.operands[2]
    assert isinstance(memory, MemoryOperand)
    assert memory.address.writeback == "post"
    assert isinstance(memory.address.displacement, ImmOp)
    assert inst.to_text() == "ldp i64_reg1, i64_reg2, [sp64], #imm1"


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


def test_rule_immediate_collection_includes_derived_references() -> None:
    rule = Rule(
        1,
        "derived-only",
        guest=(),
        host=(Instruction.from_text("mov i32_reg1, ${(1 << imm7)}"),),
    )

    assert collect_imm_ids(rule) == {7}


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


def test_immediate_substitution_combines_placeholder_and_value_signs() -> None:
    rule = Rule(
        1,
        "signed-substitution",
        guest=(Instruction.from_text("sub i32_reg1, i32_reg1, #-imm1"),),
        host=(),
    )

    substituted = substitute_imm(rule, 1, "-3")

    assert substituted.guest[0].to_text() == "sub i32_reg1, i32_reg1, #3"


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


def test_generated_rule_round_trip_preserves_arch_and_metadata() -> None:
    original = Rule(
        rule_id=1,
        candidate_id="round-trip",
        guest=(Instruction.from_text("ldr i32_reg1, [ptr64_reg2]", arch="aarch64"),),
        host=(
            Instruction(
                "and",
                (RegOp("i32", 32, 1), LitOp("1")),
                meta=(MetaOp("save", (RegOp("i32", 32, 1),)),),
                post_meta=(MetaOp("restore", (RegOp("i32", 32, 1),)),),
            ),
        ),
    )
    guest_lines = tuple(
        line for inst in original.guest for line in inst.to_text().splitlines()
    )
    host_lines = tuple(
        line for inst in original.host for line in inst.to_text().splitlines()
    )

    rebuilt = Rule.from_generated(
        1,
        "round-trip",
        guest_lines,
        host_lines,
        guest_arch="aarch64",
        host_arch="x86-64",
    )

    assert rule_alpha_equal(original, rebuilt)
    assert len(rebuilt.host) == 1
    assert rebuilt.host[0].meta[0].kind == "save"
    assert rebuilt.host[0].post_meta[0].kind == "restore"


def test_operand_traversal_includes_memory_children_and_metadata() -> None:
    instruction = Instruction.from_text(
        "ldr i32_reg1, [ptr64_reg2], #imm3", arch="aarch64"
    )
    instruction = Instruction(
        instruction.mnemonic,
        instruction.operands,
        meta=(MetaOp("save", (RegOp("i64", 64, 4),)),),
    )

    texts = [op.to_text() for op in iter_instruction_operands((instruction,))]

    assert texts == [
        "i32_reg1",
        "[ptr64_reg2], #imm3",
        "ptr64_reg2",
        "#imm3",
        "i64_reg4",
    ]


def test_operand_transform_preserves_wrapper_semantics() -> None:
    instruction = Instruction.from_text(
        "ldr i32_reg1, [ptr64_reg2], #imm3", arch="aarch64"
    )
    memory = instruction.operands[1]

    transformed = map_operand(
        memory,
        lambda op: LitOp("#4") if isinstance(op, ImmOp) and op.id == 3 else op,
    )

    assert isinstance(transformed, MemoryOperand)
    assert transformed.address.writeback == "post"
    assert transformed.to_text() == "[ptr64_reg2], #4"


def test_read_write_operand_round_trips_distinct_value_roles() -> None:
    instruction = Instruction.from_text("add rw(i32_reg2, i32_reg1), i32_reg3")

    destination = instruction.operands[0]

    assert isinstance(destination, ReadWriteOp)
    assert destination.read == RegOp("i32", 32, 2)
    assert destination.write == RegOp("i32", 32, 1)
    assert instruction.to_text() == "add rw(i32_reg2, i32_reg1), i32_reg3"
