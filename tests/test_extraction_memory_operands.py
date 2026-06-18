from angr_rule_learning.extraction.memory_operands import (
    MemoryOperand,
    extract_memory_operands,
)
from angr_rule_learning.extraction.memory_surfaces import (
    _adjust_for_sp_delta,
    _instruction_sp_delta,
)
from angr_rule_learning.extraction.models import ExtractedInstruction
from angr_rule_learning.verification.addressing import AddressExpr


def _inst(arch: str, mnemonic: str, op_str: str) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=0x1000,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic=mnemonic,
        op_str=op_str,
        function="f",
        source=None,
    )


def test_parses_aarch64_ldr_base_address() -> None:
    operands = extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1]"))

    assert operands == (
        MemoryOperand(
            kind="read",
            width=4,
            address=AddressExpr(base="x1"),
            text="[x1]",
            value_register="w0",
        ),
    )


def test_parses_aarch64_str_base_plus_offset() -> None:
    operands = extract_memory_operands(_inst("aarch64", "str", "x2, [sp, #16]"))

    assert operands == (
        MemoryOperand(
            kind="write",
            width=8,
            address=AddressExpr(base="sp", displacement=16),
            text="[sp, #16]",
            value_register="x2",
        ),
    )


def test_parses_aarch64_negative_offset() -> None:
    operands = extract_memory_operands(_inst("aarch64", "ldur", "w8, [x29, #-4]"))

    assert operands[0].address == AddressExpr(base="x29", displacement=-4)
    assert operands[0].width == 4


def test_parses_x86_64_mov_load_with_ptr_prefix() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "mov", "eax, dword ptr [rcx + 4]")
    )

    assert operands == (
        MemoryOperand(
            kind="read",
            width=4,
            address=AddressExpr(base="rcx", displacement=4),
            text="[rcx + 4]",
            value_register="eax",
        ),
    )


def test_parses_x86_64_mov_store_with_negative_offset() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "mov", "qword ptr [rbp - 8], rax")
    )

    assert operands == (
        MemoryOperand(
            kind="write",
            width=8,
            address=AddressExpr(base="rbp", displacement=-8),
            text="[rbp - 8]",
            value_register="rax",
        ),
    )


def test_unsupported_memory_forms_return_empty_tuple() -> None:
    assert extract_memory_operands(_inst("x86-64", "pusha", " ")) == ()
    assert (
        extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1, w2, uxtw #2]")) == ()
    )


def test_rejects_aarch64_post_index_addressing() -> None:
    assert extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1], #4")) == ()


def test_rejects_aarch64_pre_index_writeback_addressing() -> None:
    assert extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1, #4]!")) == ()


def test_parses_aarch64_register_offset_addressing() -> None:
    operands = extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1, x2]"))

    assert operands == (
        MemoryOperand(
            kind="read",
            width=4,
            address=AddressExpr(base="x1", index="x2"),
            text="[x1, x2]",
            value_register="w0",
        ),
    )


def test_parses_aarch64_lsl_indexed_addressing() -> None:
    operands = extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1, x2, lsl #2]"))

    assert operands[0].address == AddressExpr(base="x1", index="x2", scale=4)
    assert operands[0].text == "[x1, x2, lsl #2]"


def test_parses_x86_64_indexed_addressing() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "mov", "eax, dword ptr [rcx + rdx*4 + 8]")
    )

    assert operands[0].address == AddressExpr(
        base="rcx",
        index="rdx",
        scale=4,
        displacement=8,
    )
    assert operands[0].text == "[rcx + rdx*4 + 8]"


def test_rejects_aarch64_extend_index_addressing() -> None:
    assert (
        extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1, w2, uxtw #2]")) == ()
    )


def test_rejects_x86_64_rip_relative_addressing() -> None:
    assert (
        extract_memory_operands(_inst("x86-64", "mov", "eax, dword ptr [rip + 4]"))
        == ()
    )


def test_rejects_x86_64_segment_override_addressing() -> None:
    assert (
        extract_memory_operands(_inst("x86-64", "mov", "eax, dword ptr fs:[rcx]")) == ()
    )


def test_x86_store_immediate_memory_operand_is_marked_non_register_value() -> None:
    operands = extract_memory_operands(_inst("x86-64", "mov", "dword ptr [rbp - 4], 3"))

    assert len(operands) == 1
    assert operands[0].kind == "write"
    assert operands[0].width == 4
    assert operands[0].address == AddressExpr(base="rbp", displacement=-4)
    assert operands[0].value_register is None
    assert operands[0].value_immediate == "3"


def test_parses_aarch64_ldrsw_as_32_bit_memory_read() -> None:
    operands = extract_memory_operands(
        _inst("aarch64", "ldrsw", "x0, [x1, x2, lsl #2]")
    )

    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 4
    assert operands[0].value_register == "x0"
    assert operands[0].address == AddressExpr(base="x1", index="x2", scale=4)


def test_parses_x86_movsxd_memory_source_as_32_bit_memory_read() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "movsxd", "rax, dword ptr [rcx + rdx*4]")
    )

    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 4
    assert operands[0].value_register == "rax"
    assert operands[0].address == AddressExpr(base="rcx", index="rdx", scale=4)


def test_parses_x86_add_memory_source_as_read_operand() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "add", "eax, dword ptr [rbp - 8]")
    )

    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 4
    assert operands[0].value_register == "eax"
    assert operands[0].address == AddressExpr(base="rbp", displacement=-8)


def test_parses_x86_sub_memory_source_as_read_operand() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "sub", "eax, dword ptr [rbp - 4]")
    )

    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 4
    assert operands[0].value_register == "eax"


def test_parses_x86_imul_memory_source_as_read_operand() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "imul", "eax, dword ptr [rbp - 8]")
    )

    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 4
    assert operands[0].value_register == "eax"


def test_parses_x86_and_memory_source_as_read_operand() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "and", "eax, dword ptr [rbp - 0xc]")
    )

    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 4
    assert operands[0].value_register == "eax"


def test_rejects_x86_rmw_write_to_memory() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "add", "dword ptr [rbp - 8], eax")
    )

    assert operands == ()


# ── RMW width tests ─────────────────────────────────────────────────────


def test_rmw_byte_width() -> None:
    """add al, byte ptr [rcx] -> width 1"""
    operands = extract_memory_operands(_inst("x86-64", "add", "al, byte ptr [rcx]"))
    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 1
    assert operands[0].value_register == "al"
    assert operands[0].address == AddressExpr(base="rcx")


def test_rmw_word_width() -> None:
    """sub ax, word ptr [rcx] -> width 2"""
    operands = extract_memory_operands(_inst("x86-64", "sub", "ax, word ptr [rcx]"))
    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 2
    assert operands[0].value_register == "ax"


def test_rmw_dword_width() -> None:
    """xor eax, dword ptr [rcx] -> width 4"""
    operands = extract_memory_operands(_inst("x86-64", "xor", "eax, dword ptr [rcx]"))
    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 4
    assert operands[0].value_register == "eax"


def test_rmw_qword_width() -> None:
    """imul rax, qword ptr [rcx] -> width 8"""
    operands = extract_memory_operands(_inst("x86-64", "imul", "rax, qword ptr [rcx]"))
    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 8
    assert operands[0].value_register == "rax"


def test_rmw_width_inferred_from_register() -> None:
    """add rax, [rcx] -> width 8 (inferred from rax, no ptr keyword)"""
    operands = extract_memory_operands(_inst("x86-64", "add", "rax, [rcx]"))
    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 8
    assert operands[0].value_register == "rax"


# ── push / pop tests ────────────────────────────────────────────────────


def test_parses_push_reg_as_memory_write() -> None:
    operands = extract_memory_operands(_inst("x86-64", "push", "rbp"))

    assert operands == (
        MemoryOperand(
            kind="write",
            width=8,
            address=AddressExpr(base="rsp", displacement=-8),
            text="[rsp]",
            value_register="rbp",
        ),
    )


def test_parses_pop_reg_as_memory_read() -> None:
    operands = extract_memory_operands(_inst("x86-64", "pop", "r15"))

    assert operands == (
        MemoryOperand(
            kind="read",
            width=8,
            address=AddressExpr(base="rsp"),
            text="[rsp]",
            value_register="r15",
        ),
    )


def test_parses_push_imm_as_memory_write() -> None:
    operands = extract_memory_operands(_inst("x86-64", "push", "0x18"))

    assert len(operands) == 1
    assert operands[0].kind == "write"
    assert operands[0].width == 8
    assert operands[0].address == AddressExpr(base="rsp", displacement=-8)
    assert operands[0].value_register is None
    assert operands[0].value_immediate == "0x18"


def test_push_16bit_width() -> None:
    """push r8w -> width 2 (16-bit operand-size override)"""
    operands = extract_memory_operands(_inst("x86-64", "push", "r8w"))
    assert len(operands) == 1
    assert operands[0].width == 2
    assert operands[0].address.displacement == -2
    assert operands[0].value_register == "r8w"


def test_pop_16bit_width() -> None:
    """pop r9w -> width 2"""
    operands = extract_memory_operands(_inst("x86-64", "pop", "r9w"))
    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 2
    assert operands[0].value_register == "r9w"


def test_push_r8_64bit_register() -> None:
    """push r8 -> width 8 (64-bit extended GPR)"""
    operands = extract_memory_operands(_inst("x86-64", "push", "r8"))
    assert len(operands) == 1
    assert operands[0].width == 8
    assert operands[0].value_register == "r8"


def test_push_eax_rejected_in_64bit_mode() -> None:
    """32-bit register pushes are not encodable in 64-bit mode."""
    assert extract_memory_operands(_inst("x86-64", "push", "eax")) == ()


def test_pop_edi_rejected_in_64bit_mode() -> None:
    """32-bit register pops are not encodable in 64-bit mode."""
    assert extract_memory_operands(_inst("x86-64", "pop", "edi")) == ()


def test_push_r8d_rejected_in_64bit_mode() -> None:
    assert extract_memory_operands(_inst("x86-64", "push", "r8d")) == ()


def test_push_r8b_rejected_in_64bit_mode() -> None:
    """8-bit register pushes are not encodable in 64-bit mode."""
    assert extract_memory_operands(_inst("x86-64", "push", "r8b")) == ()


# ── stp / ldp tests ─────────────────────────────────────────────────────


def test_parses_stp_offset_as_two_writes() -> None:
    operands = extract_memory_operands(_inst("aarch64", "stp", "x20, x19, [sp, #0x40]"))

    assert len(operands) == 2
    assert operands[0] == MemoryOperand(
        kind="write",
        width=8,
        address=AddressExpr(base="sp", displacement=0x40),
        text="[sp, #64]",
        value_register="x20",
    )
    assert operands[1] == MemoryOperand(
        kind="write",
        width=8,
        address=AddressExpr(base="sp", displacement=0x48),
        text="[sp, #72]",
        value_register="x19",
    )


def test_parses_stp_pre_index_as_two_writes() -> None:
    operands = extract_memory_operands(
        _inst("aarch64", "stp", "x29, x30, [sp, #-0x10]!")
    )

    assert len(operands) == 2
    assert operands[0] == MemoryOperand(
        kind="write",
        width=8,
        address=AddressExpr(base="sp", displacement=-0x10),
        text="[sp, #-16]",
        value_register="x29",
    )
    assert operands[1] == MemoryOperand(
        kind="write",
        width=8,
        address=AddressExpr(base="sp", displacement=-8),
        text="[sp, #-8]",
        value_register="x30",
    )


def test_parses_ldp_post_index_as_two_reads() -> None:
    operands = extract_memory_operands(_inst("aarch64", "ldp", "x29, x30, [sp], #0x10"))

    assert len(operands) == 2
    assert operands[0] == MemoryOperand(
        kind="read",
        width=8,
        address=AddressExpr(base="sp"),
        text="[sp]",
        value_register="x29",
    )
    assert operands[1] == MemoryOperand(
        kind="read",
        width=8,
        address=AddressExpr(base="sp", displacement=8),
        text="[sp, #8]",
        value_register="x30",
    )


def test_parses_ldnp_offset_as_two_reads() -> None:
    operands = extract_memory_operands(_inst("aarch64", "ldnp", "x0, x1, [x2, #0x20]"))

    assert len(operands) == 2
    assert operands[0].kind == "read"
    assert operands[0].width == 8
    assert operands[1].kind == "read"


def test_stp_w_register_uses_4_byte_width() -> None:
    """stp with w registers should produce 4-byte operands."""
    operands = extract_memory_operands(_inst("aarch64", "stp", "w8, w9, [sp, #8]"))

    assert len(operands) == 2
    assert operands[0].width == 4
    assert operands[0].value_register == "w8"
    assert operands[1].address == AddressExpr(base="sp", displacement=12)


# ── sp delta tracking tests ──────────────────────────────────────────────


def test_push_has_negative_sp_delta() -> None:
    assert _instruction_sp_delta(_inst("x86-64", "push", "rbp")) == -8


def test_pop_has_positive_sp_delta() -> None:
    assert _instruction_sp_delta(_inst("x86-64", "pop", "r14")) == 8


def test_push_imm_has_negative_sp_delta() -> None:
    assert _instruction_sp_delta(_inst("x86-64", "push", "0x18")) == -8


def test_stp_pre_index_has_negative_sp_delta() -> None:
    assert (
        _instruction_sp_delta(_inst("aarch64", "stp", "x29, x30, [sp, #-0x10]!"))
        == -0x10
    )


def test_stp_offset_no_writeback_has_zero_sp_delta() -> None:
    assert _instruction_sp_delta(_inst("aarch64", "stp", "x20, x19, [sp, #0x40]")) == 0


def test_ldp_post_index_has_positive_sp_delta() -> None:
    assert (
        _instruction_sp_delta(_inst("aarch64", "ldp", "x29, x30, [sp], #0x10")) == 0x10
    )


def test_ldp_offset_no_writeback_has_zero_sp_delta() -> None:
    assert _instruction_sp_delta(_inst("aarch64", "ldp", "x20, x19, [sp, #0x40]")) == 0


def test_x86_add_rsp_sp_delta() -> None:
    assert _instruction_sp_delta(_inst("x86-64", "add", "rsp, 0x18")) == 0x18


def test_x86_sub_rsp_sp_delta() -> None:
    assert _instruction_sp_delta(_inst("x86-64", "sub", "rsp, 0x18")) == -0x18


def test_aarch64_sub_sp_sp_delta() -> None:
    assert _instruction_sp_delta(_inst("aarch64", "sub", "sp, sp, #0x50")) == -0x50


def test_non_sp_instruction_has_zero_delta() -> None:
    assert _instruction_sp_delta(_inst("x86-64", "mov", "eax, ebx")) == 0
    assert _instruction_sp_delta(_inst("aarch64", "add", "w0, w1, w2")) == 0


def test_adjust_for_sp_delta_modifies_rsp_based_operand() -> None:
    op = MemoryOperand(
        kind="write",
        width=8,
        address=AddressExpr(base="rsp", displacement=-8),
        text="[rsp]",
        value_register="rbp",
    )
    adjusted = _adjust_for_sp_delta(op, -16, "x86-64")
    assert adjusted.address.displacement == -24  # -8 + (-16)


def test_adjust_for_sp_delta_ignores_non_stack_bases() -> None:
    op = MemoryOperand(
        kind="read",
        width=4,
        address=AddressExpr(base="x0", displacement=16),
        text="[x0, #16]",
        value_register="w1",
    )
    adjusted = _adjust_for_sp_delta(op, -8, "aarch64")
    assert adjusted is op  # unchanged


def test_adjust_for_sp_delta_zero_is_noop() -> None:
    op = MemoryOperand(
        kind="write",
        width=8,
        address=AddressExpr(base="rsp", displacement=-8),
        text="[rsp]",
        value_register="rbp",
    )
    adjusted = _adjust_for_sp_delta(op, 0, "x86-64")
    assert adjusted is op  # unchanged


# ── pair / stack zero-displacement tests ────────────────────────────────


def test_parses_stp_zero_offset() -> None:
    """stp with no explicit offset (encoding offset=0)."""
    operands = extract_memory_operands(_inst("aarch64", "stp", "x0, x1, [sp]"))
    assert len(operands) == 2
    assert operands[0].address == AddressExpr(base="sp")
    assert operands[1].address == AddressExpr(base="sp", displacement=8)


def test_rejects_stnp_writeback() -> None:
    """stnp does not support pre-index writeback."""
    assert (
        extract_memory_operands(_inst("aarch64", "stnp", "x0, x1, [sp, #0x10]!")) == ()
    )


def test_rejects_ldnp_writeback() -> None:
    """ldnp does not support post-index."""
    assert (
        extract_memory_operands(_inst("aarch64", "ldnp", "x0, x1, [sp], #0x10")) == ()
    )


def test_ldnp_offset_form_is_parsed() -> None:
    """ldnp offset form (no writeback) is valid."""
    operands = extract_memory_operands(_inst("aarch64", "ldnp", "x0, x1, [x2, #0x20]"))
    assert len(operands) == 2
    assert operands[0].kind == "read"


# ── multi-instruction SP delta tests ────────────────────────────────────


def test_sp_delta_stp_writeback_adjusts_subsequent_str() -> None:
    """After stp [sp, #-0x10]!, subsequent str [sp, #8] addresses are
    adjusted to account for the -0x10 sp change."""
    # str x0, [sp, #8] after sp was decremented by 0x10
    op = MemoryOperand(
        kind="write",
        width=8,
        address=AddressExpr(base="sp", displacement=8),
        text="[sp, #8]",
        value_register="x0",
    )
    adjusted = _adjust_for_sp_delta(op, -0x10, "aarch64")
    assert adjusted.address.displacement == -8  # 8 + (-0x10)


def test_sp_delta_ldp_post_index_adjusts_subsequent_ldr() -> None:
    """After ldp [sp], #0x10, subsequent ldr [sp, #8] gets adjusted."""
    op = MemoryOperand(
        kind="read",
        width=8,
        address=AddressExpr(base="sp", displacement=8),
        text="[sp, #8]",
        value_register="x0",
    )
    adjusted = _adjust_for_sp_delta(op, 0x10, "aarch64")
    assert adjusted.address.displacement == 0x18  # 8 + 0x10


def test_double_push_sp_deltas_accumulate() -> None:
    """push rbp; push r15: second push sees cumulative sp_delta of -8."""
    op = MemoryOperand(
        kind="write",
        width=8,
        address=AddressExpr(base="rsp", displacement=-8),
        text="[rsp]",
        value_register="r15",
    )
    adjusted = _adjust_for_sp_delta(op, -8, "x86-64")
    assert adjusted.address.displacement == -16  # -8 + (-8)
