from angr_rule_learning.extraction.memory_operands import (
    MemoryOperand,
    extract_memory_operands,
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
    assert extract_memory_operands(_inst("x86-64", "push", "rax")) == ()
    assert extract_memory_operands(_inst("aarch64", "ldp", "x0, x1, [sp]")) == ()


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
