from angr_rule_learning.extraction.memory_operands import (
    MemoryAddress,
    MemoryOperand,
    extract_memory_operands,
)
from angr_rule_learning.extraction.models import ExtractedInstruction


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
            address=MemoryAddress(base="x1", displacement=0),
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
            address=MemoryAddress(base="sp", displacement=16),
            text="[sp, #16]",
            value_register="x2",
        ),
    )


def test_parses_aarch64_negative_offset() -> None:
    operands = extract_memory_operands(_inst("aarch64", "ldur", "w8, [x29, #-4]"))

    assert operands[0].address == MemoryAddress(base="x29", displacement=-4)
    assert operands[0].width == 4


def test_parses_x86_64_mov_load_with_ptr_prefix() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "mov", "eax, dword ptr [rcx + 4]")
    )

    assert operands == (
        MemoryOperand(
            kind="read",
            width=4,
            address=MemoryAddress(base="rcx", displacement=4),
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
            address=MemoryAddress(base="rbp", displacement=-8),
            text="[rbp - 8]",
            value_register="rax",
        ),
    )


def test_unsupported_memory_forms_return_empty_tuple() -> None:
    assert extract_memory_operands(_inst("x86-64", "push", "rax")) == ()
    assert extract_memory_operands(_inst("aarch64", "ldp", "x0, x1, [sp]")) == ()
    assert extract_memory_operands(_inst("x86-64", "mov", "eax, [rax + rcx * 4]")) == ()


def test_rejects_aarch64_post_index_addressing() -> None:
    assert extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1], #4")) == ()


def test_rejects_aarch64_pre_index_writeback_addressing() -> None:
    assert extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1, #4]!")) == ()


def test_rejects_aarch64_register_offset_addressing() -> None:
    assert extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1, x2]")) == ()
