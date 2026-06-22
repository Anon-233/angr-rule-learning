from angr_rule_learning.arch.memory import (
    extract_memory_operands,
    has_any_memory_access,
    stack_pointer_delta,
)
from angr_rule_learning.extraction.models import ExtractedInstruction


def _instruction(arch: str, mnemonic: str, op_str: str) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=0x1000,
        size=4,
        code_bytes=b"\x00\x00\x00\x00",
        mnemonic=mnemonic,
        op_str=op_str,
        function="test",
        source=None,
    )


def test_memory_facade_dispatches_by_canonical_architecture() -> None:
    arm = extract_memory_operands(_instruction("arm64", "ldr", "w0, [x1]"))
    x86 = extract_memory_operands(_instruction("amd64", "mov", "eax, dword ptr [rcx]"))

    assert arm[0].address.base == "x1"
    assert x86[0].address.base == "rcx"


def test_memory_facade_exposes_broad_detection_and_stack_delta() -> None:
    push = _instruction("x86-64", "push", "rbp")

    assert has_any_memory_access(push)
    assert stack_pointer_delta(push) == -8


def test_architecture_without_memory_recognizer_is_conservatively_unsupported() -> None:
    instruction = _instruction("arm", "ldr", "r0, [r1]")

    assert extract_memory_operands(instruction) == ()
    assert not has_any_memory_access(instruction)
    assert stack_pointer_delta(instruction) == 0
