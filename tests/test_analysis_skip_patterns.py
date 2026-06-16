from angr_rule_learning.analysis.skip_patterns import (
    instruction_text,
    normalize_instruction_text,
)
from angr_rule_learning.extraction.models import ExtractedInstruction, SourceLocation


def _inst(
    arch: str,
    mnemonic: str,
    op_str: str,
    *,
    address: int = 0x1000,
) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic=mnemonic,
        op_str=op_str,
        function="sample",
        source=SourceLocation("sample.c", 7),
    )


def test_instruction_text_joins_mnemonic_and_operands() -> None:
    assert instruction_text(_inst("aarch64", "ldr", "w0, [x1]")) == "ldr w0, [x1]"
    assert instruction_text(_inst("aarch64", "ret", "")) == "ret"


def test_normalize_instruction_text_replaces_numbers_and_spacing() -> None:
    text = normalize_instruction_text("  mov   dword ptr [rbp - 0xc],  13 ")

    assert text == "mov dword ptr [rbp - IMM], IMM"
