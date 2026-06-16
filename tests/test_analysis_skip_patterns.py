from angr_rule_learning.analysis.skip_patterns import (
    SkipPatternAggregator,
    instruction_text,
    normalize_instruction_text,
)
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    SourceLocation,
    WindowPair,
)


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


def _window(
    region_id: str,
    side: str,
    instructions: tuple[ExtractedInstruction, ...],
) -> InstructionWindow:
    return InstructionWindow(region_id=region_id, side=side, instructions=instructions)


def _pair(
    guest: tuple[ExtractedInstruction, ...],
    host: tuple[ExtractedInstruction, ...],
    *,
    stage: tuple[int, int] = (1, 1),
    region_id: str = "sample:sample.c:7:0",
) -> WindowPair:
    return WindowPair(
        region_id=region_id,
        stage=stage,
        guest=_window(region_id, "guest", guest),
        host=_window(region_id, "host", host),
    )


def test_aggregator_records_unparsed_instruction_pattern() -> None:
    aggregator = SkipPatternAggregator(max_examples=2)
    pair = _pair(
        (_inst("aarch64", "ldp", "x0, x1, [x2]"),),
        (_inst("x86-64", "mov", "rax, qword ptr [rcx]"),),
    )

    aggregator.record("unparsed_memory_access", pair)
    payload = aggregator.to_json()

    detail = payload["details"]["unparsed_memory_access"]
    assert detail["total"] == 1
    assert detail["by_arch_mnemonic"]["aarch64:ldp"] == 1
    assert detail["top_instruction_patterns"][0]["count"] >= 1
    assert detail["top_instruction_patterns"][0]["arch"] == "aarch64"
    assert detail["top_instruction_patterns"][0]["mnemonic"] == "ldp"
    assert detail["top_instruction_patterns"][0]["examples"][0]["function"] == "sample"


def test_aggregator_records_one_sided_window_pair_pattern() -> None:
    aggregator = SkipPatternAggregator(max_examples=2)
    pair = _pair(
        (_inst("aarch64", "str", "w0, [sp, #12]"),),
        (_inst("x86-64", "mov", "eax, edi"),),
        stage=(1, 1),
    )

    aggregator.record("one_sided_memory_access", pair)
    payload = aggregator.to_json()

    detail = payload["details"]["one_sided_memory_access"]
    assert detail["total"] == 1
    assert detail["by_stage"] == {"1x1": 1}
    top = detail["top_window_pairs"][0]
    assert top["guest_memory_count"] == 1
    assert top["host_memory_count"] == 0
    assert top["guest_pattern"] == "str w0, [sp, #IMM]"
    assert top["host_pattern"] == "mov eax, edi"
