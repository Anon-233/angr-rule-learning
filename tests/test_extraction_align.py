from angr_rule_learning.extraction.align import AlignmentRegionBuilder
from angr_rule_learning.extraction.blocks import BasicBlockBuilder
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.models import (
    BasicBlock,
    ExtractedFunction,
    ExtractedInstruction,
    SourceLocation,
)


def _inst(arch: str, address: int, mnemonic: str, line: int) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4 if arch == "aarch64" else 1,
        code_bytes=b"\x00" * (4 if arch == "aarch64" else 1),
        mnemonic=mnemonic,
        op_str="",
        function="add",
        source=SourceLocation("sample.c", line),
    )


def test_basic_block_builder_splits_after_control_flow() -> None:
    function = ExtractedFunction(
        arch="aarch64",
        name="add",
        address=0x1000,
        size=12,
        instructions=(
            _inst("aarch64", 0x1000, "cmp", 3),
            _inst("aarch64", 0x1004, "b.eq", 3),
            _inst("aarch64", 0x1008, "add", 4),
        ),
    )

    blocks = BasicBlockBuilder().build(function)

    assert len(blocks) == 2
    assert [inst.mnemonic for inst in blocks[0].instructions] == ["cmp", "b.eq"]
    assert [inst.mnemonic for inst in blocks[1].instructions] == ["add"]


def test_alignment_pairs_same_function_and_source_span() -> None:
    guest_block = BasicBlock(
        "g0", "aarch64", "add", (_inst("aarch64", 0x1000, "add", 3),)
    )
    host_block = BasicBlock("h0", "x86-64", "add", (_inst("x86-64", 0x2000, "lea", 3),))
    diagnostics = MiningDiagnostics()

    regions = AlignmentRegionBuilder(diagnostics).build((guest_block,), (host_block,))

    assert len(regions) == 1
    assert regions[0].region_id == "add:sample.c:3:0"
    assert regions[0].guest_instructions == guest_block.instructions
    assert regions[0].host_instructions == host_block.instructions


def test_alignment_skips_ambiguous_block_counts() -> None:
    guest_blocks = (
        BasicBlock("g0", "aarch64", "add", (_inst("aarch64", 0x1000, "add", 3),)),
        BasicBlock("g1", "aarch64", "add", (_inst("aarch64", 0x1004, "sub", 3),)),
    )
    host_blocks = (
        BasicBlock(
            "h0",
            "x86-64",
            "add",
            (_inst("x86-64", 0x2000, "lea", 3),),
        ),
    )
    diagnostics = MiningDiagnostics()

    regions = AlignmentRegionBuilder(diagnostics).build(guest_blocks, host_blocks)

    assert regions == ()
    assert diagnostics.to_json()["skip_reasons"] == {"ambiguous_alignment_region": 1}
