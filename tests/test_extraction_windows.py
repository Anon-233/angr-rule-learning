from angr_rule_learning.extraction.config import WindowLimits
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.models import (
    AlignmentRegion,
    ExtractedInstruction,
    SourceLocation,
)
from angr_rule_learning.extraction.windows import VerifiedWindowSet, WindowMiner


def _inst(arch: str, address: int, index: int) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4 if arch == "aarch64" else 1,
        code_bytes=bytes([index]) * (4 if arch == "aarch64" else 1),
        mnemonic="add",
        op_str="",
        function="f",
        source=SourceLocation("sample.c", 3),
    )


def _region() -> AlignmentRegion:
    return AlignmentRegion(
        region_id="r0",
        function="f",
        source_file="sample.c",
        source_lines=(3,),
        guest_instructions=(
            _inst("aarch64", 0x1000, 1),
            _inst("aarch64", 0x1004, 2),
        ),
        host_instructions=(
            _inst("x86-64", 0x2000, 3),
            _inst("x86-64", 0x2001, 4),
            _inst("x86-64", 0x2002, 5),
        ),
    )


def test_window_miner_enumerates_in_stage_order() -> None:
    diagnostics = MiningDiagnostics()
    windows = WindowMiner(WindowLimits(), diagnostics).enumerate_region(_region())

    assert windows[0].stage == (1, 1)
    assert windows[0].guest.instruction_count == 1
    assert windows[0].host.instruction_count == 1
    assert (1, 3) in [window.stage for window in windows]
    assert (2, 3) in [window.stage for window in windows]
    assert diagnostics.to_json()["windows_enumerated"] == len(windows)


def test_verified_window_set_detects_composite_coverage() -> None:
    windows = WindowMiner(WindowLimits(), MiningDiagnostics()).enumerate_region(
        _region()
    )
    first = next(
        window
        for window in windows
        if window.guest.instruction_count == 1 and window.host.instruction_count == 1
    )
    second = next(
        window
        for window in windows
        if window.guest.instructions[0].address == 0x1004
        and window.host.instructions[0].address == 0x2001
        and window.guest.instruction_count == 1
        and window.host.instruction_count == 1
    )
    large = next(
        window
        for window in windows
        if window.guest.instruction_count == 2
        and window.host.instruction_count == 2
        and window.host.instructions[0].address == 0x2000
    )
    verified = VerifiedWindowSet()

    verified.add(first)
    verified.add(second)

    assert verified.covers(large)


def test_window_miner_prunes_verified_composites() -> None:
    region = _region()
    diagnostics = MiningDiagnostics()
    miner = WindowMiner(WindowLimits(), diagnostics)
    windows = miner.enumerate_region(region)
    verified = VerifiedWindowSet()
    for window in windows:
        if window.stage == (1, 1):
            verified.add(window)

    pruned = miner.prune_composites(windows, verified)

    assert all(
        not verified.covers(window) for window in pruned if window.stage != (1, 1)
    )
    assert diagnostics.to_json()["skip_reasons"]["subsumed_by_smaller_window"] > 0
