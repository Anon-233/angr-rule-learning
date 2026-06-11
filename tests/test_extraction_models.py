from pathlib import Path

from angr_rule_learning.extraction.config import (
    CompileOptions,
    ExtractionConfig,
    WindowLimits,
)
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    SourceLocation,
)


def test_window_limits_default_stage_order() -> None:
    limits = WindowLimits()

    assert limits.guest_min == 1
    assert limits.guest_max == 2
    assert limits.host_min == 1
    assert limits.host_max == 3
    assert limits.stage_order() == (
        (1, 1),
        (1, 2),
        (2, 1),
        (1, 3),
        (2, 2),
        (2, 3),
    )


def test_extraction_config_defaults() -> None:
    config = ExtractionConfig(source=Path("sample.c"), work_dir=Path("build/extract"))

    assert config.source == Path("sample.c")
    assert config.work_dir == Path("build/extract")
    assert config.guest_arch == "aarch64"
    assert config.host_arch == "x86-64"
    assert config.compile_options.optimization == "0"
    assert config.compile_options.command_flags_for_side("guest") == (
        "-g",
        "-O0",
        "-ffreestanding",
        "-fno-builtin",
    )
    assert config.window_limits.stage_order()[0] == (1, 1)


def test_compile_options_exposes_side_specific_flags() -> None:
    options = CompileOptions(
        clang="custom-clang",
        optimization="g",
        common_flags=("-ffreestanding",),
        guest_flags=("-mstrict-align",),
        host_flags=("-mno-red-zone",),
    )

    assert options.clang == "custom-clang"
    assert options.command_flags_for_side("guest") == (
        "-g",
        "-Og",
        "-ffreestanding",
        "-mstrict-align",
    )
    assert options.command_flags_for_side("host") == (
        "-g",
        "-Og",
        "-ffreestanding",
        "-mno-red-zone",
    )


def test_instruction_window_properties() -> None:
    inst = ExtractedInstruction(
        arch="aarch64",
        address=0x1000,
        size=4,
        code_bytes=bytes.fromhex("2000028b"),
        mnemonic="add",
        op_str="x0, x1, x2",
        function="add3",
        source=SourceLocation("sample.c", 3),
        read_registers=("x1", "x2"),
        write_registers=("x0",),
        groups=(),
    )
    window = InstructionWindow(region_id="r0", side="guest", instructions=(inst,))

    assert window.instruction_count == 1
    assert window.code_hex == "2000028b"
    assert window.address == 0x1000
    assert window.source_span == "sample.c:3"


def test_mining_diagnostics_records_windows_and_skips() -> None:
    diagnostics = MiningDiagnostics()

    diagnostics.record_region()
    diagnostics.record_region_skipped("ambiguous_alignment_region")
    diagnostics.record_window_enumerated(guest_size=1, host_size=2)
    diagnostics.record_window_emitted(
        guest_size=1, host_size=2, surface_kinds=("register",)
    )
    diagnostics.record_window_verified(status="pass")
    diagnostics.record_window_skipped("no_verifiable_surface")

    payload = diagnostics.to_json()

    assert payload["regions"] == 1
    assert payload["regions_skipped"] == 1
    assert payload["windows_enumerated"] == 1
    assert payload["windows_emitted"] == 1
    assert payload["windows_verified"] == 1
    assert payload["windows_verified_pass"] == 1
    assert payload["mean_guest_window_size"] == 1
    assert payload["mean_host_window_size"] == 2
    assert payload["skip_reasons"] == {
        "ambiguous_alignment_region": 1,
        "no_verifiable_surface": 1,
    }
    assert payload["surface_kinds"] == {"register": 1}
