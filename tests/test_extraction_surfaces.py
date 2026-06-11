from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    SourceLocation,
    WindowPair,
)
from angr_rule_learning.extraction.surfaces import SurfaceInferer


def _inst(
    arch: str,
    address: int,
    reads: tuple[str, ...],
    writes: tuple[str, ...],
    mnemonic: str = "add",
) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4 if arch == "aarch64" else 3,
        code_bytes=b"\x01" * (4 if arch == "aarch64" else 3),
        mnemonic=mnemonic,
        op_str="",
        function="add",
        source=SourceLocation("sample.c", 3),
        read_registers=reads,
        write_registers=writes,
    )


def _pair(guest: ExtractedInstruction, host: ExtractedInstruction) -> WindowPair:
    return WindowPair(
        region_id="r0",
        stage=(1, 1),
        guest=InstructionWindow("r0", "guest", (guest,)),
        host=InstructionWindow("r0", "host", (host,)),
    )


def test_surface_inferer_pairs_register_reads_and_writes() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1", "x2"), ("x0",)),
        _inst("x86-64", 0x2000, ("rcx", "rdx"), ("rax",)),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics).infer(pair)

    assert candidate is not None
    assert candidate.input_registers == (("x1", "rcx"), ("x2", "rdx"))
    assert candidate.output_registers == (("x0", "rax"),)
    assert candidate.guest.code_hex == "01010101"
    assert candidate.host.code_hex == "010101"


def test_surface_inferer_skips_no_output_surface() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1",), ()),
        _inst("x86-64", 0x2000, ("rcx",), ()),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics).infer(pair)

    assert candidate is None
    assert diagnostics.to_json()["skip_reasons"] == {"no_verifiable_surface": 1}


def test_surface_inferer_skips_ambiguous_register_counts() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1", "x2"), ("x0",)),
        _inst("x86-64", 0x2000, ("rcx",), ("rax",)),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics).infer(pair)

    assert candidate is None
    assert diagnostics.to_json()["skip_reasons"] == {"ambiguous_register_surface": 1}
