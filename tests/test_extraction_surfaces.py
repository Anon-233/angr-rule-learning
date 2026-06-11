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


def test_surface_inferer_skips_memory_access_window() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1",), ("x0",), mnemonic="ldr"),
        _inst("x86-64", 0x2000, ("rcx",), ("rax",), mnemonic="mov"),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics).infer(pair)

    assert candidate is None
    assert diagnostics.to_json()["skip_reasons"] == {"unsupported_memory_surface": 1}


def test_surface_inferer_skips_x86_implicit_stack_memory() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1",), ("x0",), mnemonic="add"),
        _inst("x86-64", 0x2000, ("rcx",), ("rax",), mnemonic="push"),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics).infer(pair)

    assert candidate is None
    reasons = diagnostics.to_json()["skip_reasons"]
    assert reasons.get("unsupported_memory_surface", 0) >= 1


def test_surface_inferer_skips_terminal_ret_or_call() -> None:
    diagnostics = MiningDiagnostics()

    # x86 ret
    pair = _pair(
        _inst("aarch64", 0x1000, (), (), mnemonic="ret"),
        _inst("x86-64", 0x2000, (), (), mnemonic="ret"),
    )
    assert SurfaceInferer(diagnostics).infer(pair) is None

    # x86 call
    pair2 = _pair(
        _inst("aarch64", 0x1000, (), (), mnemonic="bl"),
        _inst("x86-64", 0x2000, (), (), mnemonic="call"),
    )
    assert SurfaceInferer(diagnostics).infer(pair2) is None

    # AArch64 unconditional b
    pair3 = _pair(
        _inst("aarch64", 0x1000, (), (), mnemonic="b"),
        _inst("x86-64", 0x2000, (), (), mnemonic="jmp"),
    )
    assert SurfaceInferer(diagnostics).infer(pair3) is None

    reasons = diagnostics.to_json()["skip_reasons"]
    assert reasons.get("unsupported_control_flow_surface", 0) >= 3


def test_surface_inferer_keeps_conditional_branch_candidate() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x0", "x1"), (), mnemonic="b.eq"),
        _inst("x86-64", 0x2000, ("rax", "rcx"), (), mnemonic="je"),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics).infer(pair)

    assert candidate is not None
    assert candidate.output_registers == ()
    assert diagnostics.to_json()["surface_kinds"].get("branch", 0) == 1


def test_surface_inferer_skips_aarch64_bl() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x0",), (), mnemonic="bl"),
        _inst("x86-64", 0x2000, ("rax",), ("rax",), mnemonic="mov"),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics).infer(pair)

    assert candidate is None
    reasons = diagnostics.to_json()["skip_reasons"]
    assert reasons.get("unsupported_control_flow_surface", 0) >= 1


def test_surface_inferer_skips_flag_register_surface() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1", "x2"), ("x0", "nzcv"), mnemonic="subs"),
        _inst("x86-64", 0x2000, ("rcx", "rdx"), ("rax", "rflags"), mnemonic="sub"),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics).infer(pair)

    assert candidate is None
    assert diagnostics.to_json()["skip_reasons"] == {"unsupported_flag_surface": 1}
