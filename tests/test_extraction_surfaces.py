from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.liveness import LivenessIndex
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

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    assert "missing_liveness_surface" in diagnostics.skip_reasons


def test_surface_inferer_skips_no_output_surface() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1",), ()),
        _inst("x86-64", 0x2000, ("rcx",), ()),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    assert "missing_liveness_surface" in diagnostics.skip_reasons


def test_surface_inferer_skips_ambiguous_register_counts() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1", "x2"), ("x0",)),
        _inst("x86-64", 0x2000, ("rcx",), ("rax",)),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    assert "missing_liveness_surface" in diagnostics.skip_reasons


def test_surface_inferer_skips_memory_access_window() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1",), ("x0",), mnemonic="ldr"),
        _inst("x86-64", 0x2000, ("rcx",), ("rax",), mnemonic="mov"),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    assert "unsupported_memory_surface" in diagnostics.skip_reasons


def test_surface_inferer_skips_x86_implicit_stack_memory() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1",), ("x0",), mnemonic="add"),
        _inst("x86-64", 0x2000, ("rcx",), ("rax",), mnemonic="push"),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    reasons = diagnostics.skip_reasons
    assert "unsupported_memory_surface" in reasons


def test_surface_inferer_skips_terminal_ret_or_call() -> None:
    diagnostics = MiningDiagnostics()

    # x86 ret
    pair = _pair(
        _inst("aarch64", 0x1000, (), (), mnemonic="ret"),
        _inst("x86-64", 0x2000, (), (), mnemonic="ret"),
    )
    assert SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair) is None

    # x86 call
    pair2 = _pair(
        _inst("aarch64", 0x1000, (), (), mnemonic="bl"),
        _inst("x86-64", 0x2000, (), (), mnemonic="call"),
    )
    assert SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair2) is None

    # AArch64 unconditional b
    pair3 = _pair(
        _inst("aarch64", 0x1000, (), (), mnemonic="b"),
        _inst("x86-64", 0x2000, (), (), mnemonic="jmp"),
    )
    assert SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair3) is None

    reasons = diagnostics.to_json()["skip_reasons"]
    assert reasons.get("unsupported_control_flow_surface", 0) >= 3


def test_surface_inferer_keeps_conditional_branch_candidate() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x0", "x1"), (), mnemonic="b.eq"),
        _inst("x86-64", 0x2000, ("rax", "rcx"), (), mnemonic="je"),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    assert "missing_liveness_surface" in diagnostics.skip_reasons


def test_surface_inferer_skips_aarch64_bl() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x0",), (), mnemonic="bl"),
        _inst("x86-64", 0x2000, ("rax",), ("rax",), mnemonic="mov"),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    reasons = diagnostics.to_json()["skip_reasons"]
    assert reasons.get("unsupported_control_flow_surface", 0) >= 1


def test_surface_inferer_skips_flag_register_surface() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1", "x2"), ("x0", "nzcv"), mnemonic="subs"),
        _inst("x86-64", 0x2000, ("rcx", "rdx"), ("rax", "rflags"), mnemonic="sub"),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    assert "missing_liveness_surface" in diagnostics.skip_reasons


def _mem_inst(
    arch: str,
    address: int,
    reads: tuple[str, ...],
    writes: tuple[str, ...],
    *,
    mnemonic: str = "add",
    op_str: str = "",
) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4 if arch == "aarch64" else 3,
        code_bytes=b"\x01" * (4 if arch == "aarch64" else 3),
        mnemonic=mnemonic,
        op_str=op_str,
        function="sample",
        source=SourceLocation("sample.c", 3),
        read_registers=reads,
        write_registers=writes,
    )


def _mem_pair(guest: ExtractedInstruction, host: ExtractedInstruction) -> WindowPair:
    return WindowPair(
        region_id="r0",
        stage=(1, 1),
        guest=InstructionWindow("r0", "guest", (guest,)),
        host=InstructionWindow("r0", "host", (host,)),
    )


def test_surface_inferer_rejects_unsupported_memory_both_sides() -> None:
    pair = _mem_pair(
        _mem_inst(
            "aarch64",
            0x1000,
            ("sp",),
            ("x0", "x1"),
            mnemonic="ldp",
            op_str="x0, x1, [sp]",
        ),
        _mem_inst(
            "x86-64",
            0x2000,
            ("rsp",),
            ("rsp",),
            mnemonic="push",
            op_str="rax",
        ),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    assert diagnostics.skip_reasons.get("unsupported_memory_surface", 0) >= 1


def test_surface_inferer_rejects_unsupported_x86_pop() -> None:
    pair = _mem_pair(
        _mem_inst(
            "aarch64",
            0x1000,
            ("x1",),
            ("x0",),
            mnemonic="add",
            op_str="x0, x1, x2",
        ),
        _mem_inst(
            "x86-64",
            0x2000,
            ("rsp",),
            ("rax", "rsp"),
            mnemonic="pop",
            op_str="rax",
        ),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    assert diagnostics.skip_reasons.get("unsupported_memory_surface", 0) >= 1


def test_surface_inferer_rejects_unsupported_x86_indexed_memory() -> None:
    pair = _mem_pair(
        _mem_inst(
            "aarch64",
            0x1000,
            ("x1", "x2"),
            ("x0",),
            mnemonic="add",
            op_str="x0, x1, x2",
        ),
        _mem_inst(
            "x86-64",
            0x2000,
            ("rcx", "rdx"),
            ("rax",),
            mnemonic="mov",
            op_str="eax, dword ptr [rcx + rdx*4]",
        ),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    assert diagnostics.skip_reasons.get("unsupported_memory_surface", 0) >= 1


def test_surface_inferer_still_emits_register_only_windows() -> None:
    pair = _mem_pair(
        _mem_inst(
            "aarch64",
            0x1000,
            ("x1", "x2"),
            ("x0",),
            mnemonic="add",
            op_str="x0, x1, x2",
        ),
        _mem_inst(
            "x86-64",
            0x2000,
            ("rcx", "rdx"),
            ("rax",),
            mnemonic="add",
            op_str="eax, ecx, edx",
        ),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    assert "unsupported_memory_surface" not in diagnostics.skip_reasons
    assert "missing_liveness_surface" in diagnostics.skip_reasons


def _multi_window_pair(
    guest_insts: tuple[ExtractedInstruction, ...],
    host_insts: tuple[ExtractedInstruction, ...],
) -> WindowPair:
    return WindowPair(
        region_id="r0",
        stage=(1, 1),
        guest=InstructionWindow("r0", "guest", guest_insts),
        host=InstructionWindow("r0", "host", host_insts),
    )


def test_surface_inferer_rejects_mixed_supported_unsupported_memory() -> None:
    pair = _multi_window_pair(
        (
            _mem_inst(
                "aarch64",
                0x1000,
                ("x1",),
                ("w0",),
                mnemonic="ldr",
                op_str="w0, [x1]",
            ),
            _mem_inst(
                "aarch64",
                0x1004,
                ("sp",),
                ("x2", "x3"),
                mnemonic="ldp",
                op_str="x2, x3, [sp]",
            ),
        ),
        (
            _mem_inst(
                "x86-64",
                0x2000,
                ("rcx",),
                ("eax",),
                mnemonic="mov",
                op_str="eax, dword ptr [rcx]",
            ),
            _mem_inst(
                "x86-64",
                0x2003,
                ("rsp",),
                ("rsp",),
                mnemonic="push",
                op_str="rax",
            ),
        ),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None, "mixed supported+unsupported memory must not emit"
    assert diagnostics.skip_reasons.get("unsupported_memory_surface", 0) >= 1
    assert diagnostics.windows_emitted == 0


def test_surface_inferer_rejects_post_index_addressing_surface() -> None:
    pair = _mem_pair(
        _mem_inst(
            "aarch64",
            0x1000,
            ("x1",),
            ("w0",),
            mnemonic="ldr",
            op_str="w0, [x1], #4",
        ),
        _mem_inst(
            "x86-64",
            0x2000,
            ("rcx",),
            ("eax",),
            mnemonic="mov",
            op_str="eax, dword ptr [rcx]",
        ),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    assert diagnostics.skip_reasons.get("unsupported_memory_surface", 0) >= 1
    assert diagnostics.windows_emitted == 0


def test_surface_inferer_rejects_pre_index_writeback_addressing_surface() -> None:
    pair = _mem_pair(
        _mem_inst(
            "aarch64",
            0x1000,
            ("x1",),
            ("w0", "x1"),
            mnemonic="ldr",
            op_str="w0, [x1, #4]!",
        ),
        _mem_inst(
            "x86-64",
            0x2000,
            ("rcx",),
            ("eax",),
            mnemonic="mov",
            op_str="eax, dword ptr [rcx]",
        ),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, LivenessIndex.empty()).infer(pair)

    assert candidate is None
    assert diagnostics.skip_reasons.get("unsupported_memory_surface", 0) >= 1
    assert diagnostics.windows_emitted == 0
