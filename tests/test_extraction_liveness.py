from angr_rule_learning.extraction.liveness import (
    LivenessAnalyzer,
    WindowSurfaceInferer,
    abi_exit_live_out,
    families_for_registers,
    family_for_register,
    is_condition_family,
)
from angr_rule_learning.extraction.models import (
    ExtractedFunction,
    ExtractedInstruction,
    InstructionWindow,
)


def test_aarch64_integer_aliases_share_family() -> None:
    assert family_for_register("aarch64", "w0") == "x0"
    assert family_for_register("aarch64", "x0") == "x0"
    assert family_for_register("aarch64", "fp") == "x29"
    assert family_for_register("aarch64", "lr") == "x30"
    assert family_for_register("aarch64", "sp") == "sp"


def test_x86_64_subregister_aliases_share_family() -> None:
    expected = "rax"
    for register in ("al", "ah", "ax", "eax", "rax"):
        assert family_for_register("x86-64", register) == expected
    assert family_for_register("x86-64", "r8b") == "r8"
    assert family_for_register("x86-64", "r8w") == "r8"
    assert family_for_register("x86-64", "r8d") == "r8"
    assert family_for_register("x86-64", "r8") == "r8"


def test_condition_code_families_are_normalized() -> None:
    assert family_for_register("aarch64", "nzcv") == "nzcv"
    assert family_for_register("x86-64", "rflags") == "rflags"
    assert family_for_register("x86-64", "zf") == "rflags"
    assert family_for_register("x86-64", "cf") == "rflags"
    assert is_condition_family("aarch64", "nzcv")
    assert is_condition_family("x86-64", "rflags")
    assert not is_condition_family("x86-64", "rax")


def test_families_for_registers_preserves_first_use_order() -> None:
    assert families_for_registers("x86-64", ("eax", "al", "ecx", "rflags")) == (
        "rax",
        "rcx",
        "rflags",
    )


def test_aarch64_zero_registers_are_not_live_register_families() -> None:
    assert families_for_registers("aarch64", ("wzr", "xzr", "w0")) == ("x0",)


def test_abi_exit_live_out_includes_return_and_callee_saved() -> None:
    assert abi_exit_live_out("aarch64") == frozenset(
        {
            "x0",
            "x19",
            "x20",
            "x21",
            "x22",
            "x23",
            "x24",
            "x25",
            "x26",
            "x27",
            "x28",
            "x29",
            "x30",
            "sp",
        }
    )
    assert abi_exit_live_out("x86-64") == frozenset(
        {"rax", "rbx", "rbp", "r12", "r13", "r14", "r15", "rsp"}
    )


def _inst(
    address: int,
    mnemonic: str,
    op_str: str = "",
    *,
    arch: str = "x86-64",
    reads: tuple[str, ...] = (),
    writes: tuple[str, ...] = (),
) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4,
        code_bytes=b"\x90\x90\x90\x90",
        mnemonic=mnemonic,
        op_str=op_str,
        function="f",
        source=None,
        read_registers=reads,
        write_registers=writes,
    )


def _function(
    instructions: tuple[ExtractedInstruction, ...],
    *,
    arch: str = "x86-64",
) -> ExtractedFunction:
    return ExtractedFunction(
        arch=arch,
        name="f",
        address=instructions[0].address,
        size=sum(inst.size for inst in instructions),
        instructions=instructions,
    )


def test_linear_liveness_keeps_return_value_live_at_exit() -> None:
    function = _function(
        (
            _inst(
                0x1000,
                "add",
                "eax, ecx",
                reads=("eax", "ecx"),
                writes=("eax", "rflags"),
            ),
            _inst(0x1004, "ret"),
        )
    )

    index = LivenessAnalyzer().analyze((function,))
    add = index.for_instruction(function.instructions[0])
    ret = index.for_instruction(function.instructions[1])

    assert add.reads == ("rax", "rcx")
    assert add.writes == ("rax", "rflags")
    assert "rax" in add.live_out
    assert "rflags" not in add.live_out
    assert "rax" in ret.live_out
    assert {"rbx", "rbp", "r12", "r13", "r14", "r15", "rsp"}.issubset(ret.live_out)


def test_conditional_branch_merges_target_and_fallthrough_liveness() -> None:
    function = _function(
        (
            _inst(
                0x1000,
                "cmp",
                "eax, ecx",
                reads=("eax", "ecx"),
                writes=("rflags",),
            ),
            _inst(0x1004, "jl", "0x1010", reads=("rflags",)),
            _inst(0x1008, "mov", "eax, 1", writes=("eax",)),
            _inst(0x100C, "ret"),
            _inst(0x1010, "mov", "eax, 2", writes=("eax",)),
            _inst(0x1014, "ret"),
        )
    )

    index = LivenessAnalyzer().analyze((function,))
    cmp_inst = index.for_instruction(function.instructions[0])
    branch = index.for_instruction(function.instructions[1])

    assert branch.successor_addresses == (0x1010, 0x1008)
    assert "rflags" in cmp_inst.live_out
    assert "rflags" in branch.live_in
    assert "rax" not in branch.live_out


def test_aarch64_return_liveness_uses_return_and_callee_saved_seed() -> None:
    function = _function(
        (
            _inst(
                0x4000,
                "add",
                "w0, w0, w1",
                arch="aarch64",
                reads=("w0", "w1"),
                writes=("w0", "nzcv"),
            ),
            _inst(0x4004, "ret", arch="aarch64"),
        ),
        arch="aarch64",
    )

    index = LivenessAnalyzer().analyze((function,))
    add = index.for_instruction(function.instructions[0])

    assert "x0" in add.live_out
    assert "nzcv" not in add.live_out
    assert {"x19", "x28", "x29", "x30", "sp"}.issubset(
        index.for_instruction(function.instructions[1]).live_out
    )


def _window(
    instructions: tuple[ExtractedInstruction, ...], side: str = "host"
) -> InstructionWindow:
    return InstructionWindow("r1", side, instructions)


def test_window_surface_ignores_dead_flag_write() -> None:
    function = _function(
        (
            _inst(
                0x1000,
                "add",
                "eax, ecx",
                reads=("eax", "ecx"),
                writes=("eax", "rflags"),
            ),
            _inst(0x1004, "ret"),
        )
    )
    index = LivenessAnalyzer().analyze((function,))

    surface = WindowSurfaceInferer(index).infer(_window((function.instructions[0],)))

    assert surface.skip_reason is None
    assert surface.outputs == ("eax",)
    assert surface.output_families == ("rax",)
    assert surface.inputs == ("eax", "ecx")
    assert surface.input_families == ("rax", "rcx")
    assert surface.kind == "register"


def test_window_surface_rejects_external_live_condition_code_dependency() -> None:
    function = _function(
        (
            _inst(0x1000, "jl", "0x1008", reads=("rflags",)),
            _inst(0x1004, "mov", "eax, 1", writes=("eax",)),
            _inst(0x1008, "ret"),
        )
    )
    index = LivenessAnalyzer().analyze((function,))

    surface = WindowSurfaceInferer(index).infer(_window((function.instructions[0],)))

    assert surface.skip_reason == "external_live_condition_code_dependency"


def test_window_surface_keeps_local_compare_and_branch() -> None:
    function = _function(
        (
            _inst(
                0x1000,
                "cmp",
                "eax, ecx",
                reads=("eax", "ecx"),
                writes=("rflags",),
            ),
            _inst(0x1004, "jl", "0x100C", reads=("rflags",)),
            _inst(0x1008, "mov", "eax, 1", writes=("eax",)),
            _inst(0x100C, "ret"),
        )
    )
    index = LivenessAnalyzer().analyze((function,))

    surface = WindowSurfaceInferer(index).infer(
        _window((function.instructions[0], function.instructions[1]))
    )

    assert surface.skip_reason is None
    assert surface.kind == "branch"
    assert surface.outputs == ()
    assert surface.inputs == ("eax", "ecx")
    assert surface.input_families == ("rax", "rcx")


def test_window_surface_reports_no_verifiable_surface_for_dead_write() -> None:
    function = _function(
        (
            _inst(0x1000, "mov", "ecx, 1", writes=("ecx",)),
            _inst(0x1004, "ret"),
        )
    )
    index = LivenessAnalyzer().analyze((function,))

    surface = WindowSurfaceInferer(index).infer(_window((function.instructions[0],)))

    assert surface.skip_reason == "no_verifiable_surface"


def test_call_site_reads_argument_registers_and_writes_return_register() -> None:
    function = _function(
        (
            _inst(0x1000, "mov", "edi, 9", writes=("edi",)),
            _inst(0x1003, "call", "0x1100"),
            _inst(0x1008, "add", "eax, eax", reads=("eax",), writes=("eax", "rflags")),
            _inst(0x100B, "ret"),
        )
    )

    index = LivenessAnalyzer().analyze((function,))
    call_entry = index.for_instruction(function.instructions[1])

    # Argument registers should be live-in at the call site
    assert "rdi" in call_entry.live_in, (
        "rdi (argument register) must be live at call site"
    )
    # return register should be written (killed) at the call site
    assert "rax" in call_entry.writes, (
        "rax (return register) must be in call site writes"
    )


def test_aarch64_bl_implicit_parameter_register_liveness() -> None:
    function = _function(
        (
            _inst(
                0x4000,
                "mov",
                "w0, #9",
                arch="aarch64",
                writes=("w0",),
            ),
            _inst(0x4004, "bl", "0x5000", arch="aarch64"),
            _inst(0x4008, "ret", arch="aarch64"),
        ),
        arch="aarch64",
    )

    index = LivenessAnalyzer().analyze((function,))
    mov_entry = index.for_instruction(function.instructions[0])

    # mov w0, #9 is a parameter setup before a call — w0/x0 should be live
    assert "x0" in mov_entry.live_out, (
        "x0 must be live after mov w0, #9 (used by bl as argument)"
    )
