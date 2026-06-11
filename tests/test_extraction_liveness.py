from angr_rule_learning.extraction.liveness import (
    LivenessAnalyzer,
    abi_exit_live_out,
    families_for_registers,
    family_for_register,
    is_condition_family,
)
from angr_rule_learning.extraction.models import (
    ExtractedFunction,
    ExtractedInstruction,
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
