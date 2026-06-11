from angr_rule_learning.extraction.liveness import (
    abi_exit_live_out,
    families_for_registers,
    family_for_register,
    is_condition_family,
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
