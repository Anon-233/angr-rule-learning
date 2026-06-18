import pytest

from angr_rule_learning.arch.registry import canonical_arch_name, clang_target
from angr_rule_learning.arch.registers import (
    fixed_role_preserve_register,
    is_compatible_frame_base_pair,
    is_fixed_role_register,
    is_stack_pointer,
    register_bit_range,
    register_family,
)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("AARCH64", "aarch64"),
        ("arm64", "aarch64"),
        ("AMD64", "x86-64"),
        ("x86_64", "x86-64"),
    ],
)
def test_canonical_arch_name_normalizes_supported_aliases(
    name: str, expected: str
) -> None:
    assert canonical_arch_name(name) == expected


def test_clang_target_is_selected_by_architecture() -> None:
    assert clang_target("aarch64") == "aarch64-linux-gnu"
    assert clang_target("amd64") == "x86_64-linux-gnu"


def test_unknown_architecture_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported architecture"):
        canonical_arch_name("made-up-isa")


def test_register_capabilities_are_selected_by_explicit_architecture() -> None:
    assert register_family("aarch64", "w8") == "x8"
    assert register_family("x86-64", "eax") == "rax"
    assert register_bit_range("aarch64", "w8") == (0, 31)
    assert register_bit_range("x86-64", "ch") == (8, 15)
    assert is_fixed_role_register("x86-64", "cl")
    assert not is_fixed_role_register("aarch64", "w1")
    assert fixed_role_preserve_register("x86-64", "ecx") == "rcx"


def test_frame_base_compatibility_is_symmetric() -> None:
    forward = is_compatible_frame_base_pair("aarch64", "sp", "x86-64", "rbp")
    reverse = is_compatible_frame_base_pair("x86-64", "rbp", "aarch64", "sp")

    assert forward
    assert reverse


def test_frame_base_compatibility_requires_equal_address_widths() -> None:
    assert not is_compatible_frame_base_pair("aarch64", "sp", "x86-64", "ebp")


def test_missing_address_base_is_not_a_stack_pointer() -> None:
    assert not is_stack_pointer("x86-64", None)
