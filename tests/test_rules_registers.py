import pytest

from angr_rule_learning.rules.registers import (
    RegisterClass,
    RegisterClassError,
    UnsupportedRegisterClass,
    classify_register,
    is_allowed_literal_register,
    known_register_tokens,
)


def test_classifies_aarch64_integer_register_widths() -> None:
    assert classify_register("aarch64", "w0") == RegisterClass("i", 32)
    assert classify_register("aarch64", "x0") == RegisterClass("i", 64)
    assert classify_register("aarch64", "lr") == RegisterClass("i", 64)


def test_classifies_x86_64_integer_subregister_widths() -> None:
    assert classify_register("x86-64", "al") == RegisterClass("i", 8)
    assert classify_register("x86-64", "ax") == RegisterClass("i", 16)
    assert classify_register("x86-64", "eax") == RegisterClass("i", 32)
    assert classify_register("x86-64", "rax") == RegisterClass("i", 64)
    assert classify_register("x86-64", "r8d") == RegisterClass("i", 32)
    assert classify_register("x86-64", "r15") == RegisterClass("i", 64)


def test_normalizes_project_arch_names_for_archinfo() -> None:
    assert classify_register("amd64", "edi") == classify_register("x86-64", "edi")
    assert classify_register("aarch64", "X8") == RegisterClass("i", 64)


def test_stack_pointer_placeholder_names() -> None:
    from angr_rule_learning.rules.registers import stack_pointer_placeholder

    assert stack_pointer_placeholder("aarch64", "sp") == "sp64"
    assert stack_pointer_placeholder("aarch64", "wsp") == "sp32"
    assert stack_pointer_placeholder("x86-64", "rsp") == "sp64"
    assert stack_pointer_placeholder("x86-64", "esp") == "sp32"
    assert stack_pointer_placeholder("x86-64", "rbp") is None


def test_frame_registers_remain_literals() -> None:
    for reg in ("fp", "rbp", "ebp", "bp"):
        arch = "aarch64" if reg == "fp" else "x86-64"
        assert is_allowed_literal_register(arch, reg)
        with pytest.raises(RegisterClassError):
            classify_register(arch, reg)


def test_stack_pointer_is_allowed_literal() -> None:
    for reg in ("sp", "wsp", "rsp", "esp"):
        arch = "aarch64" if reg in ("sp", "wsp") else "x86-64"
        assert is_allowed_literal_register(arch, reg)
        with pytest.raises(RegisterClassError):
            classify_register(arch, reg)


def test_zero_registers_are_literals_not_classified_operands() -> None:
    assert is_allowed_literal_register("aarch64", "xzr")
    assert is_allowed_literal_register("aarch64", "wzr")
    with pytest.raises(RegisterClassError, match="unknown register"):
        classify_register("aarch64", "xzr")


def test_unknown_registers_raise_unknown_class_error() -> None:
    with pytest.raises(RegisterClassError, match="unknown register"):
        classify_register("aarch64", "notareg")


def test_float_and_vector_registers_are_explicitly_unsupported() -> None:
    with pytest.raises(UnsupportedRegisterClass, match="unsupported register class"):
        classify_register("aarch64", "v0")
    with pytest.raises(UnsupportedRegisterClass, match="unsupported register class"):
        classify_register("x86-64", "xmm0")


def test_known_register_tokens_include_subregisters_and_literals() -> None:
    aarch64 = known_register_tokens("aarch64")
    x86_64 = known_register_tokens("x86-64")

    assert {"w0", "x0", "xzr", "wzr", "sp", "lr"}.issubset(aarch64)
    assert {"al", "eax", "rax", "r8d", "r15"}.issubset(x86_64)


def test_register_class_placeholder_prefix() -> None:
    assert RegisterClass("i", 32).placeholder_prefix == "i32"
