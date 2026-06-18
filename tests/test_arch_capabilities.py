import pytest

from angr_rule_learning.arch.registry import canonical_arch_name, clang_target


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
