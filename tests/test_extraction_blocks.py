from angr_rule_learning.extraction.blocks import is_control_flow


def test_aarch64_control_flow_does_not_match_all_b_prefix_instructions() -> None:
    assert not is_control_flow("aarch64", "bic")
    assert not is_control_flow("aarch64", "bfi")
    assert is_control_flow("aarch64", "b")
    assert is_control_flow("aarch64", "bl")
    assert is_control_flow("aarch64", "b.eq")
    assert is_control_flow("aarch64", "cbz")


def test_x86_control_flow_recognizes_jump_family() -> None:
    assert not is_control_flow("x86-64", "imul")
    assert is_control_flow("x86-64", "jmp")
    assert is_control_flow("x86-64", "jne")
    assert is_control_flow("x86-64", "call")
    assert is_control_flow("x86-64", "int3")
    assert is_control_flow("x86-64", "retf")
