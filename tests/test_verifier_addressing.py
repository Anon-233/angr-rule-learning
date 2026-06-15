import pytest

from angr_rule_learning.verification.addressing import (
    AddressExpr,
    parse_address_binding,
)


def test_address_expr_canonical_base_only() -> None:
    expr = AddressExpr(base="X1")

    assert expr.base == "x1"
    assert expr.index is None
    assert expr.scale == 1
    assert expr.displacement == 0
    assert expr.canonical() == "x1"
    assert expr.registers() == ("x1",)


def test_address_expr_canonical_indexed_with_displacement() -> None:
    expr = AddressExpr(base="RCX", index="RDX", scale=4, displacement=8)

    assert expr.canonical() == "rcx + rdx * 4 + 8"
    assert expr.registers() == ("rcx", "rdx")


def test_address_expr_canonical_negative_displacement() -> None:
    expr = AddressExpr(base="x1", index="x2", scale=4, displacement=-16)

    assert expr.canonical() == "x1 + x2 * 4 - 16"


def test_parse_address_binding_base_plus_index_scale_disp() -> None:
    expr = parse_address_binding("rcx + rdx * 4 + 8")

    assert expr == AddressExpr(base="rcx", index="rdx", scale=4, displacement=8)


def test_parse_address_binding_accepts_legacy_base_plus_offset() -> None:
    expr = parse_address_binding("x1 + 4")

    assert expr == AddressExpr(base="x1", displacement=4)


def test_parse_address_binding_rejects_no_base_first_iteration() -> None:
    with pytest.raises(ValueError, match="unsupported address expression"):
        parse_address_binding("rdx * 4 + 8")


def test_address_expr_rejects_invalid_scale_without_index() -> None:
    with pytest.raises(ValueError, match="scale requires index"):
        AddressExpr(base="x1", scale=4)


def test_address_expr_rejects_invalid_x86_scale() -> None:
    with pytest.raises(ValueError, match="unsupported address scale"):
        AddressExpr(base="rcx", index="rdx", scale=3)
