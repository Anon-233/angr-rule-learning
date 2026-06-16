import claripy

from angr_rule_learning.verification.relations import RelationChecker


def test_relation_checker_passes_when_difference_is_unsat() -> None:
    x = claripy.BVS("x", 64)
    checker = RelationChecker(symbols={"x": x})

    result = checker.check_equal(
        kind="register",
        guest="x0",
        host="rax",
        guest_expr=x + 1,
        host_expr=x + 1,
        mismatch_reason="register_mismatch",
    )

    assert result.status == "pass"
    assert result.reason == ""


def test_relation_checker_fails_with_counterexample() -> None:
    x = claripy.BVS("x", 64)
    y = claripy.BVS("y", 64)
    checker = RelationChecker(symbols={"x": x, "y": y})

    result = checker.check_equal(
        kind="register",
        guest="x0",
        host="rax",
        guest_expr=x + y,
        host_expr=x,
        mismatch_reason="register_mismatch",
    )

    assert result.status == "fail"
    assert result.reason == "register_mismatch"
    assert "y" in result.counterexample


def test_relation_checker_aligns_widths() -> None:
    x32 = claripy.BVS("x32", 32)
    x64 = claripy.ZeroExt(32, x32)
    checker = RelationChecker(symbols={"x32": x32})

    result = checker.check_equal(
        kind="register",
        guest="w0",
        host="rax",
        guest_expr=x32,
        host_expr=x64,
        mismatch_reason="register_mismatch",
    )

    assert result.status == "pass"


def test_relation_checker_accepts_multiple_constraints() -> None:
    x = claripy.BVS("x", 32)
    y = claripy.BVS("y", 32)
    checker = RelationChecker(
        symbols={"x": x, "y": y},
        constraints=(x == 3, y == 4),
    )

    result = checker.check_equal(
        kind="register",
        guest="x_plus_y",
        host="seven",
        guest_expr=x + y,
        host_expr=claripy.BVV(7, 32),
        mismatch_reason="register_mismatch",
    )

    assert result.status == "pass"


def test_relation_checker_counterexample_with_multiple_constraints() -> None:
    x = claripy.BVS("x", 32)
    y = claripy.BVS("y", 32)
    checker = RelationChecker(
        symbols={"x": x, "y": y},
        constraints=(x == 3, y == 4),
    )

    result = checker.check_equal(
        kind="register",
        guest="x_plus_y",
        host="eight",
        guest_expr=x + y,
        host_expr=claripy.BVV(8, 32),
        mismatch_reason="register_mismatch",
    )

    assert result.status == "fail"
    assert result.reason == "register_mismatch"
    assert result.counterexample["x"] == 3
    assert result.counterexample["y"] == 4
