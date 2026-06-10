import pytest

from angr_rule_learning.io.schema import report_to_json
from angr_rule_learning.verification.batch import BatchVerifier
from angr_rule_learning.verification.report import CheckResult, VerificationReport


def test_check_result_preserves_json_metadata() -> None:
    check = CheckResult(
        kind="memory",
        status="fail",
        guest="mem0",
        host="mem0",
        reason="memory_address_mismatch",
        counterexample={"x1": 0x70000004},
        metadata={"event_index": 0, "width": 4, "address": "x1 + 4"},
    )

    assert check.metadata["event_index"] == 0
    assert check.metadata["width"] == 4


def test_report_supports_error_status_without_equivalence() -> None:
    report = VerificationReport(
        candidate_id="bad",
        status="error",
        checks=(
            CheckResult(
                kind="execution",
                status="error",
                guest="guest",
                host="host",
                reason="angr_execution_error",
                metadata={"detail": "boom"},
            ),
        ),
    )

    assert not report.equivalent
    assert report.failure_reasons == {"angr_execution_error": 1}
    assert report_to_json(report)["checks"][0]["metadata"] == {"detail": "boom"}


def test_report_rejects_unknown_status() -> None:
    with pytest.raises(ValueError, match="unsupported report status"):
        VerificationReport(candidate_id="bad", status="maybe")


def test_batch_summary_counts_by_kind_and_top_reasons() -> None:
    reports = [
        VerificationReport(
            candidate_id="r0",
            status="fail",
            checks=(
                CheckResult(
                    "register",
                    "fail",
                    "x0",
                    "rax",
                    reason="register_mismatch",
                ),
            ),
        ),
        VerificationReport(
            candidate_id="r1",
            status="unsupported",
            checks=(
                CheckResult(
                    "flag",
                    "unsupported",
                    "nzcv.p",
                    "pf",
                    reason="unsupported_flag",
                ),
            ),
        ),
    ]

    summary = BatchVerifier.summarize(reports).to_json()

    assert summary["statuses"] == {"fail": 1, "unsupported": 1}
    assert summary["by_kind"] == {
        "flag": {"unsupported": 1},
        "register": {"fail": 1},
    }
    assert summary["top_reasons"] == {
        "register_mismatch": 1,
        "unsupported_flag": 1,
    }


def test_failure_reasons_does_not_double_count_unsupported() -> None:
    from angr_rule_learning.verification.verifier import _unsupported

    report = _unsupported("test", "execution", "preconditions")

    assert report.unsupported_features == ("preconditions",)
    assert report.failure_reasons == {"preconditions": 1}


def test_failure_reasons_counts_multiple_same_reason_checks() -> None:
    report = VerificationReport(
        candidate_id="multi-fail",
        status="fail",
        checks=(
            CheckResult("register", "fail", "x0", "rax", reason="register_mismatch"),
            CheckResult("register", "fail", "x1", "rcx", reason="register_mismatch"),
        ),
    )

    assert report.failure_reasons == {"register_mismatch": 2}


def test_failure_reasons_does_not_double_count_unsupported_reason() -> None:
    from angr_rule_learning.verification.verifier import _unsupported

    report = _unsupported("test", "execution", "preconditions")

    assert report.unsupported_features == ("preconditions",)
    assert report.failure_reasons == {"preconditions": 1}
