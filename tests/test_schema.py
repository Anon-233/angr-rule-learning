import json

import pytest

from angr_rule_learning.io.schema import candidate_from_json, report_to_json
from angr_rule_learning.verification.report import CheckResult, VerificationReport


def _payload() -> dict[str, object]:
    return {
        "candidate_id": "load32",
        "guest": {
            "arch": "aarch64",
            "address": 0x10000,
            "code_hex": "20 00 40 b9",
            "instruction_count": 1,
        },
        "host": {
            "arch": "x86-64",
            "address": 0x8048000,
            "code_hex": "8b 01",
            "instruction_count": 1,
        },
        "inputs": {"registers": [["x1", "rcx"]]},
        "outputs": {"registers": [["w0", "eax"]], "flags": []},
        "memory": {
            "slots": [{"name": "mem0", "size": 4, "initial": "symbolic"}],
            "bindings": [
                {
                    "slot": "mem0",
                    "guest_addr": "x1",
                    "host_addr": "rcx",
                    "access": "read",
                }
            ],
            "accesses": [{"slot": "mem0", "kind": "read", "width": 4}],
            "alias": [],
        },
        "preconditions": [],
        "clobbers": {"guest": [], "host": []},
    }


def test_candidate_from_json_parses_new_schema() -> None:
    candidate = candidate_from_json(_payload())

    assert candidate.candidate_id == "load32"
    assert candidate.guest.arch == "aarch64"
    assert candidate.memory.slots[0].name == "mem0"
    assert candidate.output_registers == (("w0", "eax"),)


def test_candidate_from_json_rejects_legacy_init_map() -> None:
    payload = _payload()
    payload["init_map"] = [["x1", "rcx"]]

    with pytest.raises(ValueError, match="unknown top-level field: init_map"):
        candidate_from_json(payload)


def test_candidate_from_json_rejects_missing_required_field() -> None:
    payload = _payload()
    del payload["guest"]

    with pytest.raises(ValueError, match="missing top-level field: guest"):
        candidate_from_json(payload)


@pytest.mark.parametrize(
    "field", ("inputs", "outputs", "memory", "preconditions", "clobbers")
)
def test_candidate_from_json_rejects_missing_required_schema_sections(
    field: str,
) -> None:
    payload = _payload()
    del payload[field]

    with pytest.raises(ValueError, match=f"missing top-level field: {field}"):
        candidate_from_json(payload)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    (
        (("inputs", "init_map"), [], "unknown inputs field: init_map"),
        (("memory", "legacy"), [], "unknown memory field: legacy"),
        (
            ("memory", "slots", 0, "extra"),
            True,
            r"unknown memory\.slots\[0\] field: extra",
        ),
    ),
)
def test_candidate_from_json_rejects_nested_unknown_fields(
    path: tuple[object, ...], value: object, message: str
) -> None:
    payload = _payload()
    target = payload
    for part in path[:-1]:
        if isinstance(target, dict):
            target = target[part]
        else:
            target = target[part]
    target[path[-1]] = value

    with pytest.raises(ValueError, match=message):
        candidate_from_json(payload)


def test_candidate_from_json_rejects_preconditions_string() -> None:
    payload = _payload()
    payload["preconditions"] = "x1 != 0"

    with pytest.raises(ValueError, match="preconditions must be a list"):
        candidate_from_json(payload)


def test_candidate_from_json_rejects_clobbers_guest_string() -> None:
    payload = _payload()
    payload["clobbers"] = {"guest": "x0", "host": []}

    with pytest.raises(ValueError, match=r"clobbers\.guest must be a list"):
        candidate_from_json(payload)


def test_candidate_from_json_rejects_bool_candidate_id() -> None:
    payload = _payload()
    payload["candidate_id"] = True

    with pytest.raises(ValueError, match="candidate_id must be a string"):
        candidate_from_json(payload)


def test_candidate_from_json_rejects_string_integer_field() -> None:
    payload = _payload()
    payload["guest"]["address"] = "65536"

    with pytest.raises(ValueError, match=r"guest\.address must be an integer"):
        candidate_from_json(payload)


def test_candidate_from_json_rejects_missing_nested_fragment_field() -> None:
    payload = _payload()
    del payload["guest"]["arch"]

    with pytest.raises(ValueError, match="missing guest field: arch"):
        candidate_from_json(payload)


def test_candidate_from_json_rejects_missing_nested_memory_field() -> None:
    payload = _payload()
    del payload["memory"]["bindings"][0]["access"]

    with pytest.raises(
        ValueError, match=r"missing memory\.bindings\[0\] field: access"
    ):
        candidate_from_json(payload)


@pytest.mark.parametrize(
    ("container", "field", "message"),
    (
        ("inputs", "registers", r"missing inputs field: registers"),
        ("outputs", "registers", r"missing outputs field: registers"),
        ("outputs", "flags", r"missing outputs field: flags"),
        ("clobbers", "guest", r"missing clobbers field: guest"),
        ("clobbers", "host", r"missing clobbers field: host"),
    ),
)
def test_candidate_from_json_rejects_missing_nested_collection_fields(
    container: str, field: str, message: str
) -> None:
    payload = _payload()
    del payload[container][field]

    with pytest.raises(ValueError, match=message):
        candidate_from_json(payload)


@pytest.mark.parametrize(
    "field",
    ("slots", "bindings", "accesses", "alias"),
)
def test_candidate_from_json_rejects_missing_memory_collection_fields(
    field: str,
) -> None:
    payload = _payload()
    del payload["memory"][field]

    with pytest.raises(ValueError, match=f"missing memory field: {field}"):
        candidate_from_json(payload)


def test_candidate_from_json_rejects_pair_entries_with_non_strings() -> None:
    payload = _payload()
    payload["inputs"] = {"registers": [["x1", 2]]}

    with pytest.raises(
        ValueError, match=r"inputs\.registers entries must contain strings"
    ):
        candidate_from_json(payload)


def test_report_to_json_is_stable() -> None:
    report = VerificationReport(
        candidate_id="load32",
        status="fail",
        checks=(
            CheckResult(
                kind="memory",
                status="fail",
                guest="mem0",
                host="mem0",
                reason="memory_read_value_mismatch",
                counterexample={"x1": 1},
            ),
        ),
    )

    assert report_to_json(report) == {
        "candidate_id": "load32",
        "equivalent": False,
        "status": "fail",
        "checks": [
            {
                "kind": "memory",
                "status": "fail",
                "guest": "mem0",
                "host": "mem0",
                "reason": "memory_read_value_mismatch",
                "counterexample": {"x1": 1},
            }
        ],
        "unsupported_features": [],
        "events": [],
        "failure_reasons": {"memory_read_value_mismatch": 1},
    }


def test_report_to_json_supports_nested_json_event_values() -> None:
    report = VerificationReport(
        candidate_id="load32",
        status="pass",
        events=(
            {
                "kind": "trace",
                "steps": [{"pc": 0x10000, "registers": ["x1", "w0"]}],
            },
        ),
    )

    assert json.dumps(report_to_json(report))


def test_report_to_json_rejects_unsupported_event_value() -> None:
    report = VerificationReport(
        candidate_id="load32",
        status="pass",
        events=({"bad": object()},),
    )

    with pytest.raises(
        ValueError, match=r"report contains non-JSON value at events\[0\]\.bad"
    ):
        report_to_json(report)


@pytest.mark.parametrize("value", (float("nan"), float("inf"), float("-inf")))
def test_report_to_json_rejects_non_finite_float_values(value: float) -> None:
    report = VerificationReport(
        candidate_id="load32",
        status="pass",
        events=({"bad": value},),
    )

    with pytest.raises(
        ValueError, match=r"report contains non-JSON value at events\[0\]\.bad"
    ):
        report_to_json(report)


def test_report_to_json_rejects_non_string_mapping_keys() -> None:
    report = VerificationReport(
        candidate_id="load32",
        status="pass",
        events=({1: "bad"},),
    )

    with pytest.raises(
        ValueError, match=r"report contains non-JSON value at events\[0\]\[1\]"
    ):
        report_to_json(report)


def test_report_to_json_validates_top_level_report_fields() -> None:
    report = VerificationReport(candidate_id=float("nan"), status="pass")

    with pytest.raises(
        ValueError, match="report contains non-JSON value at candidate_id"
    ):
        report_to_json(report)


def test_report_to_json_validates_check_fields() -> None:
    report = VerificationReport(
        candidate_id="load32",
        status="fail",
        checks=(CheckResult(kind=object(), status="fail", guest="mem0", host="mem0"),),
    )

    with pytest.raises(
        ValueError, match=r"report contains non-JSON value at checks\[0\]\.kind"
    ):
        report_to_json(report)
