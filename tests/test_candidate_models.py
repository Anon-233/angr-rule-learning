import pytest

from angr_rule_learning.verification.candidate import (
    AliasDeclaration,
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)
from angr_rule_learning.verification.config import VerificationConfig
from angr_rule_learning.verification.report import CheckResult, VerificationReport


def test_candidate_normalizes_hex_and_register_names() -> None:
    candidate = VerificationCandidate(
        candidate_id="add",
        guest=CodeFragment("AARCH64", 0x10000, "20 00 02 8b", 1),
        host=CodeFragment("x86-64", 0x8048000, "48_8d_04_11", 1),
        input_registers=(("X1", "RCX"),),
        output_registers=(("X0", "RAX"),),
    )

    assert candidate.guest.arch == "aarch64"
    assert candidate.guest.code_hex == "2000028b"
    assert candidate.host.code_bytes == bytes.fromhex("488d0411")
    assert candidate.input_registers == (("x1", "rcx"),)
    assert candidate.output_registers == (("x0", "rax"),)


def test_candidate_converts_preconditions_to_tuple() -> None:
    candidate = VerificationCandidate(
        candidate_id="load",
        guest=CodeFragment("AARCH64", 0x10000, "20 00 02 8b", 1),
        host=CodeFragment("x86-64", 0x8048000, "48_8d_04_11", 1),
        preconditions=["x1 != 0"],
    )

    assert candidate.preconditions == ("x1 != 0",)
    assert isinstance(candidate.preconditions, tuple)


def test_memory_model_rejects_invalid_slot_size() -> None:
    with pytest.raises(ValueError, match="memory slot size must be positive"):
        MemorySlot(name="mem0", size=0)


def test_code_fragment_rejects_invalid_hex() -> None:
    with pytest.raises(
        ValueError, match="code_hex must contain valid hexadecimal bytes"
    ):
        CodeFragment("aarch64", 0x10000, "abc", 1)


def test_code_fragment_rejects_empty_hex() -> None:
    with pytest.raises(ValueError, match="code_hex must contain at least one byte"):
        CodeFragment("aarch64", 0x10000, "", 1)


def test_memory_spec_converts_list_inputs_to_tuples() -> None:
    slot = MemorySlot(name="mem0", size=4)
    alias_slot = MemorySlot(name="mem1", size=4)
    binding = MemoryBinding("mem0", "x1", "rcx", "read")
    access = MemoryAccessExpectation("mem0", "read", 4)
    alias = AliasDeclaration(("mem0", "mem1"), "disjoint")

    spec = MemorySpec(
        slots=[slot, alias_slot],
        bindings=[binding],
        accesses=[access],
        alias=[alias],
    )

    assert spec.slots == (slot, alias_slot)
    assert spec.bindings == (binding,)
    assert spec.accesses == (access,)
    assert spec.alias == (alias,)


def test_memory_model_rejects_invalid_alias_relation() -> None:
    with pytest.raises(ValueError, match="unsupported alias relation"):
        AliasDeclaration(slots=("mem0", "mem1"), relation="unknown")


def test_memory_model_rejects_empty_slot_references() -> None:
    with pytest.raises(ValueError, match="memory binding slot must not be empty"):
        MemoryBinding(slot=" ", guest_addr="x1", host_addr="rcx", access="read")
    with pytest.raises(
        ValueError, match="guest memory address expression must not be empty"
    ):
        MemoryBinding(slot="mem0", guest_addr="", host_addr="rcx", access="read")
    with pytest.raises(
        ValueError, match="host memory address expression must not be empty"
    ):
        MemoryBinding(slot="mem0", guest_addr="x1", host_addr="", access="read")
    with pytest.raises(ValueError, match="memory access slot must not be empty"):
        MemoryAccessExpectation(slot=" ", kind="read", width=4)
    with pytest.raises(ValueError, match="alias slot must not be empty"):
        AliasDeclaration(slots=("mem0", " "), relation="disjoint")


def test_memory_spec_rejects_duplicate_slots() -> None:
    with pytest.raises(ValueError, match="duplicate memory slot: mem0"):
        MemorySpec(slots=(MemorySlot("mem0", 4), MemorySlot("mem0", 4)))


def test_memory_spec_rejects_binding_for_unknown_slot() -> None:
    with pytest.raises(ValueError, match="unknown memory slot: mem1"):
        MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem1", "x1", "rcx", "read"),),
        )


def test_memory_spec_rejects_access_for_unknown_slot() -> None:
    with pytest.raises(ValueError, match="unknown memory slot: mem1"):
        MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            accesses=(MemoryAccessExpectation("mem1", "read", 4),),
        )


def test_memory_spec_rejects_alias_for_unknown_slot() -> None:
    with pytest.raises(ValueError, match="unknown memory slot: mem1"):
        MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            alias=(AliasDeclaration(("mem0", "mem1"), "disjoint"),),
        )


def test_memory_access_expectation_rejects_invalid_kind() -> None:
    with pytest.raises(ValueError, match="unsupported memory access kind"):
        MemoryAccessExpectation(slot="mem0", kind="execute", width=4)


def test_report_equivalent_only_when_status_passes() -> None:
    report = VerificationReport(
        candidate_id="add",
        status="pass",
        checks=(CheckResult("register", "pass", "x0", "rax"),),
    )

    assert report.equivalent
    assert report.failure_reasons == {}


def test_report_equivalent_false_and_failure_reasons_populated() -> None:
    report = VerificationReport(
        candidate_id="add",
        status="fail",
        checks=(CheckResult("register", "fail", "x0", "rax", reason="mismatch"),),
        unsupported_features=("memory",),
    )

    assert not report.equivalent
    assert report.failure_reasons == {"mismatch": 1, "memory": 1}


def test_report_mappings_are_immutable() -> None:
    check = CheckResult(
        "register",
        "fail",
        "x0",
        "rax",
        counterexample={"x0": 1},
    )
    event = {"kind": "check", "value": 1}
    report = VerificationReport("add", "fail", events=[event])

    assert check.counterexample == {"x0": 1}
    assert report.events == ({"kind": "check", "value": 1},)

    with pytest.raises(TypeError):
        check.counterexample["x0"] = 2
    with pytest.raises(TypeError):
        report.events[0]["value"] = 2


def test_config_defaults_are_small_fragment_focused() -> None:
    config = VerificationConfig()

    assert config.max_successors == 1
    assert config.emit_events is False


def test_memory_binding_normalizes_indexed_addresses() -> None:
    binding = MemoryBinding(
        "mem0",
        "X1  +  X2 * 4 + 8",
        "RCX  +  RDX * 4 + 8",
        "read",
    )

    assert binding.guest_addr == "x1 + x2 * 4 + 8"
    assert binding.host_addr == "rcx + rdx * 4 + 8"


def test_config_rejects_invalid_numeric_values() -> None:
    with pytest.raises(ValueError, match="max_successors must be positive"):
        VerificationConfig(max_successors=0)
    with pytest.raises(ValueError, match="memory_stride must be positive"):
        VerificationConfig(memory_stride=0)
    with pytest.raises(ValueError, match="memory_base must be non-negative"):
        VerificationConfig(memory_base=-1)
