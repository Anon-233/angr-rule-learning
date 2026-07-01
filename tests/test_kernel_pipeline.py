import shutil

import pytest

from angr_rule_learning.kernel.models import (
    KernelConfig,
    KernelPipelineResult,
    KernelRunRecord,
)
from angr_rule_learning.kernel.pipeline import KernelLearningPipeline
from angr_rule_learning.rules.generalize import RuleDiagnostics


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_kernel_pipeline_emits_verified_rules(tmp_path) -> None:
    result = KernelLearningPipeline().run(
        KernelConfig(work_dir=tmp_path / "work", optimization="1"),
        rules_output=tmp_path / "rules.txt",
        diagnostics_output=tmp_path / "diagnostics.json",
    )

    rules_text = (tmp_path / "rules.txt").read_text(encoding="utf-8")
    diagnostics_text = (tmp_path / "diagnostics.json").read_text(encoding="utf-8")

    assert result.rules
    assert ".Guest:" in rules_text
    assert "lea " in rules_text
    assert '"kernels_total"' in diagnostics_text
    assert any(
        record.kernel_id == "kernel_add_i32" and record.status == "rule_emitted"
        for record in result.records
    )
    record_status = {record.kernel_id: record.status for record in result.records}
    partial_register_kernel_ids = {
        "kernel_and_const_i32",
        "kernel_and_const_i64",
        "kernel_icmp_eq_i32",
        "kernel_icmp_slt_i32",
    }
    assert {
        kernel_id: record_status.get(kernel_id)
        for kernel_id in partial_register_kernel_ids
    } == {kernel_id: "rule_emitted" for kernel_id in partial_register_kernel_ids}
    assert result.diagnostics["kernels_total"] >= 1
    assert result.diagnostics["verified_pass"] >= 1

    # ── RegViewOp regression assertions ──────────────────────────────
    # add rule must use reg64(...) for LEA address operands.
    assert "reg64(i32_reg" in rules_text, (
        f"add rule should emit reg64(...) for LEA address: {rules_text!r}"
    )
    # The old wrong form must NOT appear.
    assert "lea i32_reg1, [i32_reg" not in rules_text, (
        f"old wrong lea form detected: {rules_text!r}"
    )
    # Line-level check: find the LEA line and verify it has reg64.
    lea_lines = [ln.strip() for ln in rules_text.splitlines() if "lea " in ln]
    assert any("reg64(" in ln for ln in lea_lines), (
        f"lea rule line must contain reg64(...): {lea_lines}"
    )

    # sub/and/or/xor rules must NOT have spurious reg64(...).
    # Collect all non-lea Host instructions and check.
    in_host = False
    for line in rules_text.splitlines():
        stripped = line.strip()
        if stripped == ".Host:":
            in_host = True
            continue
        if stripped.startswith(".") or stripped == "":
            in_host = False
            continue
        if not in_host:
            continue
        mnemonic = stripped.split()[0] if stripped.split() else ""
        if mnemonic in ("sub", "and", "or", "xor", "mov"):
            assert "reg64(" not in stripped, (
                f"non-lea instruction must not have reg64: {stripped!r}"
            )

    # ── Host semantic partial-register regression assertions ──────────
    assert "movzx i32_reg1, lo8(i32_reg2)" in rules_text
    assert "movzx i64_reg1, lo16(i64_reg2)" in rules_text
    assert "sete lo8(i32_reg1)" in rules_text
    assert "setl lo8(i32_reg1)" in rules_text
    assert "sete al" not in rules_text
    assert "setl al" not in rules_text


def test_kernel_diagnostics_group_records_by_suite() -> None:
    result = KernelPipelineResult(
        candidates=(),
        reports=(),
        rules=(),
        rule_diagnostics=RuleDiagnostics(),
        records=(
            KernelRunRecord(
                "stable_ok",
                "stable_ok",
                "rule_emitted",
                suite="stable",
                expected_status="rule_emitted",
            ),
            KernelRunRecord(
                "probe_skip",
                "probe_skip",
                "unsupported",
                suite="probe",
                expected_status="unsupported",
                expected_reason="unsupported ABI argument width",
                reason="unsupported ABI argument width: x86-64:16",
            ),
        ),
    )

    diagnostics = result.diagnostics

    assert diagnostics["by_suite"]["stable"]["rule_emitted"] == 1
    assert diagnostics["by_suite"]["probe"]["unsupported"] == 1
    assert diagnostics["expectation_mismatches"] == []


def test_kernel_diagnostics_report_expectation_mismatch() -> None:
    result = KernelPipelineResult(
        candidates=(),
        reports=(),
        rules=(),
        rule_diagnostics=RuleDiagnostics(),
        records=(
            KernelRunRecord(
                "probe_changed",
                "probe_changed",
                "rule_emitted",
                suite="probe",
                expected_status="unsupported",
                expected_reason="unsupported ABI argument width",
            ),
        ),
    )

    diagnostics = result.diagnostics

    assert diagnostics["expectation_mismatches"] == [
        {
            "kernel_id": "probe_changed",
            "suite": "probe",
            "expected_status": "unsupported",
            "expected_reason": "unsupported ABI argument width",
            "actual_status": "rule_emitted",
            "actual_reason": None,
        }
    ]


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_memory_kernel_pipeline_emits_load_and_store_rules(tmp_path) -> None:
    """Run the pipeline with both directions and verify memory kernel rules
    contain ptr64_regN and native ISA memory operands."""
    for guest_arch, host_arch in [("aarch64", "x86-64"), ("x86-64", "aarch64")]:
        result = KernelLearningPipeline().run(
            KernelConfig(
                work_dir=tmp_path / f"mem_{guest_arch}_{host_arch}",
                guest_arch=guest_arch,
                host_arch=host_arch,
                optimization="1",
            ),
            rules_output=tmp_path / f"rules_{guest_arch}_{host_arch}.txt",
            diagnostics_output=tmp_path / f"diag_{guest_arch}_{host_arch}.json",
        )

        # At least the memory kernels should pass verification.
        assert result.diagnostics["verified_pass"] >= 1
        assert result.rules

        lines: list[str] = []
        for r in result.rules:
            for ln in r.guest_lines:
                lines.append(ln)
            for ln in r.host_lines:
                lines.append(ln)
        rules_text = "\n".join(lines)

        # Memory rules should contain ptr64_regN.
        assert "ptr64_reg" in rules_text, (
            f"memory rules should contain ptr64_regN in: {rules_text!r}"
        )

        # Memory rules should NOT use addr64 format.
        assert "addr64_" not in rules_text, (
            f"memory rules should not use addr64_: {rules_text!r}"
        )

        # Every memory kernel must emit a rule.
        memory_kernel_ids = [
            "kernel_load_i32",
            "kernel_load_i64",
            "kernel_store_i32",
            "kernel_store_i64",
            "kernel_load_i32_idx",
            "kernel_load_i64_idx",
            "kernel_store_i32_idx",
            "kernel_store_i64_idx",
            "kernel_load_i32_disp",
            "kernel_load_i64_disp",
            "kernel_store_i32_disp",
            "kernel_store_i64_disp",
            "kernel_load_i32_prev",
            "kernel_load_i64_prev",
            "kernel_store_i32_prev",
            "kernel_store_i64_prev",
            "kernel_load_i32_idx_disp",
            "kernel_load_i64_idx_disp",
            "kernel_store_i32_idx_disp",
            "kernel_store_i64_idx_disp",
        ]
        memory_records = {
            r.kernel_id: r for r in result.records if r.kernel_id in memory_kernel_ids
        }
        assert len(memory_records) == len(memory_kernel_ids), (
            f"expected {len(memory_kernel_ids)} memory kernel records, got {len(memory_records)}"
        )
        failed: list[str] = []
        for kid in memory_kernel_ids:
            rec = memory_records[kid]
            if rec.status != "rule_emitted":
                failed.append(f"{kid}: {rec.status} reason={rec.reason}")
        assert not failed, f"memory kernel failures: {'; '.join(failed)}"

        # Generated memory rules must contain ptr64_regN.
        assert "ptr64_reg" in rules_text, (
            f"memory rules should contain ptr64_regN in: {rules_text!r}"
        )


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_probe_kernel_pipeline_reports_expected_unsupported(tmp_path) -> None:
    result = KernelLearningPipeline().run(
        KernelConfig(
            work_dir=tmp_path / "probe",
            kernel_suite="probe",
            optimization="1",
        ),
        rules_output=tmp_path / "probe-rules.txt",
        diagnostics_output=tmp_path / "probe-diagnostics.json",
    )

    diagnostics = result.diagnostics

    assert result.records
    assert {record.suite for record in result.records} == {"probe"}
    assert diagnostics["by_suite"]["probe"]["unsupported"] == len(result.records)
    assert diagnostics["expectation_mismatches"] == []
    assert all(record.expectation_matched for record in result.records)
