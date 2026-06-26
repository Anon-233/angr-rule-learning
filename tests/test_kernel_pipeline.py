import shutil

import pytest

from angr_rule_learning.kernel.models import KernelConfig
from angr_rule_learning.kernel.pipeline import KernelLearningPipeline


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
