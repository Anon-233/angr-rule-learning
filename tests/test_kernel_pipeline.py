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
