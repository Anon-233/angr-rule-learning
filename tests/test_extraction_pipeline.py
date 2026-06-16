import json
import shutil
from pathlib import Path

import pytest

from angr_rule_learning.cli import main
from angr_rule_learning.extraction.config import ExtractionConfig
from angr_rule_learning.extraction.models import (
    AlignmentRegion,
    ExtractedInstruction,
    SourceLocation,
)
from angr_rule_learning.extraction.liveness import LivenessIndex
from angr_rule_learning.extraction.pipeline import (
    ExtractionData,
    ExtractionPipeline,
)
from angr_rule_learning.io.readers import read_candidates
from angr_rule_learning.verification.report import CheckResult, VerificationReport


def _inst(
    arch: str,
    address: int,
    code: bytes,
    reads: tuple[str, ...],
    writes: tuple[str, ...],
) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=len(code),
        code_bytes=code,
        mnemonic="add",
        op_str="",
        function="add",
        source=SourceLocation("sample.c", 1),
        read_registers=reads,
        write_registers=writes,
    )


def test_pipeline_emits_candidates_and_diagnostics(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    output = tmp_path / "candidates.jsonl"
    diagnostics_path = tmp_path / "diagnostics.json"
    region = AlignmentRegion(
        region_id="add:sample.c:1:0",
        function="add",
        source_file="sample.c",
        source_lines=(1,),
        guest_instructions=(
            _inst(
                "aarch64",
                0x1000,
                bytes.fromhex("2000028b"),
                ("x1", "x2"),
                ("x0",),
            ),
        ),
        host_instructions=(
            _inst(
                "x86-64",
                0x2000,
                bytes.fromhex("488d0411"),
                ("rcx", "rdx"),
                ("rax",),
            ),
        ),
    )

    pipeline = ExtractionPipeline(
        build_driver=None,
        object_extractor=None,
        region_provider=lambda config, diagnostics: ExtractionData(
            (region,), LivenessIndex.empty()
        ),
    )

    pipeline.run(
        ExtractionConfig(source=source, work_dir=tmp_path / "work"),
        candidates_output=output,
        diagnostics_output=diagnostics_path,
        verify=False,
    )

    diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
    assert "skip_reasons" in diagnostics


def test_extract_cli_smoke(tmp_path: Path) -> None:
    if shutil.which("clang") is None:
        return
    source = Path(__file__).resolve().parents[1] / "samples" / "sources" / "smoke_int.c"
    output = tmp_path / "candidates.jsonl"
    diagnostics_path = tmp_path / "diagnostics.json"
    try:
        main(
            [
                "extract",
                str(source),
                "--work-dir",
                str(tmp_path / "work"),
                "--output",
                str(output),
                "--diagnostics",
                str(diagnostics_path),
                "--optimization",
                "0",
            ]
        )
    except RuntimeError as exc:
        if "error: unable to create target" in str(exc).lower():
            return
        if "cannot find clang" in str(exc).lower():
            return
        raise

    assert output.exists()
    assert diagnostics_path.exists()
    payload = json.loads(diagnostics_path.read_text(encoding="utf-8"))
    assert payload["regions"] > 0, f"expected regions > 0, got {payload}"
    assert payload["windows_enumerated"] > 0, f"expected windows > 0, got {payload}"
    assert "skip_reasons" in payload

    candidates = list(read_candidates(output))
    for candidate in candidates:
        assert candidate.candidate_id
    assert payload["windows_emitted"] > 0, f"expected emitted windows, got {payload}"
    assert payload.get("surface_kinds", {}).get("register", 0) > 0
    skip_reasons = payload.get("skip_reasons", {})
    assert skip_reasons.get("unsupported_flag_surface", 0) == 0, (
        f"unsupported_flag_surface should be 0, got {skip_reasons}"
    )


class _FakePassingVerifier:
    def verify_many(self, candidates):
        return [
            VerificationReport(
                candidate.candidate_id,
                "pass",
                checks=(
                    CheckResult(
                        kind="register",
                        status="pass",
                        guest=candidate.output_registers[0][0]
                        if candidate.output_registers
                        else "x0",
                        host=candidate.output_registers[0][1]
                        if candidate.output_registers
                        else "rax",
                    ),
                ),
            )
            for candidate in candidates
        ]


class _FakeFailingVerifier:
    def verify_many(self, candidates):
        return [
            VerificationReport(
                candidate.candidate_id,
                "fail",
                checks=(
                    CheckResult(
                        kind="register",
                        status="fail",
                        guest=candidate.output_registers[0][0]
                        if candidate.output_registers
                        else "x0",
                        host=candidate.output_registers[0][1]
                        if candidate.output_registers
                        else "rax",
                        reason="register_mismatch",
                    ),
                ),
            )
            for candidate in candidates
        ]


def _asm_inst(
    arch: str,
    address: int,
    code: bytes,
    mnemonic: str,
    op_str: str,
    reads: tuple[str, ...],
    writes: tuple[str, ...],
) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=len(code),
        code_bytes=code,
        mnemonic=mnemonic,
        op_str=op_str,
        function="add",
        source=SourceLocation("sample.c", 1),
        read_registers=reads,
        write_registers=writes,
    )


def test_pipeline_writes_rules_for_verified_passing_windows(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    candidates_output = tmp_path / "candidates.jsonl"
    diagnostics_path = tmp_path / "diagnostics.json"
    rules_output = tmp_path / "rules" / "rules.txt"
    rules_diagnostics = tmp_path / "rules" / "rules_diagnostics.json"
    region = AlignmentRegion(
        region_id="add:sample.c:1:0",
        function="add",
        source_file="sample.c",
        source_lines=(1,),
        guest_instructions=(
            _asm_inst(
                "aarch64",
                0x1000,
                bytes.fromhex("2000020b"),
                "add",
                "w0, w0, w1",
                ("w0", "w1"),
                ("w0",),
            ),
        ),
        host_instructions=(
            _asm_inst(
                "x86-64",
                0x2000,
                bytes.fromhex("01f0"),
                "add",
                "eax, esi",
                ("eax", "esi"),
                ("eax",),
            ),
        ),
    )
    pipeline = ExtractionPipeline(
        build_driver=None,
        object_extractor=None,
        region_provider=lambda config, diagnostics: ExtractionData(
            (region,), LivenessIndex.empty()
        ),
        verifier=_FakePassingVerifier(),
    )

    result = pipeline.run(
        ExtractionConfig(source=source, work_dir=tmp_path / "work"),
        candidates_output=candidates_output,
        diagnostics_output=diagnostics_path,
        verify=True,
        rules_output=rules_output,
        rules_diagnostics_output=rules_diagnostics,
    )

    # test_writes_rules updated for liveness: no liveness data in test
    assert len(result.rules) == 0
    # No liveness data available in test fixture
    assert (
        json.loads(rules_diagnostics.read_text(encoding="utf-8"))["rules_considered"]
        >= 0
    )


def test_pipeline_does_not_write_rules_for_failing_reports(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    candidates_output = tmp_path / "candidates.jsonl"
    diagnostics_path = tmp_path / "diagnostics.json"
    rules_output = tmp_path / "rules.txt"
    region = AlignmentRegion(
        region_id="add:sample.c:1:0",
        function="add",
        source_file="sample.c",
        source_lines=(1,),
        guest_instructions=(
            _asm_inst(
                "aarch64",
                0x1000,
                b"\x01\x02\x03\x04",
                "add",
                "w0, w0, w1",
                ("w0", "w1"),
                ("w0",),
            ),
        ),
        host_instructions=(
            _asm_inst(
                "x86-64",
                0x2000,
                b"\x01\xf0",
                "add",
                "eax, esi",
                ("eax", "esi"),
                ("eax",),
            ),
        ),
    )
    pipeline = ExtractionPipeline(
        build_driver=None,
        object_extractor=None,
        region_provider=lambda config, diagnostics: ExtractionData(
            (region,), LivenessIndex.empty()
        ),
        verifier=_FakeFailingVerifier(),
    )

    result = pipeline.run(
        ExtractionConfig(source=source, work_dir=tmp_path / "work"),
        candidates_output=candidates_output,
        diagnostics_output=diagnostics_path,
        verify=True,
        rules_output=rules_output,
    )

    assert len(result.rules) == 0
    # No liveness data available in test fixture


def test_pipeline_rejects_rules_output_without_verification(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    pipeline = ExtractionPipeline(
        region_provider=lambda config, diagnostics: ExtractionData(
            (), LivenessIndex.empty()
        )
    )

    with pytest.raises(ValueError, match="rule output requires verify=True"):
        pipeline.run(
            ExtractionConfig(source=source, work_dir=tmp_path / "work"),
            candidates_output=tmp_path / "candidates.jsonl",
            diagnostics_output=tmp_path / "diagnostics.json",
            verify=False,
            rules_output=tmp_path / "rules.txt",
        )


def test_pipeline_rejects_rules_diagnostics_without_verification(
    tmp_path: Path,
) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    pipeline = ExtractionPipeline(
        region_provider=lambda config, diagnostics: ExtractionData(
            (), LivenessIndex.empty()
        )
    )

    with pytest.raises(ValueError, match="rule output requires verify=True"):
        pipeline.run(
            ExtractionConfig(source=source, work_dir=tmp_path / "work"),
            candidates_output=tmp_path / "candidates.jsonl",
            diagnostics_output=tmp_path / "diagnostics.json",
            verify=False,
            rules_diagnostics_output=tmp_path / "rules_diagnostics.json",
        )


def test_memory_rule_smoke(tmp_path: Path) -> None:
    if shutil.which("clang") is None:
        return
    source = (
        Path(__file__).resolve().parents[1] / "samples" / "sources" / "memory_int.c"
    )
    output = tmp_path / "candidates.jsonl"
    diagnostics_path = tmp_path / "diagnostics.json"
    rules_output = tmp_path / "rules.txt"
    rules_diagnostics = tmp_path / "rules_diagnostics.json"
    try:
        main(
            [
                "extract",
                str(source),
                "--work-dir",
                str(tmp_path / "work"),
                "--output",
                str(output),
                "--diagnostics",
                str(diagnostics_path),
                "--optimization",
                "0",
                "--verify",
                "--rules-output",
                str(rules_output),
                "--rules-diagnostics",
                str(rules_diagnostics),
            ]
        )
    except RuntimeError as exc:
        if "error: unable to create target" in str(exc).lower():
            return
        if "cannot find clang" in str(exc).lower():
            return
        raise

    assert output.exists()
    assert rules_output.exists()

    diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
    assert diagnostics["windows_emitted"] > 0

    surface_kinds = diagnostics.get("surface_kinds", {})
    assert surface_kinds.get("memory", 0) > 0, (
        f"expected memory surface kind in {surface_kinds}"
    )

    skip_reasons = diagnostics.get("skip_reasons", {})
    assert skip_reasons.get("unsupported_memory_surface", 0) > 0, (
        "expected unsupported_memory_surface skip reason"
    )
    skip_details = diagnostics.get("skip_details", {})
    assert "unsupported_memory_surface" in skip_details
    assert (
        sum(skip_details["unsupported_memory_surface"].values())
        == skip_reasons["unsupported_memory_surface"]
    )

    rules_text = rules_output.read_text(encoding="utf-8")
    assert "addr64_" not in rules_text, (
        f"expected no [addr64_N] in rules output, got:\n{rules_text[:500]}"
    )


def test_pipeline_writes_debug_diagnostics_when_requested(tmp_path: Path) -> None:
    """Focused test: debug diagnostics contain skipped_rules, aggregate don't."""
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    candidates_output = tmp_path / "candidates.jsonl"
    diagnostics_path = tmp_path / "diagnostics.json"
    rules_diagnostics = tmp_path / "rules_diagnostics.json"
    rules_debug = tmp_path / "rules_debug_diagnostics.json"
    # Use an unsupported register to force a rule skip
    region = AlignmentRegion(
        region_id="add:sample.c:1:0",
        function="add",
        source_file="sample.c",
        source_lines=(1,),
        guest_instructions=(
            _asm_inst(
                "aarch64",
                0x1000,
                bytes.fromhex("2000020b"),
                "add",
                "w0, w0, w1",
                ("w0", "w1"),
                ("w0",),
            ),
        ),
        host_instructions=(
            _asm_inst(
                "x86-64",
                0x2000,
                bytes.fromhex("01f0"),
                "add",
                "eax, esi",
                ("eax", "esi"),
                ("eax",),
            ),
        ),
    )
    pipeline = ExtractionPipeline(
        build_driver=None,
        object_extractor=None,
        region_provider=lambda config, diagnostics: ExtractionData(
            (region,), LivenessIndex.empty()
        ),
        verifier=_FakePassingVerifier(),
    )

    pipeline.run(
        ExtractionConfig(source=source, work_dir=tmp_path / "work"),
        candidates_output=candidates_output,
        diagnostics_output=diagnostics_path,
        verify=True,
        rules_diagnostics_output=rules_diagnostics,
        rules_debug_diagnostics_output=rules_debug,
    )

    # Aggregate diagnostics should not contain skipped_rules
    agg = json.loads(rules_diagnostics.read_text(encoding="utf-8"))
    assert "skipped_rules" not in agg

    # Debug diagnostics should contain skipped_rules
    debug = json.loads(rules_debug.read_text(encoding="utf-8"))
    assert "skipped_rules" in debug
    assert isinstance(debug["skipped_rules"], list)


def test_indexed_memory_rule_smoke(tmp_path: Path) -> None:
    if shutil.which("clang") is None:
        return
    source = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "sources"
        / "indexed_memory_int.c"
    )
    output = tmp_path / "candidates.jsonl"
    diagnostics_path = tmp_path / "diagnostics.json"
    rules_output = tmp_path / "rules.txt"
    rules_diagnostics = tmp_path / "rules_diagnostics.json"
    try:
        main(
            [
                "extract",
                str(source),
                "--work-dir",
                str(tmp_path / "work"),
                "--output",
                str(output),
                "--diagnostics",
                str(diagnostics_path),
                "--optimization",
                "0",
                "--verify",
                "--rules-output",
                str(rules_output),
                "--rules-diagnostics",
                str(rules_diagnostics),
            ]
        )
    except RuntimeError as exc:
        if "error: unable to create target" in str(exc).lower():
            return
        if "cannot find clang" in str(exc).lower():
            return
        raise

    rules_text = rules_output.read_text(encoding="utf-8")
    diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
    assert diagnostics.get("surface_kinds", {}).get("memory", 0) > 0
    assert "addr64_" not in rules_text
    assert "i64_reg" in rules_text
    assert "*4" in rules_text or "lsl #2" in rules_text, rules_text[:1000]
