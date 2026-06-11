import json
import shutil
from pathlib import Path

from angr_rule_learning.cli import main
from angr_rule_learning.extraction.config import ExtractionConfig
from angr_rule_learning.extraction.models import (
    AlignmentRegion,
    ExtractedInstruction,
    SourceLocation,
)
from angr_rule_learning.extraction.pipeline import ExtractionPipeline
from angr_rule_learning.io.readers import read_candidates


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
        region_provider=lambda config, diagnostics: (region,),
    )

    result = pipeline.run(
        ExtractionConfig(source=source, work_dir=tmp_path / "work"),
        candidates_output=output,
        diagnostics_output=diagnostics_path,
        verify=False,
    )

    candidates = list(read_candidates(output))
    diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
    assert len(candidates) == 1
    assert result.candidates == tuple(candidates)
    assert diagnostics["windows_emitted"] == 1
    assert diagnostics["surface_kinds"] == {"register": 1}


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
        host_hex = candidate.host.code_hex
        assert host_hex != "55", f"push candidate leaked: {candidate.candidate_id}"
        assert host_hex != "c3", f"ret candidate leaked: {candidate.candidate_id}"
        assert not host_hex.startswith("e8"), (
            f"call candidate leaked: {candidate.candidate_id}"
        )
        guest_hex = candidate.guest.code_hex
        assert guest_hex != "00000094", (
            f"guest bl candidate leaked: {candidate.candidate_id}"
        )
        for guest_reg, host_reg in candidate.input_registers:
            assert guest_reg not in ("nzcv", "rflags"), (
                f"flag in input: {candidate.candidate_id}"
            )
            assert host_reg not in ("nzcv", "rflags"), (
                f"flag in input: {candidate.candidate_id}"
            )
        for guest_reg, host_reg in candidate.output_registers:
            assert guest_reg not in ("nzcv", "rflags"), (
                f"flag in output: {candidate.candidate_id}"
            )
            assert host_reg not in ("nzcv", "rflags"), (
                f"flag in output: {candidate.candidate_id}"
            )
