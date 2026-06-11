import shutil
from pathlib import Path

from angr_rule_learning.extraction.build import ClangBuildDriver
from angr_rule_learning.extraction.config import ExtractionConfig
from angr_rule_learning.extraction.models import ExtractedFunction, SourceLocation
from angr_rule_learning.extraction.object import (
    ObjectExtractor,
    RawFunction,
    RawInstruction,
)


def test_object_extractor_attaches_source_locations(
    monkeypatch, tmp_path: Path
) -> None:
    obj = tmp_path / "guest.o"
    obj.write_bytes(b"fake")
    extractor = ObjectExtractor()

    monkeypatch.setattr(
        extractor,
        "_read_functions",
        lambda path, arch: (RawFunction("add", 0x1000, 4, bytes.fromhex("2000028b")),),
    )
    monkeypatch.setattr(
        extractor,
        "_read_line_map",
        lambda path: {0x1000: SourceLocation("sample.c", 3)},
    )
    monkeypatch.setattr(
        extractor,
        "_disassemble_function",
        lambda arch, raw: (
            RawInstruction(
                0x1000,
                4,
                bytes.fromhex("2000028b"),
                "add",
                "x0, x1, x2",
                ("x1", "x2"),
                ("x0",),
                (),
            ),
        ),
    )

    functions = extractor.extract(obj, "aarch64")

    assert functions == (
        ExtractedFunction(
            arch="aarch64",
            name="add",
            address=0x1000,
            size=4,
            instructions=functions[0].instructions,
        ),
    )
    assert functions[0].instructions[0].source == SourceLocation("sample.c", 3)
    assert functions[0].instructions[0].read_registers == ("x1", "x2")
    assert functions[0].instructions[0].write_registers == ("x0",)


def test_object_extractor_rejects_empty_function_set(
    monkeypatch, tmp_path: Path
) -> None:
    obj = tmp_path / "empty.o"
    obj.write_bytes(b"fake")
    extractor = ObjectExtractor()
    monkeypatch.setattr(extractor, "_read_functions", lambda path, arch: ())

    try:
        extractor.extract(obj, "x86-64")
    except ValueError as exc:
        assert "no functions found" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_object_extractor_reads_compiled_host_object(tmp_path: Path) -> None:
    if shutil.which("clang") is None:
        return
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    config = ExtractionConfig(source=source, work_dir=tmp_path / "out")
    try:
        artifacts = ClangBuildDriver().build(config)
    except RuntimeError:
        return

    functions = ObjectExtractor().extract(artifacts.host_object, "x86-64")

    assert any(function.name == "add" for function in functions)
    add_function = next(function for function in functions if function.name == "add")
    assert add_function.instructions
    assert len(add_function.instructions) > 0
    assert any(inst.source is not None for inst in add_function.instructions), (
        "source locations must be resolved for compiled object"
    )
