from pathlib import Path
import subprocess

from angr_rule_learning.extraction.build import BuildArtifacts, ClangBuildDriver
from angr_rule_learning.extraction.config import CompileOptions, ExtractionConfig


class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        output = Path(command[command.index("-o") + 1])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(b"object")
        return subprocess.CompletedProcess(command, 0, "", "")


def test_build_driver_invokes_clang_for_guest_and_host(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    runner = RecordingRunner()
    config = ExtractionConfig(source=source, work_dir=tmp_path / "out")

    artifacts = ClangBuildDriver(runner=runner).build(config)

    assert isinstance(artifacts, BuildArtifacts)
    assert artifacts.guest_object == tmp_path / "out" / "guest-aarch64.o"
    assert artifacts.host_object == tmp_path / "out" / "host-x86-64.o"
    assert artifacts.guest_object.read_bytes() == b"object"
    assert artifacts.host_object.read_bytes() == b"object"
    assert runner.commands[0][:3] == ["clang", "-target", "aarch64-linux-gnu"]
    assert runner.commands[1][:3] == ["clang", "-target", "x86_64-linux-gnu"]
    assert "-g" in runner.commands[0]
    assert "-O0" in runner.commands[0]
    assert "-ffreestanding" in runner.commands[0]
    assert "-fno-builtin" in runner.commands[0]
    assert "-c" in runner.commands[0]


def test_build_driver_supports_reverse_architecture_direction(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    runner = RecordingRunner()
    config = ExtractionConfig(
        source=source,
        work_dir=tmp_path / "out",
        guest_arch="x86_64",
        host_arch="arm64",
    )

    artifacts = ClangBuildDriver(runner=runner).build(config)

    assert artifacts.guest_object.name == "guest-x86-64.o"
    assert artifacts.host_object.name == "host-aarch64.o"
    assert runner.commands[0][:3] == ["clang", "-target", "x86_64-linux-gnu"]
    assert runner.commands[1][:3] == ["clang", "-target", "aarch64-linux-gnu"]


def test_build_driver_uses_configured_compile_options(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    runner = RecordingRunner()
    config = ExtractionConfig(
        source=source,
        work_dir=tmp_path / "out",
        compile_options=CompileOptions(
            clang="custom-clang",
            optimization="1",
            common_flags=("-ffreestanding",),
            guest_flags=("-mstrict-align",),
            host_flags=("-mno-red-zone",),
        ),
    )

    ClangBuildDriver(runner=runner).build(config)

    assert runner.commands[0][0] == "custom-clang"
    assert runner.commands[1][0] == "custom-clang"
    assert "-O1" in runner.commands[0]
    assert "-O1" in runner.commands[1]
    assert "-mstrict-align" in runner.commands[0]
    assert "-mstrict-align" not in runner.commands[1]
    assert "-mno-red-zone" in runner.commands[1]
    assert "-mno-red-zone" not in runner.commands[0]


def test_build_driver_reports_failed_command(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int f(void) { return 1; }\n", encoding="utf-8")

    def failing_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, "", "clang failed")

    config = ExtractionConfig(source=source, work_dir=tmp_path / "out")

    try:
        ClangBuildDriver(runner=failing_runner).build(config)
    except RuntimeError as exc:
        assert "clang failed" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")
