# Extractor-First Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a first source-to-candidate extraction pipeline that compiles one C source file to AArch64/x86-64 objects, extracts debug/disassembly information, mines bounded semantic windows, emits verifier candidate JSONL, and records mining diagnostics.

**Architecture:** Add a new `angr_rule_learning.extraction` package beside the existing verifier. Keep extraction stages typed and composable: build, object extraction, alignment, window mining, surface inference, emission, and orchestration. The verifier API remains unchanged; extracted candidates are ordinary `VerificationCandidate` values serialized through the existing `io.schema` boundary.

**Tech Stack:** Python dataclasses, subprocess, clang, pyelftools, Capstone, angr verifier API, pytest, ruff, uv.

---

## Design Inputs

Read before implementation:

- `docs/superpowers/specs/2026-06-11-extractor-first-pipeline-design.md`
- `docs/architecture.md`
- `docs/verifier.md`
- `docs/candidate-format.md`
- `src/angr_rule_learning/verification/candidate.py`
- `src/angr_rule_learning/io/schema.py`

Important constraints:

- Do not add rule generalization, rule storage, or coverage evaluation.
- Do not emit verifier candidates with no semantic checks.
- Do not depend on `llvm-objdump` or `llvm-dwarfdump`; they are not guaranteed available.
- Use pyelftools and Capstone directly, and declare them as direct dependencies because this package imports them.
- Keep window size configurable; default guest size is `1..2`, host size is `1..3`.
- Window size and skip diagnostics are first-class outputs.

## Target File Structure

Create:

- `src/angr_rule_learning/extraction/__init__.py`: public extraction API exports.
- `src/angr_rule_learning/extraction/config.py`: build and mining configuration dataclasses.
- `src/angr_rule_learning/extraction/models.py`: typed source, instruction, function, region, window, and result records.
- `src/angr_rule_learning/extraction/diagnostics.py`: diagnostics counters, summaries, and JSON conversion.
- `src/angr_rule_learning/extraction/build.py`: fixed clang object build driver.
- `src/angr_rule_learning/extraction/object.py`: pyelftools/Capstone object extraction.
- `src/angr_rule_learning/extraction/blocks.py`: conservative basic-block construction.
- `src/angr_rule_learning/extraction/align.py`: guest/host alignment region pairing.
- `src/angr_rule_learning/extraction/windows.py`: bounded window enumeration and verifier-feedback pruning helpers.
- `src/angr_rule_learning/extraction/surfaces.py`: conservative register/branch surface inference.
- `src/angr_rule_learning/extraction/emit.py`: candidate JSONL and diagnostics writers.
- `src/angr_rule_learning/extraction/pipeline.py`: source-to-candidate orchestration API.
- `tests/test_extraction_models.py`
- `tests/test_extraction_build.py`
- `tests/test_extraction_object.py`
- `tests/test_extraction_align.py`
- `tests/test_extraction_windows.py`
- `tests/test_extraction_surfaces.py`
- `tests/test_extraction_emit.py`
- `tests/test_extraction_pipeline.py`

Modify:

- `pyproject.toml`: add direct `pyelftools` and `capstone` dependencies.
- `src/angr_rule_learning/cli.py`: add `extract` subcommand.
- `README.md`: add one extraction command example.
- `docs/architecture.md`: mention extraction package in package structure and data flow.
- `docs/candidate-format.md`: mention extractor-produced candidate JSONL remains the same verifier format.

## Task 1: Extraction Models, Config, And Diagnostics

**Files:**
- Create: `src/angr_rule_learning/extraction/__init__.py`
- Create: `src/angr_rule_learning/extraction/config.py`
- Create: `src/angr_rule_learning/extraction/models.py`
- Create: `src/angr_rule_learning/extraction/diagnostics.py`
- Modify: `pyproject.toml`
- Test: `tests/test_extraction_models.py`

- [ ] **Step 1: Add dependency declarations**

Modify `pyproject.toml` dependencies:

```toml
dependencies = [
    "angr>=9.2.221",
    "capstone>=5.0.0",
    "pyelftools>=0.32",
]
```

- [ ] **Step 2: Write failing model/config/diagnostic tests**

Create `tests/test_extraction_models.py`:

```python
from pathlib import Path

from angr_rule_learning.extraction.config import ExtractionConfig, WindowLimits
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    SourceLocation,
)


def test_window_limits_default_stage_order() -> None:
    limits = WindowLimits()

    assert limits.guest_min == 1
    assert limits.guest_max == 2
    assert limits.host_min == 1
    assert limits.host_max == 3
    assert limits.stage_order() == ((1, 1), (1, 2), (2, 1), (1, 3), (2, 2), (2, 3))


def test_extraction_config_defaults() -> None:
    config = ExtractionConfig(source=Path("sample.c"), work_dir=Path("build/extract"))

    assert config.source == Path("sample.c")
    assert config.work_dir == Path("build/extract")
    assert config.guest_arch == "aarch64"
    assert config.host_arch == "x86-64"
    assert config.optimization == "0"
    assert config.window_limits.stage_order()[0] == (1, 1)


def test_instruction_window_properties() -> None:
    inst = ExtractedInstruction(
        arch="aarch64",
        address=0x1000,
        size=4,
        code_bytes=bytes.fromhex("2000028b"),
        mnemonic="add",
        op_str="x0, x1, x2",
        function="add3",
        source=SourceLocation("sample.c", 3),
        read_registers=("x1", "x2"),
        write_registers=("x0",),
        groups=(),
    )
    window = InstructionWindow(region_id="r0", side="guest", instructions=(inst,))

    assert window.instruction_count == 1
    assert window.code_hex == "2000028b"
    assert window.address == 0x1000
    assert window.source_span == "sample.c:3"


def test_mining_diagnostics_records_windows_and_skips() -> None:
    diagnostics = MiningDiagnostics()

    diagnostics.record_region()
    diagnostics.record_region_skipped("ambiguous_alignment_region")
    diagnostics.record_window_enumerated(guest_size=1, host_size=2)
    diagnostics.record_window_emitted(guest_size=1, host_size=2, surface_kinds=("register",))
    diagnostics.record_window_verified(status="pass")
    diagnostics.record_window_skipped("no_verifiable_surface")

    payload = diagnostics.to_json()

    assert payload["regions"] == 1
    assert payload["regions_skipped"] == 1
    assert payload["windows_enumerated"] == 1
    assert payload["windows_emitted"] == 1
    assert payload["windows_verified"] == 1
    assert payload["windows_verified_pass"] == 1
    assert payload["mean_guest_window_size"] == 1
    assert payload["mean_host_window_size"] == 2
    assert payload["skip_reasons"] == {
        "ambiguous_alignment_region": 1,
        "no_verifiable_surface": 1,
    }
    assert payload["surface_kinds"] == {"register": 1}
```

- [ ] **Step 3: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_models.py -v
```

Expected: import failure for `angr_rule_learning.extraction`.

- [ ] **Step 4: Implement config and model dataclasses**

Create `src/angr_rule_learning/extraction/config.py`:

```python
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class WindowLimits:
    guest_min: int = 1
    guest_max: int = 2
    host_min: int = 1
    host_max: int = 3

    def __post_init__(self) -> None:
        if self.guest_min < 1 or self.host_min < 1:
            raise ValueError("window minimums must be positive")
        if self.guest_max < self.guest_min:
            raise ValueError("guest window maximum must be >= minimum")
        if self.host_max < self.host_min:
            raise ValueError("host window maximum must be >= minimum")

    def stage_order(self) -> tuple[tuple[int, int], ...]:
        pairs = [
            (guest_size, host_size)
            for guest_size in range(self.guest_min, self.guest_max + 1)
            for host_size in range(self.host_min, self.host_max + 1)
        ]
        return tuple(sorted(pairs, key=lambda pair: (pair[0] + pair[1], pair[0], pair[1])))


@dataclass(frozen=True)
class ExtractionConfig:
    source: Path
    work_dir: Path
    guest_arch: str = "aarch64"
    host_arch: str = "x86-64"
    optimization: str = "0"
    clang: str = "clang"
    window_limits: WindowLimits = field(default_factory=WindowLimits)
```

Create `src/angr_rule_learning/extraction/models.py`:

```python
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class SourceLocation:
    file: str
    line: int
    column: int = 0

    def key(self) -> tuple[str, int]:
        return (self.file, self.line)

    def label(self) -> str:
        return f"{Path(self.file).name}:{self.line}"


@dataclass(frozen=True)
class ExtractedInstruction:
    arch: str
    address: int
    size: int
    code_bytes: bytes
    mnemonic: str
    op_str: str
    function: str
    source: SourceLocation | None
    read_registers: tuple[str, ...] = field(default_factory=tuple)
    write_registers: tuple[str, ...] = field(default_factory=tuple)
    groups: tuple[str, ...] = field(default_factory=tuple)

    @property
    def end_address(self) -> int:
        return self.address + self.size


@dataclass(frozen=True)
class ExtractedFunction:
    arch: str
    name: str
    address: int
    size: int
    instructions: tuple[ExtractedInstruction, ...]


@dataclass(frozen=True)
class BasicBlock:
    block_id: str
    arch: str
    function: str
    instructions: tuple[ExtractedInstruction, ...]

    @property
    def source_key(self) -> tuple[str, tuple[int, ...]] | None:
        locations = [inst.source for inst in self.instructions if inst.source is not None]
        if not locations:
            return None
        files = {loc.file for loc in locations}
        if len(files) != 1:
            return None
        return (locations[0].file, tuple(sorted({loc.line for loc in locations})))


@dataclass(frozen=True)
class AlignmentRegion:
    region_id: str
    function: str
    source_file: str
    source_lines: tuple[int, ...]
    guest_instructions: tuple[ExtractedInstruction, ...]
    host_instructions: tuple[ExtractedInstruction, ...]


@dataclass(frozen=True)
class InstructionWindow:
    region_id: str
    side: str
    instructions: tuple[ExtractedInstruction, ...]

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def code_hex(self) -> str:
        return b"".join(inst.code_bytes for inst in self.instructions).hex()

    @property
    def address(self) -> int:
        return self.instructions[0].address

    @property
    def source_span(self) -> str:
        locations = [inst.source for inst in self.instructions if inst.source is not None]
        if not locations:
            return "unknown"
        lines = sorted({loc.line for loc in locations})
        if len(lines) == 1:
            return f"{locations[0].label()}"
        return f"{Path(locations[0].file).name}:{lines[0]}-{lines[-1]}"


@dataclass(frozen=True)
class WindowPair:
    region_id: str
    stage: tuple[int, int]
    guest: InstructionWindow
    host: InstructionWindow
```

Create `src/angr_rule_learning/extraction/__init__.py`:

```python
from angr_rule_learning.extraction.config import ExtractionConfig, WindowLimits
from angr_rule_learning.extraction.models import (
    AlignmentRegion,
    BasicBlock,
    ExtractedFunction,
    ExtractedInstruction,
    InstructionWindow,
    SourceLocation,
    WindowPair,
)

__all__ = [
    "AlignmentRegion",
    "BasicBlock",
    "ExtractedFunction",
    "ExtractedInstruction",
    "ExtractionConfig",
    "InstructionWindow",
    "SourceLocation",
    "WindowLimits",
    "WindowPair",
]
```

- [ ] **Step 5: Implement diagnostics**

Create `src/angr_rule_learning/extraction/diagnostics.py`:

```python
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from statistics import mean


def _p95(values: list[int]) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * 0.95))
    return ordered[index]


@dataclass
class MiningDiagnostics:
    functions: int = 0
    regions: int = 0
    regions_skipped: int = 0
    windows_enumerated: int = 0
    windows_emitted: int = 0
    windows_verified: int = 0
    windows_verified_pass: int = 0
    skip_reasons: Counter[str] = field(default_factory=Counter)
    surface_kinds: Counter[str] = field(default_factory=Counter)
    _guest_sizes: list[int] = field(default_factory=list)
    _host_sizes: list[int] = field(default_factory=list)

    def record_function(self) -> None:
        self.functions += 1

    def record_region(self) -> None:
        self.regions += 1

    def record_region_skipped(self, reason: str) -> None:
        self.regions_skipped += 1
        self.skip_reasons[reason] += 1

    def record_window_enumerated(self, guest_size: int, host_size: int) -> None:
        self.windows_enumerated += 1
        self._guest_sizes.append(guest_size)
        self._host_sizes.append(host_size)

    def record_window_emitted(
        self,
        guest_size: int,
        host_size: int,
        surface_kinds: tuple[str, ...],
    ) -> None:
        self.windows_emitted += 1
        for kind in surface_kinds:
            self.surface_kinds[kind] += 1

    def record_window_verified(self, status: str) -> None:
        self.windows_verified += 1
        if status == "pass":
            self.windows_verified_pass += 1

    def record_window_skipped(self, reason: str) -> None:
        self.skip_reasons[reason] += 1

    def to_json(self) -> dict[str, object]:
        return {
            "functions": self.functions,
            "regions": self.regions,
            "regions_skipped": self.regions_skipped,
            "windows_enumerated": self.windows_enumerated,
            "windows_emitted": self.windows_emitted,
            "windows_verified": self.windows_verified,
            "windows_verified_pass": self.windows_verified_pass,
            "mean_guest_window_size": mean(self._guest_sizes) if self._guest_sizes else 0,
            "mean_host_window_size": mean(self._host_sizes) if self._host_sizes else 0,
            "p95_guest_window_size": _p95(self._guest_sizes),
            "p95_host_window_size": _p95(self._host_sizes),
            "max_guest_window_size": max(self._guest_sizes, default=0),
            "max_host_window_size": max(self._host_sizes, default=0),
            "skip_reasons": dict(sorted(self.skip_reasons.items())),
            "surface_kinds": dict(sorted(self.surface_kinds.items())),
        }
```

- [ ] **Step 6: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_extraction_models.py -v
git diff --check
git add pyproject.toml src/angr_rule_learning/extraction tests/test_extraction_models.py
git commit -m "Add extraction models and diagnostics"
```

Expected: test passes and ruff reports `All checks passed!`.

## Task 2: Fixed Clang Build Driver

**Files:**
- Create: `src/angr_rule_learning/extraction/build.py`
- Test: `tests/test_extraction_build.py`

- [ ] **Step 1: Write failing build driver tests**

Create `tests/test_extraction_build.py`:

```python
from pathlib import Path
import subprocess

from angr_rule_learning.extraction.build import BuildArtifacts, ClangBuildDriver
from angr_rule_learning.extraction.config import ExtractionConfig


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
    source.write_text("int add(int a, int b) { return a + b; }\\n", encoding="utf-8")
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
    assert "-c" in runner.commands[0]


def test_build_driver_reports_failed_command(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int f(void) { return 1; }\\n", encoding="utf-8")

    def failing_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, "", "clang failed")

    config = ExtractionConfig(source=source, work_dir=tmp_path / "out")

    try:
        ClangBuildDriver(runner=failing_runner).build(config)
    except RuntimeError as exc:
        assert "clang failed" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_build.py -v
```

Expected: import failure for `angr_rule_learning.extraction.build`.

- [ ] **Step 3: Implement build driver**

Create `src/angr_rule_learning/extraction/build.py`:

```python
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import subprocess

from angr_rule_learning.extraction.config import ExtractionConfig


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


TARGETS = {
    "aarch64": "aarch64-linux-gnu",
    "x86-64": "x86_64-linux-gnu",
}


@dataclass(frozen=True)
class BuildArtifacts:
    guest_object: Path
    host_object: Path
    commands: tuple[tuple[str, ...], ...]


def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


class ClangBuildDriver:
    def __init__(self, runner: Runner = _run_command) -> None:
        self._runner = runner

    def build(self, config: ExtractionConfig) -> BuildArtifacts:
        config.work_dir.mkdir(parents=True, exist_ok=True)
        guest_object = config.work_dir / f"guest-{config.guest_arch}.o"
        host_object = config.work_dir / f"host-{config.host_arch}.o"
        commands = (
            self._command(config, config.guest_arch, guest_object),
            self._command(config, config.host_arch, host_object),
        )
        for command in commands:
            result = self._runner(command)
            if result.returncode != 0:
                detail = result.stderr.strip() or result.stdout.strip() or "clang failed"
                raise RuntimeError(detail)
        return BuildArtifacts(
            guest_object=guest_object,
            host_object=host_object,
            commands=tuple(tuple(command) for command in commands),
        )

    def _command(self, config: ExtractionConfig, arch: str, output: Path) -> list[str]:
        try:
            target = TARGETS[arch]
        except KeyError as exc:
            raise ValueError(f"unsupported extraction target: {arch}") from exc
        return [
            config.clang,
            "-target",
            target,
            "-g",
            f"-O{config.optimization}",
            "-c",
            str(config.source),
            "-o",
            str(output),
        ]
```

- [ ] **Step 4: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_extraction_build.py tests/test_extraction_models.py -v
git diff --check
git add src/angr_rule_learning/extraction/build.py tests/test_extraction_build.py
git commit -m "Add fixed clang build driver"
```

Expected: tests pass and ruff reports `All checks passed!`.

## Task 3: Object Extraction From ELF, DWARF, And Capstone

**Files:**
- Create: `src/angr_rule_learning/extraction/object.py`
- Test: `tests/test_extraction_object.py`

- [ ] **Step 1: Write failing object extractor tests with monkeypatched low-level helpers**

Create `tests/test_extraction_object.py`:

```python
from pathlib import Path

from angr_rule_learning.extraction.models import ExtractedFunction, SourceLocation
from angr_rule_learning.extraction.object import ObjectExtractor, RawFunction, RawInstruction


def test_object_extractor_attaches_source_locations(monkeypatch, tmp_path: Path) -> None:
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
            RawInstruction(0x1000, 4, bytes.fromhex("2000028b"), "add", "x0, x1, x2", ("x1", "x2"), ("x0",), ()),
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


def test_object_extractor_rejects_empty_function_set(monkeypatch, tmp_path: Path) -> None:
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
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_object.py -v
```

Expected: import failure for `angr_rule_learning.extraction.object`.

- [ ] **Step 3: Implement object extraction API and patchable helpers**

Create `src/angr_rule_learning/extraction/object.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile

from angr_rule_learning.extraction.models import (
    ExtractedFunction,
    ExtractedInstruction,
    SourceLocation,
)


@dataclass(frozen=True)
class RawFunction:
    name: str
    address: int
    size: int
    code_bytes: bytes


@dataclass(frozen=True)
class RawInstruction:
    address: int
    size: int
    code_bytes: bytes
    mnemonic: str
    op_str: str
    read_registers: tuple[str, ...]
    write_registers: tuple[str, ...]
    groups: tuple[str, ...]


class ObjectExtractor:
    def extract(self, path: Path, arch: str) -> tuple[ExtractedFunction, ...]:
        raw_functions = self._read_functions(path, arch)
        if not raw_functions:
            raise ValueError(f"{path}: no functions found")
        line_map = self._read_line_map(path)
        functions: list[ExtractedFunction] = []
        for raw_function in raw_functions:
            raw_instructions = self._disassemble_function(arch, raw_function)
            instructions = tuple(
                ExtractedInstruction(
                    arch=arch,
                    address=raw.address,
                    size=raw.size,
                    code_bytes=raw.code_bytes,
                    mnemonic=raw.mnemonic,
                    op_str=raw.op_str,
                    function=raw_function.name,
                    source=line_map.get(raw.address),
                    read_registers=raw.read_registers,
                    write_registers=raw.write_registers,
                    groups=raw.groups,
                )
                for raw in raw_instructions
            )
            functions.append(
                ExtractedFunction(
                    arch=arch,
                    name=raw_function.name,
                    address=raw_function.address,
                    size=raw_function.size,
                    instructions=instructions,
                )
            )
        return tuple(functions)

    def _read_functions(self, path: Path, arch: str) -> tuple[RawFunction, ...]:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            text = elf.get_section_by_name(".text")
            if text is None:
                return ()
            text_data = text.data()
            text_base = text["sh_addr"]
            symbol_table = elf.get_section_by_name(".symtab")
            if symbol_table is None:
                return ()
            functions: list[RawFunction] = []
            for symbol in symbol_table.iter_symbols():
                if symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                size = int(symbol["st_size"])
                if size <= 0:
                    continue
                address = int(symbol["st_value"])
                offset = address - text_base
                if offset < 0 or offset + size > len(text_data):
                    continue
                functions.append(
                    RawFunction(
                        name=symbol.name,
                        address=address,
                        size=size,
                        code_bytes=text_data[offset : offset + size],
                    )
                )
        return tuple(sorted(functions, key=lambda function: (function.address, function.name)))

    def _read_line_map(self, path: Path) -> dict[int, SourceLocation]:
        result: dict[int, SourceLocation] = {}
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            if not elf.has_dwarf_info():
                return result
            dwarf = elf.get_dwarf_info()
            for compile_unit in dwarf.iter_CUs():
                line_program = dwarf.line_program_for_CU(compile_unit)
                if line_program is None:
                    continue
                file_entries = line_program["file_entry"]
                include_dirs = [entry.decode("utf-8", errors="replace") for entry in line_program["include_directory"]]
                for entry in line_program.get_entries():
                    state = entry.state
                    if state is None or state.end_sequence or state.file == 0:
                        continue
                    file_entry = file_entries[state.file - 1]
                    file_name = file_entry.name.decode("utf-8", errors="replace")
                    if file_entry.dir_index:
                        directory = include_dirs[file_entry.dir_index - 1]
                        file_name = f"{directory}/{file_name}"
                    result[int(state.address)] = SourceLocation(
                        file=file_name,
                        line=int(state.line),
                        column=int(state.column or 0),
                    )
        return result

    def _disassemble_function(
        self,
        arch: str,
        raw_function: RawFunction,
    ) -> tuple[RawInstruction, ...]:
        disassembler = _capstone_for_arch(arch)
        result: list[RawInstruction] = []
        for insn in disassembler.disasm(raw_function.code_bytes, raw_function.address):
            try:
                reads, writes = insn.regs_access()
            except capstone.CsError:
                reads, writes = ([], [])
            result.append(
                RawInstruction(
                    address=int(insn.address),
                    size=int(insn.size),
                    code_bytes=bytes(insn.bytes),
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    read_registers=tuple(disassembler.reg_name(reg) for reg in reads),
                    write_registers=tuple(disassembler.reg_name(reg) for reg in writes),
                    groups=tuple(disassembler.group_name(group) for group in insn.groups),
                )
            )
        return tuple(result)


def _capstone_for_arch(arch: str) -> capstone.Cs:
    normalized = arch.strip().lower()
    if normalized == "aarch64":
        disassembler = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    elif normalized == "x86-64":
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        raise ValueError(f"unsupported extraction architecture: {arch}")
    disassembler.detail = True
    return disassembler
```

- [ ] **Step 4: Add a smoke test that compiles only when clang target works**

Append to `tests/test_extraction_object.py`:

```python
import shutil
import subprocess

from angr_rule_learning.extraction.build import ClangBuildDriver
from angr_rule_learning.extraction.config import ExtractionConfig


def test_object_extractor_reads_compiled_host_object(tmp_path: Path) -> None:
    if shutil.which("clang") is None:
        return
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\\n", encoding="utf-8")
    config = ExtractionConfig(source=source, work_dir=tmp_path / "out")
    try:
        artifacts = ClangBuildDriver().build(config)
    except RuntimeError:
        return

    functions = ObjectExtractor().extract(artifacts.host_object, "x86-64")

    assert any(function.name == "add" for function in functions)
    add_function = next(function for function in functions if function.name == "add")
    assert add_function.instructions
    assert any(inst.source is not None for inst in add_function.instructions)
```

- [ ] **Step 5: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_extraction_object.py tests/test_extraction_build.py -v
git diff --check
git add src/angr_rule_learning/extraction/object.py tests/test_extraction_object.py pyproject.toml
git commit -m "Extract functions and debug locations from objects"
```

Expected: tests pass on machines with pyelftools/capstone available.

## Task 4: Basic Blocks And Alignment Regions

**Files:**
- Create: `src/angr_rule_learning/extraction/blocks.py`
- Create: `src/angr_rule_learning/extraction/align.py`
- Test: `tests/test_extraction_align.py`

- [ ] **Step 1: Write failing block/alignment tests**

Create `tests/test_extraction_align.py`:

```python
from angr_rule_learning.extraction.align import AlignmentRegionBuilder
from angr_rule_learning.extraction.blocks import BasicBlockBuilder
from angr_rule_learning.extraction.models import (
    BasicBlock,
    ExtractedFunction,
    ExtractedInstruction,
    SourceLocation,
)
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics


def _inst(arch: str, address: int, mnemonic: str, line: int) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4 if arch == "aarch64" else 1,
        code_bytes=b"\\x00" * (4 if arch == "aarch64" else 1),
        mnemonic=mnemonic,
        op_str="",
        function="add",
        source=SourceLocation("sample.c", line),
    )


def test_basic_block_builder_splits_after_control_flow() -> None:
    function = ExtractedFunction(
        arch="aarch64",
        name="add",
        address=0x1000,
        size=12,
        instructions=(
            _inst("aarch64", 0x1000, "cmp", 3),
            _inst("aarch64", 0x1004, "b.eq", 3),
            _inst("aarch64", 0x1008, "add", 4),
        ),
    )

    blocks = BasicBlockBuilder().build(function)

    assert len(blocks) == 2
    assert [inst.mnemonic for inst in blocks[0].instructions] == ["cmp", "b.eq"]
    assert [inst.mnemonic for inst in blocks[1].instructions] == ["add"]


def test_alignment_pairs_same_function_and_source_span() -> None:
    guest_block = BasicBlock("g0", "aarch64", "add", (_inst("aarch64", 0x1000, "add", 3),))
    host_block = BasicBlock("h0", "x86-64", "add", (_inst("x86-64", 0x2000, "lea", 3),))
    diagnostics = MiningDiagnostics()

    regions = AlignmentRegionBuilder(diagnostics).build((guest_block,), (host_block,))

    assert len(regions) == 1
    assert regions[0].region_id == "add:sample.c:3:0"
    assert regions[0].guest_instructions == guest_block.instructions
    assert regions[0].host_instructions == host_block.instructions


def test_alignment_skips_ambiguous_block_counts() -> None:
    guest_blocks = (
        BasicBlock("g0", "aarch64", "add", (_inst("aarch64", 0x1000, "add", 3),)),
        BasicBlock("g1", "aarch64", "add", (_inst("aarch64", 0x1004, "sub", 3),)),
    )
    host_blocks = (BasicBlock("h0", "x86-64", "add", (_inst("x86-64", 0x2000, "lea", 3),)),)
    diagnostics = MiningDiagnostics()

    regions = AlignmentRegionBuilder(diagnostics).build(guest_blocks, host_blocks)

    assert regions == ()
    assert diagnostics.to_json()["skip_reasons"] == {"ambiguous_alignment_region": 1}
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_align.py -v
```

Expected: import failure for `blocks` or `align`.

- [ ] **Step 3: Implement block builder**

Create `src/angr_rule_learning/extraction/blocks.py`:

```python
from __future__ import annotations

from angr_rule_learning.extraction.models import BasicBlock, ExtractedFunction, ExtractedInstruction


CONTROL_FLOW_PREFIXES = {
    "aarch64": ("b", "cbz", "cbnz", "tbz", "tbnz", "br", "blr", "ret", "eret"),
    "x86-64": ("j", "ret", "call", "syscall", "int"),
}


class BasicBlockBuilder:
    def build(self, function: ExtractedFunction) -> tuple[BasicBlock, ...]:
        blocks: list[BasicBlock] = []
        current: list[ExtractedInstruction] = []
        for instruction in function.instructions:
            current.append(instruction)
            if _is_control_flow(function.arch, instruction.mnemonic):
                blocks.append(_block(function, len(blocks), tuple(current)))
                current = []
        if current:
            blocks.append(_block(function, len(blocks), tuple(current)))
        return tuple(blocks)


def _block(
    function: ExtractedFunction,
    index: int,
    instructions: tuple[ExtractedInstruction, ...],
) -> BasicBlock:
    return BasicBlock(
        block_id=f"{function.name}:{index}",
        arch=function.arch,
        function=function.name,
        instructions=instructions,
    )


def _is_control_flow(arch: str, mnemonic: str) -> bool:
    normalized = mnemonic.strip().lower()
    prefixes = CONTROL_FLOW_PREFIXES.get(arch.strip().lower(), ())
    if arch.strip().lower() == "x86-64" and normalized == "jmp":
        return True
    return any(normalized.startswith(prefix) for prefix in prefixes)
```

- [ ] **Step 4: Implement alignment region builder**

Create `src/angr_rule_learning/extraction/align.py`:

```python
from __future__ import annotations

from collections import defaultdict

from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.models import AlignmentRegion, BasicBlock


class AlignmentRegionBuilder:
    def __init__(self, diagnostics: MiningDiagnostics) -> None:
        self._diagnostics = diagnostics

    def build(
        self,
        guest_blocks: tuple[BasicBlock, ...],
        host_blocks: tuple[BasicBlock, ...],
    ) -> tuple[AlignmentRegion, ...]:
        guest_groups = _group_blocks(guest_blocks)
        host_groups = _group_blocks(host_blocks)
        regions: list[AlignmentRegion] = []
        for key in sorted(set(guest_groups) | set(host_groups)):
            guest_group = guest_groups.get(key, ())
            host_group = host_groups.get(key, ())
            if len(guest_group) != 1 or len(host_group) != 1:
                self._diagnostics.record_region_skipped("ambiguous_alignment_region")
                continue
            function, file_name, lines = key
            ordinal = len([region for region in regions if region.function == function])
            region_id = f"{function}:{file_name}:{_line_label(lines)}:{ordinal}"
            region = AlignmentRegion(
                region_id=region_id,
                function=function,
                source_file=file_name,
                source_lines=lines,
                guest_instructions=guest_group[0].instructions,
                host_instructions=host_group[0].instructions,
            )
            self._diagnostics.record_region()
            regions.append(region)
        return tuple(regions)


def _group_blocks(
    blocks: tuple[BasicBlock, ...],
) -> dict[tuple[str, str, tuple[int, ...]], tuple[BasicBlock, ...]]:
    groups: dict[tuple[str, str, tuple[int, ...]], list[BasicBlock]] = defaultdict(list)
    for block in blocks:
        source_key = block.source_key
        if source_key is None:
            continue
        file_name, lines = source_key
        groups[(block.function, file_name, lines)].append(block)
    return {key: tuple(value) for key, value in groups.items()}


def _line_label(lines: tuple[int, ...]) -> str:
    if len(lines) == 1:
        return str(lines[0])
    return f"{lines[0]}-{lines[-1]}"
```

- [ ] **Step 5: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_extraction_align.py -v
git diff --check
git add src/angr_rule_learning/extraction/blocks.py src/angr_rule_learning/extraction/align.py tests/test_extraction_align.py
git commit -m "Build source-aligned extraction regions"
```

Expected: tests pass and ruff reports `All checks passed!`.

## Task 5: Bounded Window Mining And Verified-Window Subsumption

**Files:**
- Create: `src/angr_rule_learning/extraction/windows.py`
- Test: `tests/test_extraction_windows.py`

- [ ] **Step 1: Write failing window miner tests**

Create `tests/test_extraction_windows.py`:

```python
from angr_rule_learning.extraction.config import WindowLimits
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.models import AlignmentRegion, ExtractedInstruction, SourceLocation
from angr_rule_learning.extraction.windows import VerifiedWindowSet, WindowMiner


def _inst(arch: str, address: int, index: int) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4 if arch == "aarch64" else 1,
        code_bytes=bytes([index]) * (4 if arch == "aarch64" else 1),
        mnemonic="add",
        op_str="",
        function="f",
        source=SourceLocation("sample.c", 3),
    )


def _region() -> AlignmentRegion:
    return AlignmentRegion(
        region_id="r0",
        function="f",
        source_file="sample.c",
        source_lines=(3,),
        guest_instructions=(_inst("aarch64", 0x1000, 1), _inst("aarch64", 0x1004, 2)),
        host_instructions=(_inst("x86-64", 0x2000, 3), _inst("x86-64", 0x2001, 4), _inst("x86-64", 0x2002, 5)),
    )


def test_window_miner_enumerates_in_stage_order() -> None:
    diagnostics = MiningDiagnostics()
    windows = WindowMiner(WindowLimits(), diagnostics).enumerate_region(_region())

    assert windows[0].stage == (1, 1)
    assert windows[0].guest.instruction_count == 1
    assert windows[0].host.instruction_count == 1
    assert (1, 3) in [window.stage for window in windows]
    assert (2, 3) in [window.stage for window in windows]
    assert diagnostics.to_json()["windows_enumerated"] == len(windows)


def test_verified_window_set_detects_composite_coverage() -> None:
    windows = WindowMiner(WindowLimits(), MiningDiagnostics()).enumerate_region(_region())
    first = next(window for window in windows if window.guest.instruction_count == 1 and window.host.instruction_count == 1)
    second = next(
        window
        for window in windows
        if window.guest.instructions[0].address == 0x1004
        and window.host.instructions[0].address == 0x2001
        and window.guest.instruction_count == 1
        and window.host.instruction_count == 1
    )
    large = next(
        window
        for window in windows
        if window.guest.instruction_count == 2
        and window.host.instruction_count == 2
        and window.host.instructions[0].address == 0x2000
    )
    verified = VerifiedWindowSet()

    verified.add(first)
    verified.add(second)

    assert verified.covers(large)


def test_window_miner_prunes_verified_composites() -> None:
    region = _region()
    diagnostics = MiningDiagnostics()
    miner = WindowMiner(WindowLimits(), diagnostics)
    windows = miner.enumerate_region(region)
    verified = VerifiedWindowSet()
    for window in windows:
        if window.stage == (1, 1):
            verified.add(window)

    pruned = miner.prune_composites(windows, verified)

    assert all(not verified.covers(window) for window in pruned if window.stage != (1, 1))
    assert diagnostics.to_json()["skip_reasons"]["subsumed_by_smaller_window"] > 0
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_windows.py -v
```

Expected: import failure for `windows`.

- [ ] **Step 3: Implement window mining**

Create `src/angr_rule_learning/extraction/windows.py`:

```python
from __future__ import annotations

from dataclasses import dataclass, field

from angr_rule_learning.extraction.config import WindowLimits
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.models import AlignmentRegion, InstructionWindow, WindowPair


@dataclass
class VerifiedWindowSet:
    _windows_by_region: dict[str, list[WindowPair]] = field(default_factory=dict)

    def add(self, window: WindowPair) -> None:
        self._windows_by_region.setdefault(window.region_id, []).append(window)

    def covers(self, window: WindowPair) -> bool:
        smaller = [
            existing
            for existing in self._windows_by_region.get(window.region_id, [])
            if _window_area(existing) < _window_area(window)
        ]
        guest_target = _address_span(window.guest)
        host_target = _address_span(window.host)
        guest_spans = sorted(_address_span(existing.guest) for existing in smaller)
        host_spans = sorted(_address_span(existing.host) for existing in smaller)
        return _covers_span(guest_target, guest_spans) and _covers_span(host_target, host_spans)


class WindowMiner:
    def __init__(self, limits: WindowLimits, diagnostics: MiningDiagnostics) -> None:
        self._limits = limits
        self._diagnostics = diagnostics

    def enumerate_region(self, region: AlignmentRegion) -> tuple[WindowPair, ...]:
        result: list[WindowPair] = []
        for stage in self._limits.stage_order():
            guest_size, host_size = stage
            for guest_start in range(0, len(region.guest_instructions) - guest_size + 1):
                for host_start in range(0, len(region.host_instructions) - host_size + 1):
                    self._diagnostics.record_window_enumerated(guest_size, host_size)
                    result.append(
                        WindowPair(
                            region_id=region.region_id,
                            stage=stage,
                            guest=InstructionWindow(
                                region_id=region.region_id,
                                side="guest",
                                instructions=region.guest_instructions[guest_start : guest_start + guest_size],
                            ),
                            host=InstructionWindow(
                                region_id=region.region_id,
                                side="host",
                                instructions=region.host_instructions[host_start : host_start + host_size],
                            ),
                        )
                    )
        return tuple(result)

    def prune_composites(
        self,
        windows: tuple[WindowPair, ...],
        verified: VerifiedWindowSet,
    ) -> tuple[WindowPair, ...]:
        result: list[WindowPair] = []
        for window in windows:
            if verified.covers(window):
                self._diagnostics.record_window_skipped("subsumed_by_smaller_window")
                continue
            result.append(window)
        return tuple(result)


def _window_area(window: WindowPair) -> int:
    return window.guest.instruction_count + window.host.instruction_count


def _address_span(window: InstructionWindow) -> tuple[int, int]:
    return (window.instructions[0].address, window.instructions[-1].end_address)


def _covers_span(target: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    cursor = target[0]
    for start, end in spans:
        if end <= cursor:
            continue
        if start != cursor:
            continue
        cursor = end
        if cursor == target[1]:
            return True
    return False
```

- [ ] **Step 4: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_extraction_windows.py -v
git diff --check
git add src/angr_rule_learning/extraction/windows.py tests/test_extraction_windows.py
git commit -m "Add bounded semantic window mining"
```

Expected: tests pass and ruff reports `All checks passed!`.

## Task 6: Conservative Surface Inference And Candidate Emission

**Files:**
- Create: `src/angr_rule_learning/extraction/surfaces.py`
- Create: `src/angr_rule_learning/extraction/emit.py`
- Test: `tests/test_extraction_surfaces.py`
- Test: `tests/test_extraction_emit.py`

- [ ] **Step 1: Write failing surface inference tests**

Create `tests/test_extraction_surfaces.py`:

```python
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.models import ExtractedInstruction, InstructionWindow, SourceLocation, WindowPair
from angr_rule_learning.extraction.surfaces import SurfaceInferer


def _inst(
    arch: str,
    address: int,
    reads: tuple[str, ...],
    writes: tuple[str, ...],
    mnemonic: str = "add",
) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4 if arch == "aarch64" else 3,
        code_bytes=b"\\x01" * (4 if arch == "aarch64" else 3),
        mnemonic=mnemonic,
        op_str="",
        function="add",
        source=SourceLocation("sample.c", 3),
        read_registers=reads,
        write_registers=writes,
    )


def _pair(guest: ExtractedInstruction, host: ExtractedInstruction) -> WindowPair:
    return WindowPair(
        region_id="r0",
        stage=(1, 1),
        guest=InstructionWindow("r0", "guest", (guest,)),
        host=InstructionWindow("r0", "host", (host,)),
    )


def test_surface_inferer_pairs_register_reads_and_writes() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1", "x2"), ("x0",)),
        _inst("x86-64", 0x2000, ("rcx", "rdx"), ("rax",)),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics).infer(pair)

    assert candidate is not None
    assert candidate.input_registers == (("x1", "rcx"), ("x2", "rdx"))
    assert candidate.output_registers == (("x0", "rax"),)
    assert candidate.guest.code_hex == "01010101"
    assert candidate.host.code_hex == "010101"


def test_surface_inferer_skips_no_output_surface() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1",), ()),
        _inst("x86-64", 0x2000, ("rcx",), ()),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics).infer(pair)

    assert candidate is None
    assert diagnostics.to_json()["skip_reasons"] == {"no_verifiable_surface": 1}


def test_surface_inferer_skips_ambiguous_register_counts() -> None:
    pair = _pair(
        _inst("aarch64", 0x1000, ("x1", "x2"), ("x0",)),
        _inst("x86-64", 0x2000, ("rcx",), ("rax",)),
    )
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics).infer(pair)

    assert candidate is None
    assert diagnostics.to_json()["skip_reasons"] == {"ambiguous_register_surface": 1}
```

- [ ] **Step 2: Write failing emitter tests**

Create `tests/test_extraction_emit.py`:

```python
import json
from pathlib import Path

from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.emit import write_candidates_jsonl, write_diagnostics_json
from angr_rule_learning.verification.candidate import CodeFragment, VerificationCandidate
from angr_rule_learning.io.readers import read_candidates


def test_write_candidates_jsonl_round_trips_through_schema(tmp_path: Path) -> None:
    candidate = VerificationCandidate(
        candidate_id="sample:add:3:0:g0:h0",
        guest=CodeFragment("aarch64", 0x1000, "20 00 02 8b", 1),
        host=CodeFragment("x86-64", 0x2000, "48 8d 04 11", 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("x0", "rax"),),
    )
    output = tmp_path / "candidates.jsonl"

    write_candidates_jsonl(output, (candidate,))

    assert list(read_candidates(output)) == [candidate]
    assert json.loads(output.read_text(encoding="utf-8"))["candidate_id"] == candidate.candidate_id


def test_write_diagnostics_json(tmp_path: Path) -> None:
    diagnostics = MiningDiagnostics()
    diagnostics.record_window_skipped("no_verifiable_surface")
    output = tmp_path / "diagnostics.json"

    write_diagnostics_json(output, diagnostics)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["skip_reasons"] == {"no_verifiable_surface": 1}
```

- [ ] **Step 3: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_surfaces.py tests/test_extraction_emit.py -v
```

Expected: import failures for `surfaces` and `emit`.

- [ ] **Step 4: Implement conservative surface inference**

Create `src/angr_rule_learning/extraction/surfaces.py`:

```python
from __future__ import annotations

from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.models import ExtractedInstruction, WindowPair
from angr_rule_learning.verification.candidate import (
    Clobbers,
    CodeFragment,
    MemorySpec,
    VerificationCandidate,
)


class SurfaceInferer:
    def __init__(self, diagnostics: MiningDiagnostics) -> None:
        self._diagnostics = diagnostics

    def infer(self, pair: WindowPair) -> VerificationCandidate | None:
        guest_reads = _ordered_unique(
            reg for inst in pair.guest.instructions for reg in inst.read_registers
        )
        host_reads = _ordered_unique(
            reg for inst in pair.host.instructions for reg in inst.read_registers
        )
        guest_writes = _ordered_unique(
            reg for inst in pair.guest.instructions for reg in inst.write_registers
        )
        host_writes = _ordered_unique(
            reg for inst in pair.host.instructions for reg in inst.write_registers
        )
        if len(guest_reads) != len(host_reads) or len(guest_writes) != len(host_writes):
            self._diagnostics.record_window_skipped("ambiguous_register_surface")
            return None
        if not guest_writes and not _has_terminal_conditional_branch(pair):
            self._diagnostics.record_window_skipped("no_verifiable_surface")
            return None
        candidate = VerificationCandidate(
            candidate_id=_candidate_id(pair),
            guest=CodeFragment(
                pair.guest.instructions[0].arch,
                pair.guest.address,
                pair.guest.code_hex,
                pair.guest.instruction_count,
            ),
            host=CodeFragment(
                pair.host.instructions[0].arch,
                pair.host.address,
                pair.host.code_hex,
                pair.host.instruction_count,
            ),
            input_registers=tuple(zip(guest_reads, host_reads, strict=True)),
            output_registers=tuple(zip(guest_writes, host_writes, strict=True)),
            output_flags=(),
            memory=MemorySpec(),
            preconditions=(),
            clobbers=Clobbers(),
        )
        self._diagnostics.record_window_emitted(
            pair.guest.instruction_count,
            pair.host.instruction_count,
            ("register",) if guest_writes else ("branch",),
        )
        return candidate


def _ordered_unique(values) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def _has_terminal_conditional_branch(pair: WindowPair) -> bool:
    return _is_conditional(pair.guest.instructions[-1]) and _is_conditional(pair.host.instructions[-1])


def _is_conditional(instruction: ExtractedInstruction) -> bool:
    mnemonic = instruction.mnemonic.lower()
    if instruction.arch == "aarch64":
        return mnemonic.startswith(("b.", "cbz", "cbnz", "tbz", "tbnz"))
    if instruction.arch == "x86-64":
        return mnemonic.startswith("j") and mnemonic != "jmp"
    return False


def _candidate_id(pair: WindowPair) -> str:
    return (
        f"{pair.region_id}:"
        f"g{pair.guest.instructions[0].address:x}-{pair.guest.instructions[-1].end_address:x}:"
        f"h{pair.host.instructions[0].address:x}-{pair.host.instructions[-1].end_address:x}"
    )
```

- [ ] **Step 5: Implement emitters**

Create `src/angr_rule_learning/extraction/emit.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.io.schema import report_to_json
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport


def candidate_to_json(candidate: VerificationCandidate) -> dict[str, object]:
    return {
        "candidate_id": candidate.candidate_id,
        "guest": _fragment_to_json(candidate.guest),
        "host": _fragment_to_json(candidate.host),
        "inputs": {"registers": [list(pair) for pair in candidate.input_registers]},
        "outputs": {
            "registers": [list(pair) for pair in candidate.output_registers],
            "flags": [list(pair) for pair in candidate.output_flags],
        },
        "memory": {
            "slots": [],
            "bindings": [],
            "accesses": [],
            "alias": [],
        },
        "preconditions": list(candidate.preconditions),
        "clobbers": {
            "guest": list(candidate.clobbers.guest),
            "host": list(candidate.clobbers.host),
        },
    }


def write_candidates_jsonl(path: Path, candidates: tuple[VerificationCandidate, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(candidate_to_json(candidate), sort_keys=True) for candidate in candidates]
    path.write_text("\\n".join(lines) + ("\\n" if lines else ""), encoding="utf-8")


def write_diagnostics_json(path: Path, diagnostics: MiningDiagnostics) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(diagnostics.to_json(), indent=2, sort_keys=True) + "\\n", encoding="utf-8")


def write_reports_jsonl(path: Path, reports: tuple[VerificationReport, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(report_to_json(report), sort_keys=True) for report in reports]
    path.write_text("\\n".join(lines) + ("\\n" if lines else ""), encoding="utf-8")


def _fragment_to_json(fragment) -> dict[str, object]:
    return {
        "arch": fragment.arch,
        "address": fragment.address,
        "code_hex": fragment.code_hex,
        "instruction_count": fragment.instruction_count,
    }
```

- [ ] **Step 6: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_extraction_surfaces.py tests/test_extraction_emit.py -v
git diff --check
git add src/angr_rule_learning/extraction/surfaces.py src/angr_rule_learning/extraction/emit.py tests/test_extraction_surfaces.py tests/test_extraction_emit.py
git commit -m "Infer verifier surfaces for mined windows"
```

Expected: tests pass and ruff reports `All checks passed!`.

## Task 7: Source-To-Candidate Pipeline And CLI

**Files:**
- Create: `src/angr_rule_learning/extraction/pipeline.py`
- Modify: `src/angr_rule_learning/cli.py`
- Test: `tests/test_extraction_pipeline.py`

- [ ] **Step 1: Write failing pipeline tests with stubbed stages**

Create `tests/test_extraction_pipeline.py`:

```python
import json
from pathlib import Path

from angr_rule_learning.extraction.config import ExtractionConfig
from angr_rule_learning.extraction.models import AlignmentRegion, ExtractedInstruction, SourceLocation
from angr_rule_learning.extraction.pipeline import ExtractionPipeline
from angr_rule_learning.io.readers import read_candidates


def _inst(arch: str, address: int, code: bytes, reads: tuple[str, ...], writes: tuple[str, ...]) -> ExtractedInstruction:
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
    source.write_text("int add(int a, int b) { return a + b; }\\n", encoding="utf-8")
    output = tmp_path / "candidates.jsonl"
    diagnostics_path = tmp_path / "diagnostics.json"
    region = AlignmentRegion(
        region_id="add:sample.c:1:0",
        function="add",
        source_file="sample.c",
        source_lines=(1,),
        guest_instructions=(_inst("aarch64", 0x1000, bytes.fromhex("2000028b"), ("x1", "x2"), ("x0",)),),
        host_instructions=(_inst("x86-64", 0x2000, bytes.fromhex("488d0411"), ("rcx", "rdx"), ("rax",)),),
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
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_pipeline.py -v
```

Expected: import failure for `pipeline`.

- [ ] **Step 3: Implement pipeline orchestration**

Create `src/angr_rule_learning/extraction/pipeline.py`:

```python
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from angr_rule_learning.extraction.align import AlignmentRegionBuilder
from angr_rule_learning.extraction.blocks import BasicBlockBuilder
from angr_rule_learning.extraction.build import BuildArtifacts, ClangBuildDriver
from angr_rule_learning.extraction.config import ExtractionConfig
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.emit import write_candidates_jsonl, write_diagnostics_json
from angr_rule_learning.extraction.models import AlignmentRegion, WindowPair
from angr_rule_learning.extraction.object import ObjectExtractor
from angr_rule_learning.extraction.surfaces import SurfaceInferer
from angr_rule_learning.extraction.windows import VerifiedWindowSet, WindowMiner
from angr_rule_learning.verification.batch import BatchVerifier
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport


RegionProvider = Callable[[ExtractionConfig, MiningDiagnostics], tuple[AlignmentRegion, ...]]


@dataclass(frozen=True)
class ExtractionResult:
    candidates: tuple[VerificationCandidate, ...]
    reports: tuple[VerificationReport, ...]
    diagnostics: MiningDiagnostics


class ExtractionPipeline:
    def __init__(
        self,
        build_driver: ClangBuildDriver | None = None,
        object_extractor: ObjectExtractor | None = None,
        region_provider: RegionProvider | None = None,
        verifier: BatchVerifier | None = None,
    ) -> None:
        self._build_driver = build_driver or ClangBuildDriver()
        self._object_extractor = object_extractor or ObjectExtractor()
        self._region_provider = region_provider
        self._verifier = verifier or BatchVerifier()

    def run(
        self,
        config: ExtractionConfig,
        *,
        candidates_output: Path,
        diagnostics_output: Path,
        verify: bool = False,
    ) -> ExtractionResult:
        diagnostics = MiningDiagnostics()
        regions = self._regions(config, diagnostics)
        miner = WindowMiner(config.window_limits, diagnostics)
        inferer = SurfaceInferer(diagnostics)
        verified = VerifiedWindowSet()
        candidates: list[VerificationCandidate] = []
        reports: list[VerificationReport] = []
        for region in regions:
            windows = miner.enumerate_region(region)
            for stage in config.window_limits.stage_order():
                staged = tuple(window for window in windows if window.stage == stage)
                staged = miner.prune_composites(staged, verified)
                emitted: list[tuple[WindowPair, VerificationCandidate]] = []
                for window in staged:
                    candidate = inferer.infer(window)
                    if candidate is not None:
                        emitted.append((window, candidate))
                staged_candidates = tuple(candidate for _, candidate in emitted)
                candidates.extend(staged_candidates)
                if verify and staged_candidates:
                    staged_reports = self._verifier.verify_many(staged_candidates)
                    reports.extend(staged_reports)
                    for (window, _candidate), report in zip(
                        emitted,
                        staged_reports,
                        strict=True,
                    ):
                        diagnostics.record_window_verified(report.status)
                        if report.status == "pass":
                            verified.add(window)
        candidate_tuple = tuple(candidates)
        write_candidates_jsonl(candidates_output, candidate_tuple)
        write_diagnostics_json(diagnostics_output, diagnostics)
        return ExtractionResult(candidate_tuple, tuple(reports), diagnostics)

    def _regions(
        self,
        config: ExtractionConfig,
        diagnostics: MiningDiagnostics,
    ) -> tuple[AlignmentRegion, ...]:
        if self._region_provider is not None:
            return self._region_provider(config, diagnostics)
        artifacts = self._build_driver.build(config)
        return self._extract_regions(artifacts, diagnostics)

    def _extract_regions(
        self,
        artifacts: BuildArtifacts,
        diagnostics: MiningDiagnostics,
    ) -> tuple[AlignmentRegion, ...]:
        guest_functions = self._object_extractor.extract(artifacts.guest_object, "aarch64")
        host_functions = self._object_extractor.extract(artifacts.host_object, "x86-64")
        block_builder = BasicBlockBuilder()
        guest_blocks = tuple(block for function in guest_functions for block in block_builder.build(function))
        host_blocks = tuple(block for function in host_functions for block in block_builder.build(function))
        for _function in guest_functions:
            diagnostics.record_function()
        return AlignmentRegionBuilder(diagnostics).build(guest_blocks, host_blocks)
```

- [ ] **Step 4: Add CLI extract command**

Modify `src/angr_rule_learning/cli.py`:

```python
from angr_rule_learning.extraction.config import ExtractionConfig, WindowLimits
from angr_rule_learning.extraction.pipeline import ExtractionPipeline
```

Add parser:

```python
    extract_parser = subparsers.add_parser(
        "extract", help="compile one C source and emit verifier candidates"
    )
    extract_parser.add_argument("source", type=Path)
    extract_parser.add_argument("--work-dir", required=True, type=Path)
    extract_parser.add_argument("--output", required=True, type=Path)
    extract_parser.add_argument("--diagnostics", required=True, type=Path)
    extract_parser.add_argument("--guest-max-window", type=int, default=2)
    extract_parser.add_argument("--host-max-window", type=int, default=3)
    extract_parser.add_argument("--verify", action="store_true")
```

Add command handling:

```python
    if args.command == "extract":
        config = ExtractionConfig(
            source=args.source,
            work_dir=args.work_dir,
            window_limits=WindowLimits(
                guest_max=args.guest_max_window,
                host_max=args.host_max_window,
            ),
        )
        ExtractionPipeline().run(
            config,
            candidates_output=args.output,
            diagnostics_output=args.diagnostics,
            verify=args.verify,
        )
        return
```

- [ ] **Step 5: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_extraction_pipeline.py tests/test_batch_cli.py -v
git diff --check
git add src/angr_rule_learning/extraction/pipeline.py src/angr_rule_learning/cli.py tests/test_extraction_pipeline.py
git commit -m "Add source extraction pipeline entry point"
```

Expected: tests pass and ruff reports `All checks passed!`.

## Task 8: Documentation And End-To-End Smoke

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/verifier.md`
- Test: `tests/test_extraction_pipeline.py`

- [ ] **Step 1: Add end-to-end CLI smoke test**

Append to `tests/test_extraction_pipeline.py`:

```python
import shutil

from angr_rule_learning.cli import main


def test_extract_cli_smoke(tmp_path: Path) -> None:
    if shutil.which("clang") is None:
        return
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\\n", encoding="utf-8")
    output = tmp_path / "candidates.jsonl"
    diagnostics = tmp_path / "diagnostics.json"
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
                str(diagnostics),
            ]
        )
    except RuntimeError:
        return

    assert output.exists()
    assert diagnostics.exists()
    payload = json.loads(diagnostics.read_text(encoding="utf-8"))
    assert "windows_enumerated" in payload
    assert "skip_reasons" in payload
```

- [ ] **Step 2: Update README**

Add under Quick Start:

````markdown
Extract verifier candidates from one C source file:

```bash
uv run angr-rule-learning extract examples/simple.c \
  --work-dir /tmp/angr-rule-learning-extract \
  --output /tmp/angr-rule-learning-candidates.jsonl \
  --diagnostics /tmp/angr-rule-learning-diagnostics.json
```
````

- [ ] **Step 3: Update architecture docs**

In `docs/architecture.md`, add `extraction/` to package structure and update data flow:

```text
single C source
  -> extraction.ExtractionPipeline
  -> candidate JSONL
  -> verification.BatchVerifier
```

- [ ] **Step 4: Verify full suite and CLI smoke**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest -q
uv run angr-rule-learning verify examples/aarch64_x86_64_batch.jsonl --output /tmp/angr-rule-learning-plan-check-report.jsonl --summary /tmp/angr-rule-learning-plan-check-summary.json
git diff --check
```

Expected:

```text
All checks passed!
112+ tests passed
CLI verify exits 0
```

The exact pytest count will be higher than 112 after extractor tests are added. Third-party Python 3.14 deprecation warnings from angr dependencies are acceptable if project tests pass.

- [ ] **Step 5: Commit docs and final integration**

Run:

```bash
git add README.md docs/architecture.md docs/verifier.md tests/test_extraction_pipeline.py
git commit -m "Document extractor-first candidate pipeline"
```

Expected: commit succeeds.

## Final Completion Checklist

Before declaring this implementation complete, run:

```bash
uv run ruff format --check
uv run ruff check
uv run pytest -q
uv run angr-rule-learning verify examples/aarch64_x86_64_batch.jsonl --output /tmp/angr-rule-learning-extractor-final-report.jsonl --summary /tmp/angr-rule-learning-extractor-final-summary.json
git status -sb
```

Required outcomes:

- formatting check passes;
- lint passes;
- full pytest passes;
- existing verifier CLI smoke exits 0;
- extractor docs describe the new `extract` command;
- working tree is clean.

## Claude Code Handoff Prompt

Use this prompt when handing execution to Claude Code:

```text
Execute docs/superpowers/plans/2026-06-11-extractor-first-pipeline-implementation.md task by task.

Follow the plan exactly:
- use TDD for every task;
- run each red test before implementing the task;
- run ruff format after Python edits;
- run ruff check and the task-specific pytest commands before every commit;
- commit after every task with the message specified in the plan;
- do not add rule generalization, rule storage, or coverage evaluation;
- do not emit verifier candidates with no inferred semantic surfaces;
- do not depend on llvm-objdump or llvm-dwarfdump;
- keep extractor output compatible with docs/candidate-format.md.

After all tasks, run the Final Completion Checklist and report the exact command outputs.
```
