# Skip Pattern Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only diagnostics analysis tool that explains high-volume `unparsed_memory_access` and `one_sided_memory_access` skips by aggregating concrete instruction patterns, source locations, functions, and window stages.

**Architecture:** Keep extraction and verification behavior unchanged. Add an `analysis` package that reuses the existing extraction pipeline components to enumerate aligned windows, classifies selected skip details, and emits JSON reports; add a thin CLI subcommand as a wrapper over the analysis API.

**Tech Stack:** Python 3.14, dataclasses, `collections.Counter`, existing extraction modules, pytest, ruff, existing `uv run` workflow.

---

## File Structure

- Create `src/angr_rule_learning/analysis/__init__.py`
  - Marks the analysis package.
- Create `src/angr_rule_learning/analysis/skip_patterns.py`
  - Owns pattern normalization, sample records, aggregation models, and the `SkipPatternAnalyzer` API.
- Modify `src/angr_rule_learning/cli.py`
  - Adds `diagnose-skips` subcommand as a thin wrapper.
- Create `tests/test_analysis_skip_patterns.py`
  - Unit tests for normalization, aggregation, and selected skip classification.
- Create or modify `tests/test_analysis_cli.py`
  - CLI-level smoke test with a fake/small analyzer path if practical; otherwise test `main()` writes expected JSON using a monkeypatched analyzer.
- Modify `docs/architecture.md`
  - Documents read-only skip pattern analysis as an observability extension.

Do not change:

- candidate filtering behavior;
- verifier behavior;
- rule generation behavior;
- existing extraction diagnostics schema except by reading it.

---

## Report Shape

The analyzer writes JSON with this shape:

```json
{
  "source": "samples/sources/smoke_int.c",
  "optimization": "0",
  "window_limits": {
    "guest_max": 2,
    "host_max": 3
  },
  "totals": {
    "windows_enumerated": 5070,
    "selected_skips": 2359
  },
  "details": {
    "unparsed_memory_access": {
      "total": 1467,
      "by_arch_mnemonic": {
        "aarch64:ldp": 120
      },
      "top_instruction_patterns": [
        {
          "count": 44,
          "arch": "aarch64",
          "mnemonic": "ldp",
          "op_str": "x29, x30, [sp], #16",
          "examples": [
            {
              "function": "add_i32",
              "source_span": "smoke_int.c:3-4",
              "stage": [1, 1],
              "guest": ["ldp x29, x30, [sp], #16"],
              "host": ["pop rbp"]
            }
          ]
        }
      ]
    },
    "one_sided_memory_access": {
      "total": 892,
      "by_stage": {
        "1x1": 200
      },
      "top_window_pairs": [
        {
          "count": 33,
          "guest_pattern": "str w0, [sp, #12]",
          "host_pattern": "mov eax, edi",
          "guest_memory_count": 1,
          "host_memory_count": 0,
          "examples": []
        }
      ]
    }
  }
}
```

The exact counts in tests should use synthetic fixtures, not `smoke_int.c`, so tests remain deterministic.

---

### Task 1: Core Models And Pattern Normalization

**Files:**
- Create: `src/angr_rule_learning/analysis/__init__.py`
- Create: `src/angr_rule_learning/analysis/skip_patterns.py`
- Test: `tests/test_analysis_skip_patterns.py`

- [ ] **Step 1: Write failing normalization tests**

Create `tests/test_analysis_skip_patterns.py` with:

```python
from angr_rule_learning.analysis.skip_patterns import (
    instruction_text,
    normalize_instruction_text,
)
from angr_rule_learning.extraction.models import ExtractedInstruction, SourceLocation


def _inst(
    arch: str,
    mnemonic: str,
    op_str: str,
    *,
    address: int = 0x1000,
) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic=mnemonic,
        op_str=op_str,
        function="sample",
        source=SourceLocation("sample.c", 7),
    )


def test_instruction_text_joins_mnemonic_and_operands() -> None:
    assert instruction_text(_inst("aarch64", "ldr", "w0, [x1]")) == "ldr w0, [x1]"
    assert instruction_text(_inst("aarch64", "ret", "")) == "ret"


def test_normalize_instruction_text_replaces_numbers_and_spacing() -> None:
    text = normalize_instruction_text("  mov   dword ptr [rbp - 0xc],  13 ")

    assert text == "mov dword ptr [rbp - IMM], IMM"
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
uv run pytest tests/test_analysis_skip_patterns.py -q
```

Expected: import failure because `angr_rule_learning.analysis.skip_patterns` does not exist.

- [ ] **Step 3: Implement minimal normalization API**

Create `src/angr_rule_learning/analysis/__init__.py`:

```python
"""Read-only analysis helpers for extraction diagnostics."""
```

Create `src/angr_rule_learning/analysis/skip_patterns.py` with:

```python
from __future__ import annotations

import re

from angr_rule_learning.extraction.models import ExtractedInstruction


_HEX_RE = re.compile(r"(?<![A-Za-z0-9_])-?0x[0-9a-fA-F]+")
_DEC_RE = re.compile(r"(?<![A-Za-z0-9_])-?\d+(?![A-Za-z0-9_])")


def instruction_text(instruction: ExtractedInstruction) -> str:
    mnemonic = instruction.mnemonic.strip()
    op_str = instruction.op_str.strip()
    if op_str:
        return f"{mnemonic} {op_str}"
    return mnemonic


def normalize_instruction_text(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text.strip().lower())
    normalized = _HEX_RE.sub("IMM", normalized)
    normalized = _DEC_RE.sub("IMM", normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
uv run pytest tests/test_analysis_skip_patterns.py -q
```

Expected: pass.

- [ ] **Step 5: Run formatting and lint**

Run:

```bash
uv run ruff format src/angr_rule_learning/analysis/__init__.py src/angr_rule_learning/analysis/skip_patterns.py tests/test_analysis_skip_patterns.py
uv run ruff check src/angr_rule_learning/analysis/__init__.py src/angr_rule_learning/analysis/skip_patterns.py tests/test_analysis_skip_patterns.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add src/angr_rule_learning/analysis/__init__.py src/angr_rule_learning/analysis/skip_patterns.py tests/test_analysis_skip_patterns.py
git commit -m "Add skip pattern normalization helpers"
```

---

### Task 2: In-Memory Aggregator For Selected Skip Details

**Files:**
- Modify: `src/angr_rule_learning/analysis/skip_patterns.py`
- Modify: `tests/test_analysis_skip_patterns.py`

- [ ] **Step 1: Write failing aggregation tests**

Append to `tests/test_analysis_skip_patterns.py`:

```python
from angr_rule_learning.analysis.skip_patterns import (
    SkipPatternAggregator,
)
from angr_rule_learning.extraction.models import InstructionWindow, WindowPair


def _window(
    region_id: str,
    side: str,
    instructions: tuple[ExtractedInstruction, ...],
) -> InstructionWindow:
    return InstructionWindow(region_id=region_id, side=side, instructions=instructions)


def _pair(
    guest: tuple[ExtractedInstruction, ...],
    host: tuple[ExtractedInstruction, ...],
    *,
    stage: tuple[int, int] = (1, 1),
    region_id: str = "sample:sample.c:7:0",
) -> WindowPair:
    return WindowPair(
        region_id=region_id,
        stage=stage,
        guest=_window(region_id, "guest", guest),
        host=_window(region_id, "host", host),
    )


def test_aggregator_records_unparsed_instruction_pattern() -> None:
    aggregator = SkipPatternAggregator(max_examples=2)
    pair = _pair(
        (_inst("aarch64", "ldp", "x0, x1, [x2]"),),
        (_inst("x86-64", "mov", "rax, qword ptr [rcx]"),),
    )

    aggregator.record("unparsed_memory_access", pair)
    payload = aggregator.to_json()

    detail = payload["details"]["unparsed_memory_access"]
    assert detail["total"] == 1
    assert detail["by_arch_mnemonic"] == {"aarch64:ldp": 1}
    assert detail["top_instruction_patterns"][0]["count"] == 1
    assert detail["top_instruction_patterns"][0]["arch"] == "aarch64"
    assert detail["top_instruction_patterns"][0]["mnemonic"] == "ldp"
    assert detail["top_instruction_patterns"][0]["examples"][0]["function"] == "sample"


def test_aggregator_records_one_sided_window_pair_pattern() -> None:
    aggregator = SkipPatternAggregator(max_examples=2)
    pair = _pair(
        (_inst("aarch64", "str", "w0, [sp, #12]"),),
        (_inst("x86-64", "mov", "eax, edi"),),
        stage=(1, 1),
    )

    aggregator.record("one_sided_memory_access", pair)
    payload = aggregator.to_json()

    detail = payload["details"]["one_sided_memory_access"]
    assert detail["total"] == 1
    assert detail["by_stage"] == {"1x1": 1}
    top = detail["top_window_pairs"][0]
    assert top["guest_memory_count"] == 1
    assert top["host_memory_count"] == 0
    assert top["guest_pattern"] == "str w0, [sp, #IMM]"
    assert top["host_pattern"] == "mov eax, edi"
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
uv run pytest tests/test_analysis_skip_patterns.py -q
```

Expected: failure because `SkipPatternAggregator` does not exist.

- [ ] **Step 3: Implement aggregation models**

Add to `src/angr_rule_learning/analysis/skip_patterns.py`:

```python
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from angr_rule_learning.extraction.memory_operands import has_any_memory_access
from angr_rule_learning.extraction.models import InstructionWindow, WindowPair
```

Then add:

```python
def _source_span(window: InstructionWindow) -> str:
    return window.source_span


def _window_lines(window: InstructionWindow) -> list[str]:
    return [instruction_text(inst) for inst in window.instructions]


def _window_pattern(window: InstructionWindow) -> str:
    return " | ".join(
        normalize_instruction_text(instruction_text(inst))
        for inst in window.instructions
    )


def _memory_count(window: InstructionWindow) -> int:
    return sum(1 for inst in window.instructions if has_any_memory_access(inst))


def _example(pair: WindowPair) -> dict[str, Any]:
    first = pair.guest.instructions[0] if pair.guest.instructions else pair.host.instructions[0]
    return {
        "function": first.function,
        "source_span": pair.guest.source_span,
        "stage": list(pair.stage),
        "guest": _window_lines(pair.guest),
        "host": _window_lines(pair.host),
    }
```

Add dataclasses:

```python
@dataclass
class _PatternBucket:
    count: int = 0
    examples: list[dict[str, Any]] = field(default_factory=list)

    def add(self, example: dict[str, Any], max_examples: int) -> None:
        self.count += 1
        if len(self.examples) < max_examples:
            self.examples.append(example)


@dataclass
class SkipPatternAggregator:
    max_examples: int = 5
    _totals: Counter[str] = field(default_factory=Counter)
    _by_arch_mnemonic: dict[str, Counter[str]] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    _by_stage: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    _instruction_patterns: dict[str, dict[tuple[str, str, str], _PatternBucket]] = field(
        default_factory=lambda: defaultdict(dict)
    )
    _window_pairs: dict[str, dict[tuple[str, str, int, int], _PatternBucket]] = field(
        default_factory=lambda: defaultdict(dict)
    )

    def record(self, detail: str, pair: WindowPair) -> None:
        self._totals[detail] += 1
        if detail == "unparsed_memory_access":
            self._record_unparsed(detail, pair)
        elif detail == "one_sided_memory_access":
            self._record_one_sided(detail, pair)

    def _record_unparsed(self, detail: str, pair: WindowPair) -> None:
        for window in (pair.guest, pair.host):
            for inst in window.instructions:
                if not has_any_memory_access(inst):
                    continue
                pattern = normalize_instruction_text(instruction_text(inst))
                key = (inst.arch, inst.mnemonic.strip().lower(), pattern)
                self._by_arch_mnemonic[detail][f"{key[0]}:{key[1]}"] += 1
                bucket = self._instruction_patterns[detail].setdefault(key, _PatternBucket())
                bucket.add(_example(pair), self.max_examples)

    def _record_one_sided(self, detail: str, pair: WindowPair) -> None:
        stage_key = f"{pair.stage[0]}x{pair.stage[1]}"
        self._by_stage[detail][stage_key] += 1
        guest_count = _memory_count(pair.guest)
        host_count = _memory_count(pair.host)
        key = (_window_pattern(pair.guest), _window_pattern(pair.host), guest_count, host_count)
        bucket = self._window_pairs[detail].setdefault(key, _PatternBucket())
        bucket.add(_example(pair), self.max_examples)

    def to_json(self) -> dict[str, Any]:
        details: dict[str, Any] = {}
        for detail, total in sorted(self._totals.items()):
            item: dict[str, Any] = {"total": total}
            if detail in self._by_arch_mnemonic:
                item["by_arch_mnemonic"] = dict(
                    sorted(self._by_arch_mnemonic[detail].items())
                )
                item["top_instruction_patterns"] = [
                    {
                        "count": bucket.count,
                        "arch": key[0],
                        "mnemonic": key[1],
                        "op_str": key[2],
                        "examples": bucket.examples,
                    }
                    for key, bucket in sorted(
                        self._instruction_patterns[detail].items(),
                        key=lambda entry: (-entry[1].count, entry[0]),
                    )
                ]
            if detail in self._by_stage:
                item["by_stage"] = dict(sorted(self._by_stage[detail].items()))
                item["top_window_pairs"] = [
                    {
                        "count": bucket.count,
                        "guest_pattern": key[0],
                        "host_pattern": key[1],
                        "guest_memory_count": key[2],
                        "host_memory_count": key[3],
                        "examples": bucket.examples,
                    }
                    for key, bucket in sorted(
                        self._window_pairs[detail].items(),
                        key=lambda entry: (-entry[1].count, entry[0]),
                    )
                ]
            details[detail] = item
        return {"details": details}
```

- [ ] **Step 4: Run tests and verify pass**

Run:

```bash
uv run pytest tests/test_analysis_skip_patterns.py -q
```

Expected: pass.

- [ ] **Step 5: Run formatting and lint**

Run:

```bash
uv run ruff format src/angr_rule_learning/analysis/skip_patterns.py tests/test_analysis_skip_patterns.py
uv run ruff check src/angr_rule_learning/analysis/skip_patterns.py tests/test_analysis_skip_patterns.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add src/angr_rule_learning/analysis/skip_patterns.py tests/test_analysis_skip_patterns.py
git commit -m "Aggregate selected skip patterns"
```

---

### Task 3: Reuse Extraction To Analyze Real Windows

**Files:**
- Modify: `src/angr_rule_learning/analysis/skip_patterns.py`
- Test: `tests/test_analysis_skip_patterns.py`

- [ ] **Step 1: Write failing analyzer tests with a fake region provider**

Append to `tests/test_analysis_skip_patterns.py`:

```python
from pathlib import Path

from angr_rule_learning.analysis.skip_patterns import (
    SkipPatternAnalyzer,
)
from angr_rule_learning.extraction.config import ExtractionConfig, WindowLimits
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.liveness import LivenessIndex
from angr_rule_learning.extraction.models import AlignmentRegion
from angr_rule_learning.extraction.pipeline import ExtractionData


def test_analyzer_reports_selected_skip_details_from_regions(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int f(int *p) { return *p; }\n", encoding="utf-8")
    region = AlignmentRegion(
        region_id="sample:sample.c:7:0",
        function="sample",
        source_file="sample.c",
        source_lines=(7,),
        guest_instructions=(
            _inst("aarch64", "ldp", "x0, x1, [x2]", address=0x1000),
            _inst("aarch64", "str", "w0, [sp, #12]", address=0x1004),
        ),
        host_instructions=(
            _inst("x86-64", "mov", "eax, edi", address=0x2000),
        ),
    )

    def provider(
        config: ExtractionConfig,
        diagnostics: MiningDiagnostics,
    ) -> ExtractionData:
        diagnostics.record_region()
        return ExtractionData((region,), LivenessIndex.empty())

    analyzer = SkipPatternAnalyzer(region_provider=provider)
    report = analyzer.analyze(
        ExtractionConfig(
            source=source,
            work_dir=tmp_path / "work",
            window_limits=WindowLimits(guest_max=1, host_max=1),
        )
    )

    assert report["totals"]["windows_enumerated"] > 0
    assert report["details"]["unparsed_memory_access"]["total"] >= 1
    assert report["details"]["one_sided_memory_access"]["total"] >= 1
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
uv run pytest tests/test_analysis_skip_patterns.py::test_analyzer_reports_selected_skip_details_from_regions -q
```

Expected: failure because `SkipPatternAnalyzer` does not exist.

- [ ] **Step 3: Implement `SkipPatternAnalyzer`**

Add imports:

```python
from pathlib import Path
from collections.abc import Callable

from angr_rule_learning.extraction.align import AlignmentRegionBuilder
from angr_rule_learning.extraction.blocks import BasicBlockBuilder
from angr_rule_learning.extraction.build import BuildArtifacts, ClangBuildDriver
from angr_rule_learning.extraction.config import ExtractionConfig
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.memory_surfaces import infer_memory_surface
from angr_rule_learning.extraction.object import ObjectExtractor
from angr_rule_learning.extraction.pipeline import ExtractionData
from angr_rule_learning.extraction.surfaces import SurfaceInferer
from angr_rule_learning.extraction.windows import WindowMiner
```

Add:

```python
RegionProvider = Callable[[ExtractionConfig, MiningDiagnostics], ExtractionData]


class SkipPatternAnalyzer:
    def __init__(
        self,
        *,
        build_driver: ClangBuildDriver | None = None,
        object_extractor: ObjectExtractor | None = None,
        region_provider: RegionProvider | None = None,
    ) -> None:
        self._build_driver = build_driver or ClangBuildDriver()
        self._object_extractor = object_extractor or ObjectExtractor()
        self._region_provider = region_provider

    def analyze(self, config: ExtractionConfig) -> dict[str, Any]:
        diagnostics = MiningDiagnostics()
        data = self._regions(config, diagnostics)
        miner = WindowMiner(config.window_limits, diagnostics)
        inferer = SurfaceInferer(diagnostics, data.liveness)
        aggregator = SkipPatternAggregator()

        for region in data.regions:
            windows = miner.enumerate_region(region)
            for window in windows:
                memory_surface = infer_memory_surface(window)
                if memory_surface.skip_detail in {
                    "unparsed_memory_access",
                    "one_sided_memory_access",
                }:
                    aggregator.record(memory_surface.skip_detail, window)
                # Preserve diagnostics counts by using the production inferer.
                inferer.infer(window)

        payload = aggregator.to_json()
        payload.update(
            {
                "source": str(config.source),
                "optimization": config.compile_options.optimization,
                "window_limits": {
                    "guest_max": config.window_limits.guest_max,
                    "host_max": config.window_limits.host_max,
                },
                "totals": {
                    "windows_enumerated": diagnostics.windows_enumerated,
                    "selected_skips": sum(
                        detail.get("total", 0)
                        for detail in payload.get("details", {}).values()
                    ),
                },
                "skip_reasons": diagnostics.to_json().get("skip_reasons", {}),
                "skip_details": diagnostics.to_json().get("skip_details", {}),
            }
        )
        return payload

    def _regions(
        self,
        config: ExtractionConfig,
        diagnostics: MiningDiagnostics,
    ) -> ExtractionData:
        if self._region_provider is not None:
            return self._region_provider(config, diagnostics)
        artifacts = self._build_driver.build(config)
        return self._extract_regions(artifacts, config, diagnostics)

    def _extract_regions(
        self,
        artifacts: BuildArtifacts,
        config: ExtractionConfig,
        diagnostics: MiningDiagnostics,
    ) -> ExtractionData:
        guest_functions = self._object_extractor.extract(
            artifacts.guest_object, config.guest_arch
        )
        host_functions = self._object_extractor.extract(
            artifacts.host_object, config.host_arch
        )
        block_builder = BasicBlockBuilder()
        guest_blocks = tuple(
            block
            for function in guest_functions
            for block in block_builder.build(function)
        )
        host_blocks = tuple(
            block
            for function in host_functions
            for block in block_builder.build(function)
        )
        for _function in guest_functions:
            diagnostics.record_function()
        regions = AlignmentRegionBuilder(diagnostics).build(guest_blocks, host_blocks)
        # Liveness is needed by SurfaceInferer. Use the same analyzer as the pipeline.
        from angr_rule_learning.extraction.liveness import LivenessAnalyzer

        liveness = LivenessAnalyzer().analyze(guest_functions + host_functions)
        return ExtractionData(regions, liveness)
```

If ruff flags the local import, move it to the module top.

- [ ] **Step 4: Run analyzer tests and verify pass**

Run:

```bash
uv run pytest tests/test_analysis_skip_patterns.py -q
```

Expected: pass.

- [ ] **Step 5: Run formatting and lint**

Run:

```bash
uv run ruff format src/angr_rule_learning/analysis/skip_patterns.py tests/test_analysis_skip_patterns.py
uv run ruff check src/angr_rule_learning/analysis/skip_patterns.py tests/test_analysis_skip_patterns.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add src/angr_rule_learning/analysis/skip_patterns.py tests/test_analysis_skip_patterns.py
git commit -m "Analyze selected extraction skip patterns"
```

---

### Task 4: CLI Subcommand For Skip Pattern Reports

**Files:**
- Modify: `src/angr_rule_learning/cli.py`
- Create: `tests/test_analysis_cli.py`

- [ ] **Step 1: Write failing CLI test**

Create `tests/test_analysis_cli.py`:

```python
import json
from pathlib import Path

from angr_rule_learning import cli


class _FakeAnalyzer:
    def analyze(self, config):
        return {
            "source": str(config.source),
            "optimization": config.compile_options.optimization,
            "window_limits": {
                "guest_max": config.window_limits.guest_max,
                "host_max": config.window_limits.host_max,
            },
            "totals": {"windows_enumerated": 1, "selected_skips": 1},
            "details": {
                "unparsed_memory_access": {
                    "total": 1,
                    "by_arch_mnemonic": {"aarch64:ldp": 1},
                    "top_instruction_patterns": [],
                }
            },
        }


def test_diagnose_skips_cli_writes_json_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int f(void) { return 0; }\n", encoding="utf-8")
    output = tmp_path / "skip_report.json"
    monkeypatch.setattr(cli, "SkipPatternAnalyzer", lambda: _FakeAnalyzer())

    cli.main(
        [
            "diagnose-skips",
            str(source),
            "--work-dir",
            str(tmp_path / "work"),
            "--output",
            str(output),
            "--optimization",
            "0",
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["source"] == str(source)
    assert payload["totals"]["selected_skips"] == 1
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
uv run pytest tests/test_analysis_cli.py -q
```

Expected: failure because CLI has no `diagnose-skips` command and no `SkipPatternAnalyzer` import.

- [ ] **Step 3: Implement CLI subcommand**

Modify `src/angr_rule_learning/cli.py`.

Add imports:

```python
import json

from angr_rule_learning.analysis.skip_patterns import SkipPatternAnalyzer
```

Add parser after `extract_parser`:

```python
    diagnose_parser = subparsers.add_parser(
        "diagnose-skips",
        help="analyze selected extraction skip patterns for one C source",
    )
    diagnose_parser.add_argument("source", type=Path)
    diagnose_parser.add_argument("--work-dir", required=True, type=Path)
    diagnose_parser.add_argument("--output", required=True, type=Path)
    diagnose_parser.add_argument("--clang", default="clang")
    diagnose_parser.add_argument("--optimization", default="0")
    diagnose_parser.add_argument("--guest-max-window", type=int, default=2)
    diagnose_parser.add_argument("--host-max-window", type=int, default=3)
```

Add this branch in `main()` alongside the existing `extract` command branch:

```python
    elif args.command == "diagnose-skips":
        config = ExtractionConfig(
            source=args.source,
            work_dir=args.work_dir,
            compile_options=CompileOptions(
                clang=args.clang,
                optimization=args.optimization,
            ),
            window_limits=WindowLimits(
                guest_max=args.guest_max_window,
                host_max=args.host_max_window,
            ),
        )
        payload = SkipPatternAnalyzer().analyze(config)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
```

- [ ] **Step 4: Run CLI test and verify pass**

Run:

```bash
uv run pytest tests/test_analysis_cli.py -q
```

Expected: pass.

- [ ] **Step 5: Run formatting and lint**

Run:

```bash
uv run ruff format src/angr_rule_learning/cli.py tests/test_analysis_cli.py
uv run ruff check src/angr_rule_learning/cli.py tests/test_analysis_cli.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add src/angr_rule_learning/cli.py tests/test_analysis_cli.py
git commit -m "Expose skip pattern diagnostics CLI"
```

---

### Task 5: Documentation And Smoke Verification

**Files:**
- Modify: `docs/architecture.md`
- No production code changes unless smoke reveals a bug.

- [ ] **Step 1: Update architecture docs**

In `docs/architecture.md`, add a short subsection after the extraction diagnostics paragraph:

```markdown
### Skip Pattern Analysis

The `diagnose-skips` CLI is a read-only observability tool for large skip
categories. It reuses extraction alignment and window enumeration, classifies
selected memory skip details, and writes pattern reports for
`unparsed_memory_access` and `one_sided_memory_access`. These reports are used
to decide whether the next improvement should extend memory operand parsing,
refine window pairing, or add a stack/frame abstraction. The analyzer must not
change candidate emission, verification, or rule generation behavior.
```

- [ ] **Step 2: Run focused tests**

Run:

```bash
uv run pytest tests/test_analysis_skip_patterns.py tests/test_analysis_cli.py -q
```

Expected: pass.

- [ ] **Step 3: Run smoke analysis on `smoke_int.c`**

Run:

```bash
uv run angr-rule-learning diagnose-skips samples/sources/smoke_int.c \
  --work-dir /private/tmp/arl-skip-pattern-analysis/work \
  --output /private/tmp/arl-skip-pattern-analysis/skip_patterns.json \
  --optimization 0
```

Expected: command exits 0 and writes `/private/tmp/arl-skip-pattern-analysis/skip_patterns.json`.

- [ ] **Step 4: Inspect smoke analysis output**

Run:

```bash
python3 - <<'PY'
import json
p = "/private/tmp/arl-skip-pattern-analysis/skip_patterns.json"
d = json.load(open(p))
print(d["totals"])
for detail, payload in sorted(d["details"].items()):
    print(detail, payload["total"])
    if "by_arch_mnemonic" in payload:
        print(sorted(payload["by_arch_mnemonic"].items(), key=lambda x: (-x[1], x[0]))[:10])
    if "by_stage" in payload:
        print(sorted(payload["by_stage"].items(), key=lambda x: (-x[1], x[0]))[:10])
PY
```

Expected:

- `details.unparsed_memory_access.total` is greater than 0.
- `details.one_sided_memory_access.total` is greater than 0.
- Output includes concrete top patterns and examples.

- [ ] **Step 5: Run full checks**

Run:

```bash
uv run ruff format --check
uv run ruff check
uv run pytest -q
```

Expected: all pass.

- [ ] **Step 6: Commit docs**

Run:

```bash
git add docs/architecture.md
git commit -m "Document skip pattern analysis workflow"
```

If smoke required code fixes after Task 4, include those fixes in an earlier focused commit before this docs commit.

- [ ] **Step 7: Final report**

Report:

- new CLI command and output file shape;
- focused and full verification results;
- smoke top `unparsed_memory_access` patterns;
- smoke top `one_sided_memory_access` patterns;
- confirmation that extraction/verifier/rule behavior was not intentionally changed.

---

## Self-Review

- Spec coverage: The plan adds a read-only analyzer, pattern aggregation for the two selected details, CLI access, tests, docs, and smoke verification.
- Placeholder scan: No unresolved implementation placeholders remain. All code snippets define concrete functions/classes and commands.
- Type consistency: `SkipPatternAggregator.record(detail, pair)` is introduced before `SkipPatternAnalyzer` uses it; `SkipPatternAnalyzer.analyze(config)` is introduced before CLI tests monkeypatch it.
- Scope check: The plan does not alter candidate extraction decisions, verifier behavior, or rule generation. It only analyzes existing window classifications.
