from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from angr_rule_learning.extraction.align import AlignmentRegionBuilder
from angr_rule_learning.extraction.blocks import BasicBlockBuilder
from angr_rule_learning.extraction.build import BuildArtifacts, ClangBuildDriver
from angr_rule_learning.extraction.config import ExtractionConfig
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.liveness import LivenessAnalyzer
from angr_rule_learning.extraction.memory_operands import (
    extract_memory_operands,
    has_any_memory_access,
)
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    WindowPair,
)
from angr_rule_learning.extraction.object import ObjectExtractor
from angr_rule_learning.extraction.pipeline import ExtractionData
from angr_rule_learning.extraction.surfaces import SurfaceInferer
from angr_rule_learning.extraction.windows import WindowMiner

_HEX_RE = re.compile(r"(?<![A-Za-z0-9_])-?0x[0-9a-fA-F]+")
_DEC_RE = re.compile(r"(?<![A-Za-z0-9_])-?\d+(?![A-Za-z0-9_])")

RegionProvider = Callable[[ExtractionConfig, MiningDiagnostics], ExtractionData]


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
    first = (
        pair.guest.instructions[0]
        if pair.guest.instructions
        else pair.host.instructions[0]
    )
    return {
        "function": first.function,
        "source_span": pair.guest.source_span,
        "stage": list(pair.stage),
        "guest": _window_lines(pair.guest),
        "host": _window_lines(pair.host),
    }


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
    _by_stage: dict[str, Counter[str]] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    _instruction_patterns: dict[str, dict[tuple[str, str, str], _PatternBucket]] = (
        field(default_factory=lambda: defaultdict(dict))
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
                # Only count instructions that cannot be parsed by the
                # production operand extractor.  Instructions that ARE
                # parseable belong to the supported surface, not here.
                if extract_memory_operands(inst):
                    continue
                pattern = normalize_instruction_text(instruction_text(inst))
                key = (inst.arch, inst.mnemonic.strip().lower(), pattern)
                self._by_arch_mnemonic[detail][f"{key[0]}:{key[1]}"] += 1
                bucket = self._instruction_patterns[detail].setdefault(
                    key, _PatternBucket()
                )
                bucket.add(_example(pair), self.max_examples)

    def _record_one_sided(self, detail: str, pair: WindowPair) -> None:
        stage_key = f"{pair.stage[0]}x{pair.stage[1]}"
        self._by_stage[detail][stage_key] += 1
        guest_count = _memory_count(pair.guest)
        host_count = _memory_count(pair.host)
        key = (
            _window_pattern(pair.guest),
            _window_pattern(pair.host),
            guest_count,
            host_count,
        )
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
                        "pattern": key[2],
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

        _SELECTED_DETAILS = {"unparsed_memory_access", "one_sided_memory_access"}

        for region in data.regions:
            windows = miner.enumerate_region(region)
            for window in windows:
                before = dict(
                    diagnostics.skip_details.get(
                        "unsupported_memory_surface", Counter()
                    )
                )
                inferer.infer(window)
                after = diagnostics.skip_details.get(
                    "unsupported_memory_surface", Counter()
                )
                for detail in _SELECTED_DETAILS:
                    if after.get(detail, 0) > before.get(detail, 0):
                        aggregator.record(detail, window)

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
        liveness = LivenessAnalyzer().analyze(guest_functions + host_functions)
        return ExtractionData(regions, liveness)
