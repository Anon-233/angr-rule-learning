from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from angr_rule_learning.extraction.align import AlignmentRegionBuilder
from angr_rule_learning.extraction.blocks import BasicBlockBuilder
from angr_rule_learning.extraction.build import BuildArtifacts, ClangBuildDriver
from angr_rule_learning.extraction.config import ExtractionConfig
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.emit import (
    write_candidates_jsonl,
    write_diagnostics_json,
)
from angr_rule_learning.extraction.models import AlignmentRegion, WindowPair
from angr_rule_learning.extraction.object import ObjectExtractor
from angr_rule_learning.extraction.surfaces import SurfaceInferer
from angr_rule_learning.extraction.windows import VerifiedWindowSet, WindowMiner
from angr_rule_learning.verification.batch import BatchVerifier
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport


RegionProvider = Callable[
    [ExtractionConfig, MiningDiagnostics], tuple[AlignmentRegion, ...]
]


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
                        emitted, staged_reports, strict=True
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
        guest_functions = self._object_extractor.extract(
            artifacts.guest_object, "aarch64"
        )
        host_functions = self._object_extractor.extract(artifacts.host_object, "x86-64")
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
        return AlignmentRegionBuilder(diagnostics).build(guest_blocks, host_blocks)
