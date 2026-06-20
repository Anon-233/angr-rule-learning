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
from angr_rule_learning.extraction.liveness import (
    LivenessAnalyzer,
    LivenessIndex,
)
from angr_rule_learning.extraction.models import (
    AlignmentRegion,
    WindowPair,
)
from angr_rule_learning.extraction.object import ObjectExtractor
from angr_rule_learning.extraction.register_cegis import make_register_binding_solver
from angr_rule_learning.extraction.surfaces import SurfaceInferer
from angr_rule_learning.extraction.windows import VerifiedWindowSet, WindowMiner
from angr_rule_learning.rules.generalize import (
    GeneratedRule,
    RuleDiagnostics,
    RuleGeneralizer,
    consolidate_rules,
)
from angr_rule_learning.rules.writer import (
    write_rule_diagnostics_json,
    write_rules_text,
)
from angr_rule_learning.verification.batch import BatchVerifier
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport


@dataclass(frozen=True)
class ExtractionData:
    regions: tuple[AlignmentRegion, ...]
    liveness: LivenessIndex


RegionProvider = Callable[[ExtractionConfig, MiningDiagnostics], ExtractionData]


@dataclass(frozen=True)
class ExtractionResult:
    candidates: tuple[VerificationCandidate, ...]
    reports: tuple[VerificationReport, ...]
    diagnostics: MiningDiagnostics
    rules: tuple[GeneratedRule, ...] = ()
    rule_diagnostics: RuleDiagnostics | None = None


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
        rules_output: Path | None = None,
        rules_diagnostics_output: Path | None = None,
        rules_debug_diagnostics_output: Path | None = None,
    ) -> ExtractionResult:
        rule_generation_requested = (
            rules_output is not None
            or rules_diagnostics_output is not None
            or rules_debug_diagnostics_output is not None
        )
        if rule_generation_requested and not verify:
            raise ValueError("rule output requires verify=True")

        diagnostics = MiningDiagnostics()
        rule_diagnostics = RuleDiagnostics(
            collect_details=rules_debug_diagnostics_output is not None
        )
        rule_generalizer = RuleGeneralizer(rule_diagnostics)
        rules: list[GeneratedRule] = []
        data = self._regions(config, diagnostics)
        regions = data.regions
        miner = WindowMiner(config.window_limits, diagnostics)
        semantic_verifier = getattr(self._verifier, "verifier", None)
        binding_solver = make_register_binding_solver(
            config.register_binding,
            verifier=semantic_verifier,
        )
        inferer = SurfaceInferer(
            diagnostics,
            data.liveness,
            binding_solver=binding_solver,
        )
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
                    for (window, candidate), report in zip(
                        emitted, staged_reports, strict=True
                    ):
                        diagnostics.record_window_verified(report.status)
                        if report.status == "pass":
                            verified.add(window)
                        if rule_generation_requested:
                            rule = rule_generalizer.generate(
                                len(rules) + 1,
                                window,
                                candidate,
                                report,
                                region=region,
                            )
                            if rule is not None:
                                rules.append(rule)
        candidate_tuple = tuple(candidates)
        rules = consolidate_rules(rules, diagnostics=rule_diagnostics)
        rule_tuple = tuple(rules)
        if rules_output is not None:
            write_rules_text(rules_output, rule_tuple)
        if rules_diagnostics_output is not None:
            write_rule_diagnostics_json(
                rules_diagnostics_output,
                rule_diagnostics,
                include_details=False,
            )
        if rules_debug_diagnostics_output is not None:
            write_rule_diagnostics_json(
                rules_debug_diagnostics_output,
                rule_diagnostics,
                include_details=True,
            )
        write_candidates_jsonl(candidates_output, candidate_tuple)
        write_diagnostics_json(diagnostics_output, diagnostics)
        return ExtractionResult(
            candidate_tuple,
            tuple(reports),
            diagnostics,
            rule_tuple,
            rule_diagnostics if rule_generation_requested else None,
        )

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
        liveness = LivenessAnalyzer().analyze(guest_functions + host_functions)
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
        return ExtractionData(regions, liveness)
