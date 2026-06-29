from __future__ import annotations

import json
from pathlib import Path

from angr_rule_learning.extraction.emit import (
    write_candidates_jsonl,
    write_reports_jsonl,
)
from angr_rule_learning.kernel.bind import KernelBindingBuilder
from angr_rule_learning.kernel.compile import KernelCompiler
from angr_rule_learning.kernel.extract import SnippetExtractor
from angr_rule_learning.kernel.models import (
    IRKernel,
    KernelConfig,
    KernelPipelineResult,
    KernelRunRecord,
)
from angr_rule_learning.kernel.synthesize import HardcodedKernelSynthesizer
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


class KernelLearningPipeline:
    def __init__(
        self,
        synthesizer: HardcodedKernelSynthesizer | None = None,
        compiler: KernelCompiler | None = None,
        extractor: SnippetExtractor | None = None,
        binding_builder: KernelBindingBuilder | None = None,
        verifier: BatchVerifier | None = None,
    ) -> None:
        self._synthesizer = synthesizer or HardcodedKernelSynthesizer()
        self._compiler = compiler or KernelCompiler()
        self._extractor = extractor or SnippetExtractor()
        self._binding_builder = binding_builder or KernelBindingBuilder()
        self._verifier = verifier or BatchVerifier()

    def run(
        self,
        config: KernelConfig,
        *,
        rules_output: Path,
        diagnostics_output: Path,
        candidates_output: Path | None = None,
        reports_output: Path | None = None,
        rules_diagnostics_output: Path | None = None,
        rules_debug_diagnostics_output: Path | None = None,
    ) -> KernelPipelineResult:
        config.work_dir.mkdir(parents=True, exist_ok=True)
        rule_diagnostics = RuleDiagnostics(
            collect_details=rules_debug_diagnostics_output is not None
        )
        rule_generalizer = RuleGeneralizer(rule_diagnostics)
        candidates: list[VerificationCandidate] = []
        reports: list[VerificationReport] = []
        rules: list[GeneratedRule] = []
        records: list[KernelRunRecord] = []

        for kernel in self._generate_kernels(config):
            try:
                pair, candidate = self._candidate_for_kernel(kernel, config)
                candidates.append(candidate)
                report = self._verifier.verify_many((candidate,))[0]
                reports.append(report)
                if report.status != "pass":
                    records.append(
                        _record_for_kernel(
                            kernel,
                            _status_for_report(report.status),
                            candidate_id=candidate.candidate_id,
                            reason=",".join(report.failure_reasons) or None,
                        )
                    )
                    continue
                rule = rule_generalizer.generate(
                    len(rules) + 1,
                    pair,
                    candidate,
                    report,
                )
                if rule is None:
                    records.append(
                        _record_for_kernel(
                            kernel,
                            "rule_skipped",
                            candidate_id=candidate.candidate_id,
                        )
                    )
                    continue
                rules.append(rule)
                records.append(
                    _record_for_kernel(
                        kernel,
                        "rule_emitted",
                        candidate_id=candidate.candidate_id,
                        rule_id=rule.rule_id,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - diagnostics must keep going.
                records.append(
                    _record_for_kernel(
                        kernel,
                        _status_for_exception(kernel, exc),
                        reason=str(exc),
                    )
                )

        consolidated_rules = tuple(
            consolidate_rules(rules, diagnostics=rule_diagnostics)
        )
        result = KernelPipelineResult(
            candidates=tuple(candidates),
            reports=tuple(reports),
            rules=consolidated_rules,
            rule_diagnostics=rule_diagnostics,
            records=tuple(records),
        )
        write_rules_text(rules_output, result.rules)
        _write_json(diagnostics_output, result.diagnostics)
        if candidates_output is not None:
            write_candidates_jsonl(candidates_output, result.candidates)
        if reports_output is not None:
            write_reports_jsonl(reports_output, result.reports)
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
        return result

    def _candidate_for_kernel(self, kernel: IRKernel, config: KernelConfig):
        compiled = self._compiler.compile_pair(kernel, config)
        snippets = self._extractor.extract_pair(compiled, config)
        return self._binding_builder.build_candidate(kernel, snippets)

    def _generate_kernels(self, config: KernelConfig) -> tuple[IRKernel, ...]:
        try:
            return self._synthesizer.generate(config.kernel_suite)
        except TypeError:
            return self._synthesizer.generate()


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _record_for_kernel(
    kernel: IRKernel,
    status: str,
    *,
    candidate_id: str | None = None,
    rule_id: int | None = None,
    reason: str | None = None,
) -> KernelRunRecord:
    metadata = kernel.metadata
    return KernelRunRecord(
        kernel.id,
        kernel.name,
        status,
        candidate_id=candidate_id,
        rule_id=rule_id,
        reason=reason,
        suite=metadata.suite,
        expected_status=metadata.expected_status,
        expected_reason=metadata.expected_reason,
    )


def _status_for_report(status: str) -> str:
    if status == "fail":
        return "verifier_fail"
    return status


def _status_for_exception(kernel: IRKernel, exc: Exception) -> str:
    if kernel.metadata.expected_status == "unsupported":
        return "unsupported"
    return "error"
