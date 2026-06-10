from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport
from angr_rule_learning.verification.verifier import SemanticVerifier


@dataclass(frozen=True)
class BatchSummary:
    total: int
    statuses: dict[str, int]
    failure_reasons: dict[str, int]

    def to_json(self) -> dict[str, object]:
        return {
            "total": self.total,
            "statuses": dict(sorted(self.statuses.items())),
            "failure_reasons": dict(sorted(self.failure_reasons.items())),
        }


class BatchVerifier:
    def __init__(self, verifier: SemanticVerifier | None = None) -> None:
        self.verifier = verifier or SemanticVerifier()

    def verify_many(
        self, candidates: Iterable[VerificationCandidate]
    ) -> list[VerificationReport]:
        return [self.verifier.verify(candidate) for candidate in candidates]

    @staticmethod
    def summarize(reports: Iterable[VerificationReport]) -> BatchSummary:
        reports = list(reports)
        statuses = Counter(report.status for report in reports)
        failure_reasons: Counter[str] = Counter()
        for report in reports:
            failure_reasons.update(report.failure_reasons)
        return BatchSummary(
            total=len(reports),
            statuses=dict(statuses),
            failure_reasons=dict(failure_reasons),
        )
