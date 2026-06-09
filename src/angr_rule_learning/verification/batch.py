from __future__ import annotations

from collections.abc import Iterable

from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport
from angr_rule_learning.verification.verifier import SemanticVerifier


class BatchVerifier:
    def __init__(self, verifier: SemanticVerifier | None = None) -> None:
        self.verifier = verifier or SemanticVerifier()

    def verify_many(
        self, candidates: Iterable[VerificationCandidate]
    ) -> list[VerificationReport]:
        return [self.verifier.verify(candidate) for candidate in candidates]
