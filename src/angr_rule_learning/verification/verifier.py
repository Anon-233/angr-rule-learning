from __future__ import annotations

from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport


class SemanticVerifier:
    def verify(self, candidate: VerificationCandidate) -> VerificationReport:
        return VerificationReport(candidate.candidate_id, "unsupported")
