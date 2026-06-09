import angr_rule_learning
from angr_rule_learning import (
    BatchVerifier as RootBatchVerifier,
    SemanticVerifier as RootSemanticVerifier,
    VerificationCandidate as RootVerificationCandidate,
    VerificationReport as RootVerificationReport,
)
from angr_rule_learning.verification import (
    BatchVerifier as VerificationBatchVerifier,
    SemanticVerifier as VerificationSemanticVerifier,
    VerificationCandidate as VerificationVerificationCandidate,
    VerificationReport as VerificationVerificationReport,
)


def test_verification_package_exports_core_api() -> None:
    assert VerificationVerificationCandidate.__name__ == "VerificationCandidate"
    assert VerificationVerificationReport.__name__ == "VerificationReport"
    assert VerificationSemanticVerifier.__name__ == "SemanticVerifier"
    assert VerificationBatchVerifier.__name__ == "BatchVerifier"


def test_root_package_exports_core_api() -> None:
    assert RootVerificationCandidate is VerificationVerificationCandidate
    assert RootVerificationReport is VerificationVerificationReport
    assert RootSemanticVerifier is VerificationSemanticVerifier
    assert RootBatchVerifier is VerificationBatchVerifier


def test_root_package_all_lists_core_api() -> None:
    assert angr_rule_learning.__all__ == [
        "BatchVerifier",
        "SemanticVerifier",
        "VerificationCandidate",
        "VerificationReport",
    ]
