"""Stateful structural deduplication pass for generalized rules."""

from __future__ import annotations

from angr_rule_learning.rules._fingerprint import build_rule_fingerprint
from angr_rule_learning.rules.ast import Rule


class RuleDeduplicator:
    """Remember complete Guest/Host fingerprints and reject repeats."""

    def __init__(self) -> None:
        self._fingerprints: set[tuple[object, ...]] = set()

    def accept(self, rule: Rule) -> bool:
        fingerprint = build_rule_fingerprint(rule)
        if fingerprint in self._fingerprints:
            return False
        self._fingerprints.add(fingerprint)
        return True
