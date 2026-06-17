from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from angr_rule_learning.rules.generalize import GeneratedRule, RuleDiagnostics


def format_rule(rule: GeneratedRule) -> str:
    """Format a rule using its AST representation."""
    return rule.rule.to_text()


def write_rules_text(path: Path, rules: Iterable[GeneratedRule]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(rule.rule.to_text() for rule in rules), encoding="utf-8")


def write_rule_diagnostics_json(
    path: Path,
    diagnostics: RuleDiagnostics,
    *,
    include_details: bool = False,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            diagnostics.to_json(include_details=include_details),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
