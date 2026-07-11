from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr_rule_learning.rules.ast import Instruction, Rule


@dataclass(frozen=True)
class GeneratedRule:
    rule_id: int
    candidate_id: str
    rule: Rule

    @property
    def guest_lines(self) -> tuple[str, ...]:
        return tuple(
            line
            for instruction in self.rule.guest
            for line in instruction.to_text().split("\n")
        )

    @property
    def host_lines(self) -> tuple[str, ...]:
        return tuple(
            line
            for instruction in self.rule.host
            for line in instruction.to_text().split("\n")
        )

    @classmethod
    def from_text_lines(
        cls,
        rule_id: int,
        candidate_id: str,
        guest_lines: tuple[str, ...],
        host_lines: tuple[str, ...],
        *,
        guest_arch: str | None = None,
        host_arch: str | None = None,
    ) -> GeneratedRule:
        from angr_rule_learning.rules.ast import Rule

        return cls(
            rule_id=rule_id,
            candidate_id=candidate_id,
            rule=Rule.from_generated(
                rule_id,
                candidate_id,
                guest_lines,
                host_lines,
                guest_arch=guest_arch,
                host_arch=host_arch,
            ),
        )


@dataclass(frozen=True)
class RuleSkipDetail:
    candidate_id: str
    reason: str
    guest_lines: tuple[str, ...]
    host_lines: tuple[str, ...]
    input_registers: tuple[tuple[str, str], ...]
    output_registers: tuple[tuple[str, str], ...]
    memory_bindings: tuple[dict[str, str], ...]

    def to_json(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "reason": self.reason,
            "guest_lines": list(self.guest_lines),
            "host_lines": list(self.host_lines),
            "input_registers": [list(pair) for pair in self.input_registers],
            "output_registers": [list(pair) for pair in self.output_registers],
            "memory_bindings": list(self.memory_bindings),
        }


@dataclass(frozen=True)
class ImmediateOccurrence:
    side: str
    instruction_index: int
    operand_index: int
    value: int
    text: str


@dataclass(frozen=True)
class ImmediateMetadata:
    value_by_id: dict[str, int] = field(default_factory=dict)
    occurrences_by_id: dict[str, tuple[ImmediateOccurrence, ...]] = field(
        default_factory=dict
    )


@dataclass(frozen=True)
class ImmediateReplacementResult:
    guest: tuple[Instruction, ...]
    host: tuple[Instruction, ...]
    metadata: ImmediateMetadata


@dataclass
class RuleDiagnostics:
    collect_details: bool = False
    rules_considered: int = 0
    rules_emitted: int = 0
    rules_subsumed: int = 0
    skip_reasons: Counter[str] = field(default_factory=Counter)
    skipped_rules: list[RuleSkipDetail] = field(default_factory=list)

    @property
    def rules_skipped(self) -> int:
        return sum(self.skip_reasons.values())

    def record_considered(self) -> None:
        self.rules_considered += 1

    def record_emitted(self) -> None:
        self.rules_emitted += 1

    def record_subsumed(self, count: int = 1) -> None:
        self.rules_subsumed += count
        self.rules_emitted -= count

    def record_skipped(
        self,
        reason: str,
        detail: RuleSkipDetail | None = None,
    ) -> None:
        self.skip_reasons.update((reason,))
        if self.collect_details and detail is not None:
            self.skipped_rules.append(detail)

    def to_json(self, *, include_details: bool = False) -> dict[str, object]:
        payload: dict[str, object] = {
            "rules_considered": self.rules_considered,
            "rules_emitted": self.rules_emitted,
            "rules_skipped": self.rules_skipped,
            "rules_subsumed": self.rules_subsumed,
            "skip_reasons": dict(sorted(self.skip_reasons.items())),
        }
        if include_details:
            payload["skipped_rules"] = [
                detail.to_json() for detail in self.skipped_rules
            ]
        return payload
