from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from angr_rule_learning.extraction.models import ExtractedInstruction, WindowPair
from angr_rule_learning.rules.registers import (
    RegisterClass,
    RegisterClassError,
    UnsupportedRegisterClass,
    classify_register,
    is_allowed_literal_register,
    known_register_tokens,
    normalize_register_name,
)
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport


_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_]*)(?![A-Za-z0-9_])")


@dataclass(frozen=True)
class GeneratedRule:
    rule_id: int
    candidate_id: str
    guest_lines: tuple[str, ...]
    host_lines: tuple[str, ...]


@dataclass
class RuleDiagnostics:
    rules_considered: int = 0
    rules_emitted: int = 0
    skip_reasons: Counter[str] = field(default_factory=Counter)

    @property
    def rules_skipped(self) -> int:
        return sum(self.skip_reasons.values())

    def record_considered(self) -> None:
        self.rules_considered += 1

    def record_emitted(self) -> None:
        self.rules_emitted += 1

    def record_skipped(self, reason: str) -> None:
        self.skip_reasons.update((reason,))

    def to_json(self) -> dict[str, object]:
        return {
            "rules_considered": self.rules_considered,
            "rules_emitted": self.rules_emitted,
            "rules_skipped": self.rules_skipped,
            "skip_reasons": dict(sorted(self.skip_reasons.items())),
        }


class _RuleSkip(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RuleGeneralizer:
    def __init__(self, diagnostics: RuleDiagnostics | None = None) -> None:
        self.diagnostics = diagnostics or RuleDiagnostics()

    def generate(
        self,
        rule_id: int,
        window: WindowPair,
        candidate: VerificationCandidate,
        report: VerificationReport,
    ) -> GeneratedRule | None:
        if report.status != "pass" or not report.equivalent:
            return None

        self.diagnostics.record_considered()
        try:
            guest_arch = candidate.guest.arch
            host_arch = candidate.host.arch
            mapping = _build_placeholder_map(candidate, guest_arch, host_arch)
            guest_lines = _generalize_instructions(
                window.guest.instructions, mapping, guest_arch
            )
            host_lines = _generalize_instructions(
                window.host.instructions, mapping, host_arch
            )
        except _RuleSkip as exc:
            self.diagnostics.record_skipped(exc.reason)
            return None

        rule = GeneratedRule(
            rule_id=rule_id,
            candidate_id=candidate.candidate_id,
            guest_lines=guest_lines,
            host_lines=host_lines,
        )
        self.diagnostics.record_emitted()
        return rule


def _build_placeholder_map(
    candidate: VerificationCandidate,
    guest_arch: str,
    host_arch: str,
) -> dict[str, str]:
    mapping: dict[str, str] = {}
    next_id = 1
    for guest_reg, host_reg in candidate.output_registers + candidate.input_registers:
        guest_reg = normalize_register_name(guest_reg)
        host_reg = normalize_register_name(host_reg)
        guest_class = _classify_for_rule(guest_arch, guest_reg)
        host_class = _classify_for_rule(host_arch, host_reg)
        if guest_class != host_class:
            raise _RuleSkip("register_class_mismatch")
        guest_existing = mapping.get(guest_reg)
        host_existing = mapping.get(host_reg)
        if (
            guest_existing is not None
            and host_existing is not None
            and guest_existing != host_existing
        ):
            raise _RuleSkip("unsupported_rule_shape")

        existing = guest_existing or host_existing
        if existing is None:
            existing = f"{guest_class.placeholder_prefix}_reg{next_id}"
            next_id += 1

        for register in (guest_reg, host_reg):
            previous = mapping.get(register)
            if previous is not None and previous != existing:
                raise _RuleSkip("unsupported_rule_shape")
            mapping[register] = existing
    if not mapping:
        raise _RuleSkip("unsupported_rule_shape")
    return mapping


def _classify_for_rule(arch: str, register: str) -> RegisterClass:
    try:
        return classify_register(arch, register)
    except UnsupportedRegisterClass as exc:
        raise _RuleSkip("unsupported_register_class") from exc
    except RegisterClassError as exc:
        raise _RuleSkip("unknown_register_class") from exc


def _generalize_instructions(
    instructions: tuple[ExtractedInstruction, ...],
    mapping: dict[str, str],
    arch: str,
) -> tuple[str, ...]:
    lines = tuple(
        _generalize_line(_instruction_text(inst), mapping, arch)
        for inst in instructions
    )
    if not lines:
        raise _RuleSkip("unsupported_rule_shape")
    return lines


def _instruction_text(instruction: ExtractedInstruction) -> str:
    op_str = instruction.op_str.strip()
    mnemonic = instruction.mnemonic.strip()
    if op_str:
        return f"{mnemonic} {op_str}"
    return mnemonic


def _generalize_line(text: str, mapping: dict[str, str], arch: str) -> str:
    rewritten = text
    for register, replacement in sorted(
        mapping.items(), key=lambda item: len(item[0]), reverse=True
    ):
        rewritten = re.sub(
            rf"(?<![A-Za-z0-9_]){re.escape(register)}(?![A-Za-z0-9_])",
            replacement,
            rewritten,
            flags=re.IGNORECASE,
        )
    if _remaining_registers(rewritten, arch):
        raise _RuleSkip("unmapped_register_surface")
    return rewritten


def _remaining_registers(text: str, arch: str) -> tuple[str, ...]:
    known = known_register_tokens(arch)
    remaining = []
    for token in _TOKEN_RE.findall(text.lower()):
        if is_allowed_literal_register(arch, token):
            continue
        if token in known:
            remaining.append(token)
    return tuple(remaining)


def _placeholder_clash(
    mapping: dict[str, str], register: str, placeholder: str
) -> bool:
    """Check if placeholder is already assigned to a different register."""
    for mapped_reg, mapped_ph in mapping.items():
        if mapped_ph == placeholder and mapped_reg != register:
            return True
    return False
