from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from angr_rule_learning.extraction.models import ExtractedInstruction, WindowPair
from angr_rule_learning.extraction.liveness import family_for_register
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
        self._emitted_keys: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()

    def generate(
        self,
        rule_id: int,
        window: WindowPair,
        candidate: VerificationCandidate,
        report: VerificationReport,
        *,
        region: object = None,
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
            guest_lines, host_lines = _annotate_dead_writes(
                guest_lines,
                host_lines,
                candidate,
                window,
                mapping,
                guest_arch,
                host_arch,
            )
            region_guest = (
                region.guest_instructions
                if region is not None
                else window.guest.instructions
            )
            region_host = (
                region.host_instructions
                if region is not None
                else window.host.instructions
            )
            guest_lines, host_lines = _replace_labels_shared(
                guest_lines,
                guest_arch,
                host_lines,
                host_arch,
                region_guest,
                region_host,
            )
            if not _labels_are_consistent(guest_lines, host_lines):
                raise _RuleSkip("mismatched_branch_targets")
            guest_lines, host_lines = _replace_immediates_shared(
                guest_lines, guest_arch, host_lines, host_arch
            )
        except _RuleSkip as exc:
            self.diagnostics.record_skipped(exc.reason)
            return None

        key = (guest_lines, host_lines)
        if key in self._emitted_keys:
            self.diagnostics.record_skipped("duplicate_rule")
            return None
        self._emitted_keys.add(key)

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
    texts = tuple(_instruction_text(inst) for inst in instructions)
    reg_lines = tuple(_generalize_line(text, mapping, arch) for text in texts)
    if not reg_lines:
        raise _RuleSkip("unsupported_rule_shape")
    return reg_lines


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


_AARCH64_IMM_RE = re.compile(r"#(0x[0-9a-fA-F]+|-?\d+)")
_X86_64_IMM_RE = re.compile(r"(?<![#\w])(0x[0-9a-fA-F]+|-?\d+)(?![A-Za-z0-9_])")

_AARCH64_BRANCH_MNEMONICS = frozenset(
    {"b", "bl", "blr", "cbz", "cbnz", "tbz", "tbnz", "ret"}
)
_X86_64_BRANCH_MNEMONICS = frozenset({"jmp", "call", "ret"})
_AARCH64_HEX_RE = re.compile(r"#(0x[0-9a-fA-F]+)")
_X86_64_HEX_RE = re.compile(r"\b(0x[0-9a-fA-F]+)\b")


def _branch_prefixes(arch: str) -> tuple[str, ...]:
    arch = normalize_arch_name(arch)
    if arch == "aarch64":
        return ("b.",)
    if arch == "x86-64":
        return ("j",)
    return ()


def normalize_arch_name(arch: str) -> str:
    normalized = arch.strip().lower()
    if normalized in {"amd64", "x86_64"}:
        return "x86-64"
    if normalized == "arm64":
        return "aarch64"
    return normalized


def _is_branch_line(line: str, arch: str) -> bool:
    mnemonic = line.split()[0].lower() if line.strip() else ""
    arch = normalize_arch_name(arch)
    if arch == "aarch64":
        if mnemonic in _AARCH64_BRANCH_MNEMONICS:
            return True
        return mnemonic.startswith(_branch_prefixes(arch))
    if arch == "x86-64":
        if mnemonic in _X86_64_BRANCH_MNEMONICS:
            return True
        return mnemonic.startswith("j") and mnemonic != "jmp"
    return False


def _replace_labels_shared(
    guest_lines: tuple[str, ...],
    guest_arch: str,
    host_lines: tuple[str, ...],
    host_arch: str,
    guest_instructions: tuple[ExtractedInstruction, ...] = (),
    host_instructions: tuple[ExtractedInstruction, ...] = (),
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    guest_arch_n = normalize_arch_name(guest_arch)
    host_arch_n = normalize_arch_name(host_arch)
    hex_re = {"aarch64": _AARCH64_HEX_RE, "x86-64": _X86_64_HEX_RE}
    prefix = {"aarch64": "#", "x86-64": ""}

    def _addr_to_line(
        instructions: tuple[ExtractedInstruction, ...],
    ) -> dict[int, tuple[str, int] | None]:
        result: dict[int, tuple[str, int] | None] = {}
        for inst in instructions:
            sl = inst.source
            result[inst.address] = (sl.file, sl.line) if sl is not None else None
        return result

    guest_lines_map = _addr_to_line(guest_instructions)
    host_lines_map = _addr_to_line(host_instructions)

    def _resolve_source_line(
        hex_target: str,
        lines_map: dict[int, tuple[str, int] | None],
    ) -> tuple[str, int] | None:
        return lines_map.get(int(hex_target, 16))

    guest_targets: list[tuple[str, tuple[str, int] | None]] = []
    host_targets: list[tuple[str, tuple[str, int] | None]] = []

    for line in guest_lines:
        if _is_branch_line(line, guest_arch):
            m = hex_re[guest_arch_n].search(line)
            if m:
                target = m.group(1)
                sl = _resolve_source_line(target, guest_lines_map)
                guest_targets.append((target, sl))

    for line in host_lines:
        if _is_branch_line(line, host_arch):
            m = hex_re[host_arch_n].search(line)
            if m:
                target = m.group(1)
                sl = _resolve_source_line(target, host_lines_map)
                host_targets.append((target, sl))

    label_by_src: dict[tuple[str, int], int] = {}
    pos_label: dict[int, int] = {}
    next_id = 1
    guest_label_ids: list[int] = []
    host_label_ids: list[int] = []

    guest_unresolved_pos = 0
    for _target, sl in guest_targets:
        if sl is not None and sl in label_by_src:
            guest_label_ids.append(label_by_src[sl])
        elif sl is not None:
            label_by_src[sl] = next_id
            guest_label_ids.append(next_id)
            next_id += 1
        else:
            guest_unresolved_pos += 1
            if guest_unresolved_pos not in pos_label:
                pos_label[guest_unresolved_pos] = next_id
                next_id += 1
            guest_label_ids.append(pos_label[guest_unresolved_pos])

    host_unresolved_pos = 0
    for _target, sl in host_targets:
        if sl is not None and sl in label_by_src:
            host_label_ids.append(label_by_src[sl])
        elif sl is not None:
            host_label_ids.append(next_id)
            next_id += 1
        else:
            host_unresolved_pos += 1
            if host_unresolved_pos in pos_label:
                host_label_ids.append(pos_label[host_unresolved_pos])
            else:
                pos_label[host_unresolved_pos] = next_id
                host_label_ids.append(next_id)
                next_id += 1

    def _replace_side(
        lines: tuple[str, ...],
        arch: str,
        label_ids: list[int],
    ) -> tuple[str, ...]:
        result: list[str] = []
        p = prefix[arch]
        idx = 0
        for line in lines:
            if _is_branch_line(line, arch):
                m = hex_re[arch].search(line)
                if m and idx < len(label_ids):
                    line = line.replace(f"{p}{m.group(1)}", f"{p}label{label_ids[idx]}")
                    idx += 1
            result.append(line)
        return tuple(result)

    return (
        _replace_side(guest_lines, guest_arch_n, guest_label_ids),
        _replace_side(host_lines, host_arch_n, host_label_ids),
    )


def _replace_immediates_shared(
    guest_lines: tuple[str, ...],
    guest_arch: str,
    host_lines: tuple[str, ...],
    host_arch: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    canonical_to_id: dict[str, int] = {}
    next_id = 1

    guest_arch_n = normalize_arch_name(guest_arch)
    host_arch_n = normalize_arch_name(host_arch)
    guest_pattern = _AARCH64_IMM_RE if guest_arch_n == "aarch64" else _X86_64_IMM_RE
    host_pattern = _AARCH64_IMM_RE if host_arch_n == "aarch64" else _X86_64_IMM_RE

    for line in guest_lines:
        for m in guest_pattern.finditer(line):
            c = _imm_canonical(m, guest_arch)
            if c in ("0", "00", "000"):
                continue
            if c not in canonical_to_id:
                canonical_to_id[c] = next_id
                next_id += 1
    for line in host_lines:
        for m in host_pattern.finditer(line):
            c = _imm_canonical(m, host_arch)
            if c in ("0", "00", "000"):
                continue
            if c not in canonical_to_id:
                canonical_to_id[c] = next_id
                next_id += 1

    def _replace_side(
        lines: tuple[str, ...],
        pattern: re.Pattern[str],
        arch: str,
        prefix: str,
    ) -> tuple[str, ...]:
        def _replacer(match: re.Match[str]) -> str:
            c = _imm_canonical(match, arch)
            if c in ("0", "00", "000"):
                return match.group(0)
            return f"{prefix}imm{canonical_to_id[c]}"

        return tuple(pattern.sub(_replacer, line) for line in lines)

    return (
        _replace_side(guest_lines, guest_pattern, guest_arch_n, "#"),
        _replace_side(host_lines, host_pattern, host_arch_n, ""),
    )


def _imm_canonical(match: re.Match[str], arch: str) -> str:
    if normalize_arch_name(arch) == "aarch64":
        return match.group(1).lower()
    return match.group(0).lower()


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


_LABEL_RE = re.compile(r"#?label(\d+)")


def _labels_are_consistent(
    guest_lines: tuple[str, ...], host_lines: tuple[str, ...]
) -> bool:
    guest_labels = {
        m.group(1) for line in guest_lines for m in _LABEL_RE.finditer(line)
    }
    host_labels = {m.group(1) for line in host_lines for m in _LABEL_RE.finditer(line)}
    if guest_labels or host_labels:
        if guest_labels != host_labels:
            return False
    return True


def _annotate_dead_writes(
    guest_lines: tuple[str, ...],
    host_lines: tuple[str, ...],
    candidate: VerificationCandidate,
    window: WindowPair,
    mapping: dict[str, str],
    guest_arch: str,
    host_arch: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    output_regs = {reg for pair in candidate.output_registers for reg in pair}
    cc_families = {"nzcv", "rflags"}

    def _dead_write_info(
        instructions: tuple[ExtractedInstruction, ...],
    ) -> tuple[dict[str, int], dict[str, int]]:
        first_write: dict[str, int] = {}
        last_read: dict[str, int] = {}
        for idx, inst in enumerate(instructions):
            for reg in inst.write_registers:
                family = family_for_register(inst.arch, reg)
                if family in cc_families or is_allowed_literal_register(inst.arch, reg):
                    continue
                if reg not in output_regs and reg not in first_write:
                    first_write[reg] = idx
            for reg in inst.read_registers:
                if reg in first_write:
                    last_read[reg] = idx
        return first_write, last_read

    def _apply(
        lines: tuple[str, ...],
        instructions: tuple[ExtractedInstruction, ...],
    ) -> tuple[str, ...]:
        first_write, last_read = _dead_write_info(instructions)
        if not first_write:
            return lines
        result: list[str] = []
        save_regs = [
            mapping.get(r, r)
            for r, idx in sorted(first_write.items(), key=lambda x: x[1])
        ]
        result.append(f"save {', '.join(save_regs)}")
        for idx, line in enumerate(lines):
            result.append(line)
            restore_now = [
                mapping.get(r, r)
                for r, last_idx in last_read.items()
                if last_idx == idx
            ]
            if restore_now:
                result.append(f"restore {', '.join(restore_now)}")
        return tuple(result)

    return (
        _apply(guest_lines, window.guest.instructions),
        _apply(host_lines, window.host.instructions),
    )
