from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from angr_rule_learning.extraction.models import ExtractedInstruction, WindowPair
from angr_rule_learning.extraction.liveness import family_for_register
from angr_rule_learning.rules.registers import (
    RegisterClass,
    RegisterClassError,
    UnsupportedRegisterClass,
    classify_register,
    frame_pointer_placeholder,
    is_allowed_literal_register,
    known_register_tokens,
    normalize_register_name,
    stack_pointer_placeholder,
)
from angr_rule_learning.verification.addressing import parse_address_binding
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport

if TYPE_CHECKING:
    from angr_rule_learning.rules.ast import Instruction, Operand, Rule as AstRule


_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_]*)(?![A-Za-z0-9_])")

_RESERVED_LITERALS = frozenset({"0", "00", "000"})


@dataclass(frozen=True)
class GeneratedRule:
    rule_id: int
    candidate_id: str
    rule: AstRule

    @property
    def guest_lines(self) -> tuple[str, ...]:
        return tuple(inst.to_text() for inst in self.rule.guest)

    @property
    def host_lines(self) -> tuple[str, ...]:
        return tuple(inst.to_text() for inst in self.rule.host)

    @classmethod
    def from_text_lines(
        cls,
        rule_id: int,
        candidate_id: str,
        guest_lines: tuple[str, ...],
        host_lines: tuple[str, ...],
    ) -> "GeneratedRule":
        from angr_rule_learning.rules.ast import Rule

        return cls(
            rule_id=rule_id,
            candidate_id=candidate_id,
            rule=Rule.from_generated(rule_id, candidate_id, guest_lines, host_lines),
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


@dataclass
class RuleDiagnostics:
    collect_details: bool = False
    rules_considered: int = 0
    rules_emitted: int = 0
    skip_reasons: Counter[str] = field(default_factory=Counter)
    skipped_rules: list[RuleSkipDetail] = field(default_factory=list)

    @property
    def rules_skipped(self) -> int:
        return sum(self.skip_reasons.values())

    def record_considered(self) -> None:
        self.rules_considered += 1

    def record_emitted(self) -> None:
        self.rules_emitted += 1

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
            "skip_reasons": dict(sorted(self.skip_reasons.items())),
        }
        if include_details:
            payload["skipped_rules"] = [
                detail.to_json() for detail in self.skipped_rules
            ]
        return payload


class _RuleSkip(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _build_skip_detail(
    candidate: VerificationCandidate,
    reason: str,
    guest_insts: tuple[Instruction, ...],
    host_insts: tuple[Instruction, ...],
) -> RuleSkipDetail:
    return RuleSkipDetail(
        candidate_id=candidate.candidate_id,
        reason=reason,
        guest_lines=tuple(i.to_text() for i in guest_insts),
        host_lines=tuple(i.to_text() for i in host_insts),
        input_registers=candidate.input_registers,
        output_registers=candidate.output_registers,
        memory_bindings=tuple(
            {
                "slot": binding.slot,
                "guest_addr": binding.guest_addr,
                "host_addr": binding.host_addr,
                "access": binding.access,
            }
            for binding in candidate.memory.bindings
        ),
    )


class RuleGeneralizer:
    def __init__(self, diagnostics: RuleDiagnostics | None = None) -> None:
        self.diagnostics = diagnostics or RuleDiagnostics()
        self._emitted_keys: list[
            tuple[tuple[Instruction, ...], tuple[Instruction, ...]]
        ] = []

    def _record_skip(
        self,
        candidate: VerificationCandidate,
        reason: str,
        guest_insts: tuple[Instruction, ...],
        host_insts: tuple[Instruction, ...],
    ) -> None:
        detail = None
        if self.diagnostics.collect_details:
            detail = _build_skip_detail(candidate, reason, guest_insts, host_insts)
        self.diagnostics.record_skipped(reason, detail)

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

        guest_raw_insts = _instructions_to_ast(window.guest.instructions)
        host_raw_insts = _instructions_to_ast(window.host.instructions)

        self.diagnostics.record_considered()
        try:
            guest_arch = candidate.guest.arch
            host_arch = candidate.host.arch
            mapping, role_split = _build_placeholder_map(
                candidate, guest_arch, host_arch
            )
            internal_temps = _identify_internal_temps(window, candidate)
            mapping.update(internal_temps)
            guest_insts = _instructions_to_ast(window.guest.instructions)
            host_insts = _instructions_to_ast(window.host.instructions)
            guest_insts = _generalize_instructions_with_roles(
                guest_insts,
                window.guest.instructions,
                mapping,
                role_split,
                guest_arch,
            )
            host_insts = _generalize_instructions_with_roles(
                host_insts,
                window.host.instructions,
                mapping,
                role_split,
                host_arch,
            )
            # Annotate dead writes via MetaOp on AST, then convert to text
            guest_insts, host_insts = _annotate_dead_writes(
                guest_insts,
                host_insts,
                candidate,
                window,
                mapping,
                guest_arch,
                host_arch,
            )
            guest_lines = tuple(i.to_text() for i in guest_insts)
            host_lines = tuple(i.to_text() for i in host_insts)
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
            _check_label_consistency(guest_lines, host_lines)
            guest_lines, host_lines = _replace_immediates_shared(
                guest_lines, guest_arch, host_lines, host_arch
            )
            if not _host_immediates_are_derivable(guest_lines, host_lines, candidate):
                raise _RuleSkip("unpaired_host_immediate")
        except _RuleSkip as exc:
            self._record_skip(candidate, exc.reason, guest_raw_insts, host_raw_insts)
            return None

        # Parse final text to AST for structural comparison and rule building
        from angr_rule_learning.rules.ast import (
            Instruction as AstInstruction,
            Rule as AstRule,
            _insts_equal,
        )

        guest_final_insts = tuple(
            AstInstruction.from_text(line) for line in guest_lines
        )
        host_final_insts = tuple(AstInstruction.from_text(line) for line in host_lines)

        # AST structural dedup
        for existing_guest, existing_host in self._emitted_keys:
            if _insts_equal(existing_guest, guest_final_insts) and _insts_equal(
                existing_host, host_final_insts
            ):
                self._record_skip(
                    candidate,
                    "duplicate_rule",
                    guest_final_insts,
                    host_final_insts,
                )
                return None
        self._emitted_keys.append((guest_final_insts, host_final_insts))

        rule = GeneratedRule(
            rule_id=rule_id,
            candidate_id=candidate.candidate_id,
            rule=AstRule(
                rule_id=rule_id,
                candidate_id=candidate.candidate_id,
                guest=guest_final_insts,
                host=host_final_insts,
            ),
        )
        self.diagnostics.record_emitted()
        return rule


def _memory_binding_register_pairs(
    candidate: VerificationCandidate,
) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for binding in candidate.memory.bindings:
        try:
            guest_expr = parse_address_binding(binding.guest_addr)
            host_expr = parse_address_binding(binding.host_addr)
        except ValueError as exc:
            raise _RuleSkip("unsupported_rule_shape") from exc
        guest_regs = guest_expr.registers()
        host_regs = host_expr.registers()
        if len(guest_regs) != len(host_regs):
            raise _RuleSkip("unsupported_rule_shape")
        pairs.extend(zip(guest_regs, host_regs, strict=True))
    return tuple(pairs)


def _build_placeholder_map(
    candidate: VerificationCandidate,
    guest_arch: str,
    host_arch: str,
) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    """Return ``(mapping, role_split)``.

    *mapping* maps register names to placeholders.
    *role_split* maps a guest register name to
    ``(output_placeholder, input_placeholder)`` when the same guest
    register appears in both output and input pairs with **different**
    host registers and must be given distinct placeholders per role.
    """
    mapping: dict[str, str] = {}
    next_id = 1

    # Record host register per guest register for output vs input roles.
    output_host: dict[str, str] = {}
    input_host: dict[str, str] = {}

    register_pairs = (
        candidate.output_registers
        + candidate.input_registers
        + _memory_binding_register_pairs(candidate)
    )
    output_count = len(candidate.output_registers)
    input_count = len(candidate.input_registers)

    pair_index = 0
    for guest_reg, host_reg in register_pairs:
        pair_index += 1
        is_output = pair_index <= output_count
        is_input = output_count < pair_index <= output_count + input_count

        if is_output:
            output_host[guest_reg] = host_reg
        elif is_input:
            input_host[guest_reg] = host_reg
        guest_reg = normalize_register_name(guest_reg)
        host_reg = normalize_register_name(host_reg)

        guest_sp = stack_pointer_placeholder(guest_arch, guest_reg)
        host_sp = stack_pointer_placeholder(host_arch, host_reg)

        # Both sides are stack pointers with matching width.
        if guest_sp is not None and host_sp is not None:
            if guest_sp != host_sp:
                raise _RuleSkip("register_class_mismatch")
            guest_existing = mapping.get(guest_reg)
            host_existing = mapping.get(host_reg)
            existing = guest_existing or host_existing or guest_sp
            if guest_existing not in (None, existing) or host_existing not in (
                None,
                existing,
            ):
                raise _RuleSkip("unsupported_rule_shape")
            mapping[guest_reg] = existing
            mapping[host_reg] = existing
            continue

        # If only one side is a stack pointer, check frame-pointer routing.
        guest_fp = frame_pointer_placeholder(guest_arch, guest_reg)
        host_fp = frame_pointer_placeholder(host_arch, host_reg)

        if guest_sp is not None:
            # Guest is SP; host must be a matching frame pointer.
            if host_fp is None:
                raise _RuleSkip("register_class_mismatch")
            placeholder = host_fp
            guest_existing = mapping.get(guest_reg)
            host_existing = mapping.get(host_reg)
            existing = guest_existing or host_existing or placeholder
            if guest_existing not in (None, existing) or host_existing not in (
                None,
                existing,
            ):
                raise _RuleSkip("unsupported_rule_shape")
            mapping[guest_reg] = existing
            mapping[host_reg] = existing
            continue
        elif host_sp is not None:
            # Host is SP; guest must be a matching frame pointer.
            if guest_fp is None:
                raise _RuleSkip("register_class_mismatch")
            placeholder = guest_fp
            guest_existing = mapping.get(guest_reg)
            host_existing = mapping.get(host_reg)
            existing = guest_existing or host_existing or placeholder
            if guest_existing not in (None, existing) or host_existing not in (
                None,
                existing,
            ):
                raise _RuleSkip("unsupported_rule_shape")
            mapping[guest_reg] = existing
            mapping[host_reg] = existing
            continue

        if guest_fp is not None or host_fp is not None:
            if guest_fp is None or host_fp is None or guest_fp != host_fp:
                raise _RuleSkip("register_class_mismatch")
            guest_existing = mapping.get(guest_reg)
            host_existing = mapping.get(host_reg)
            existing = guest_existing or host_existing or guest_fp
            if guest_existing not in (None, existing) or host_existing not in (
                None,
                existing,
            ):
                raise _RuleSkip("unsupported_rule_shape")
            mapping[guest_reg] = existing
            mapping[host_reg] = existing
            continue

        guest_class = _classify_for_rule(guest_arch, guest_reg)
        host_class = _classify_for_rule(host_arch, host_reg)
        if guest_class != host_class:
            raise _RuleSkip("register_class_mismatch")
        guest_existing = mapping.get(guest_reg)
        host_existing = mapping.get(host_reg)

        if guest_existing is None and host_existing is None:
            existing = f"{guest_class.placeholder_prefix}_reg{next_id}"
            next_id += 1
        elif (
            guest_existing is not None
            and host_existing is not None
            and guest_existing == host_existing
        ):
            existing = guest_existing
        elif guest_existing is not None and host_existing is None:
            existing = guest_existing
        else:
            raise _RuleSkip("unsupported_rule_shape")

        for register in (guest_reg, host_reg):
            previous = mapping.get(register)
            if previous is not None and previous != existing:
                raise _RuleSkip("unsupported_rule_shape")
            mapping[register] = existing
    if not mapping:
        raise _RuleSkip("unsupported_rule_shape")

    # Detect split registers: same guest register appears in both
    # output and input pairs but with different host registers.
    role_split: dict[str, tuple[str, str]] = {}
    for guest_reg in output_host:
        if guest_reg not in input_host:
            continue
        out_ph = mapping.get(guest_reg)
        if out_ph is None:
            continue
        if output_host[guest_reg] == input_host[guest_reg]:
            continue  # Same host register — no split needed
        # Create a new input-role placeholder.
        guest_class = _classify_for_rule(guest_arch, guest_reg)
        in_ph = f"{guest_class.placeholder_prefix}_reg{next_id}"
        next_id += 1
        role_split[guest_reg] = (out_ph, in_ph)
        # Also update the host input register's mapping.
        host_input_reg = input_host[guest_reg]
        mapping[host_input_reg] = in_ph

    return mapping, role_split


def _classify_for_rule(arch: str, register: str) -> RegisterClass:
    try:
        return classify_register(arch, register)
    except UnsupportedRegisterClass as exc:
        raise _RuleSkip("unsupported_register_class") from exc
    except RegisterClassError as exc:
        raise _RuleSkip("unknown_register_class") from exc


def _instruction_text(instruction: ExtractedInstruction) -> str:
    op_str = instruction.op_str.strip()
    mnemonic = instruction.mnemonic.strip()
    if op_str:
        return f"{mnemonic} {op_str}"
    return mnemonic


_AARCH64_IMM_RE = re.compile(r"#(-?0x[0-9a-fA-F]+|-?\d+)")
_X86_64_IMM_RE = re.compile(
    r"-\s*(0x[0-9a-fA-F]+)"
    r"|-\s*(\d+)"
    r"|(?<![#\w])(0x[0-9a-fA-F]+|-?\d+)(?![A-Za-z0-9_])"
)

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


def _is_branch_instruction(inst: Instruction, arch: str) -> bool:
    """Check if an Instruction is a branch (b, bl, cbz, tbz, jmp, call, je, ...)."""
    mnemonic = inst.mnemonic.strip().lower()
    arch_n = normalize_arch_name(arch)
    if arch_n == "aarch64":
        if mnemonic in _AARCH64_BRANCH_MNEMONICS:
            return True
        return mnemonic.startswith("b.")
    if arch_n == "x86-64":
        if mnemonic in _X86_64_BRANCH_MNEMONICS:
            return True
        return mnemonic.startswith("j") and mnemonic != "jmp"
    return False


def _find_hex_operand(inst: Instruction, arch: str) -> tuple[int, str] | None:
    """Find the first operand containing a hex branch target. Returns (index, hex_string) or None."""
    from angr_rule_learning.rules.ast import LitOp

    arch_n = normalize_arch_name(arch)
    hex_pattern = (
        r"#?(0x[0-9a-fA-F]+)" if arch_n == "aarch64" else r"\b(0x[0-9a-fA-F]+)\b"
    )
    for i, op in enumerate(inst.operands):
        if isinstance(op, LitOp):
            m = re.search(hex_pattern, op.value)
            if m:
                return i, m.group(1)
    return None


def _replace_labels_ast(
    insts: tuple[Instruction, ...],
    arch: str,
    label_ids: list[int],
) -> tuple[Instruction, ...]:
    """Replace hex branch targets in AST instructions with LabelOp placeholders."""
    from angr_rule_learning.rules.ast import LabelOp

    result: list[Instruction] = []
    idx = 0
    is_aarch64 = normalize_arch_name(arch) == "aarch64"
    for inst in insts:
        if not _is_branch_instruction(inst, arch):
            result.append(inst)
            continue
        hex_info = _find_hex_operand(inst, arch)
        if hex_info is not None and idx < len(label_ids):
            op_idx, _hex_val = hex_info
            new_ops = list(inst.operands)
            new_ops[op_idx] = LabelOp(id=label_ids[idx], aarch64_hash=is_aarch64)
            inst = Instruction(
                mnemonic=inst.mnemonic, operands=tuple(new_ops), meta=inst.meta
            )
            idx += 1
        result.append(inst)
    return tuple(result)


def _labels_are_consistent_ast(
    guest_insts: tuple[Instruction, ...],
    host_insts: tuple[Instruction, ...],
) -> bool:
    """Check that guest and host use the same set of label IDs."""
    from angr_rule_learning.rules.ast import LabelOp

    def _collect(insts: tuple[Instruction, ...]) -> set[str]:
        return {
            str(op.id)
            for inst in insts
            for op in inst.operands
            if isinstance(op, LabelOp)
        }

    guest_labels = _collect(guest_insts)
    host_labels = _collect(host_insts)
    if guest_labels or host_labels:
        return guest_labels == host_labels
    return True


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


def _is_scale_immediate(line: str, match: re.Match[str], arch: str) -> bool:
    arch = normalize_arch_name(arch)
    before = line[: match.start()].lower()
    if arch == "aarch64":
        return before.rstrip().endswith("lsl")
    if arch == "x86-64":
        return before.rstrip().endswith("*")


def _is_bit_position(line: str, match: re.Match[str], arch: str) -> bool:
    arch = normalize_arch_name(arch)
    if arch == "aarch64":
        mnemonic = line.strip().split()[0].lower()
        return mnemonic in {"tbz", "tbnz"}
    return False
    return False


def _replace_immediates_shared(
    guest_lines: tuple[str, ...],
    guest_arch: str,
    host_lines: tuple[str, ...],
    host_arch: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    canonical_to_id: dict[str, int] = {}
    value_by_id: dict[str, int] = {}
    next_id = 1

    guest_arch_n = normalize_arch_name(guest_arch)
    host_arch_n = normalize_arch_name(host_arch)
    guest_pattern = _AARCH64_IMM_RE if guest_arch_n == "aarch64" else _X86_64_IMM_RE
    host_pattern = _AARCH64_IMM_RE if host_arch_n == "aarch64" else _X86_64_IMM_RE

    scale_shifts: set[int] = set()
    implicit_ids: set[str] = set()
    has_bit_position: bool = False

    for line in guest_lines:
        for m in guest_pattern.finditer(line):
            c = _imm_canonical(m, guest_arch)
            if _is_scale_immediate(line, m, guest_arch_n):
                scale_shifts.add(int(c))
                continue
            if _is_bit_position(line, m, guest_arch_n):
                scale_shifts.add(int(c))
                has_bit_position = True
            if c in _RESERVED_LITERALS:
                continue
            if c not in canonical_to_id:
                canonical_to_id[c] = next_id
                next_id += 1
            value_by_id[str(canonical_to_id[c])] = int(c)
    for line in host_lines:
        for m in host_pattern.finditer(line):
            c = _imm_canonical(m, host_arch)
            if _is_scale_immediate(line, m, host_arch_n):
                scale_shifts.add(int(c))
                continue
            # Zero on the host side is a fixed comparison constant
            # (e.g. cmp reg, 0), not a parameterizable value.
            if c in _RESERVED_LITERALS:
                continue
            if c not in canonical_to_id:
                canonical_to_id[c] = next_id
                next_id += 1
            value_by_id[str(canonical_to_id[c])] = int(c)

    if has_bit_position:
        # Inject implicit mask base value (1) so derivation can
        # find  (1 << immN) = mask.  Deferred until after all
        # textual immediates are registered so it does not consume
        # a low immN slot.
        _BASE_ONE = "1"
        if _BASE_ONE not in canonical_to_id:
            canonical_to_id[_BASE_ONE] = next_id
            next_id += 1
        implicit_id = str(canonical_to_id[_BASE_ONE])
        value_by_id[implicit_id] = 1
        implicit_ids.add(implicit_id)

    def _replace_side(
        lines: tuple[str, ...],
        pattern: re.Pattern[str],
        arch: str,
        prefix: str,
    ) -> tuple[str, ...]:
        result: list[str] = []
        for line in lines:

            def _replacer(match: re.Match[str]) -> str:
                if _is_scale_immediate(line, match, arch):
                    return match.group(0)
                c = _imm_canonical(match, arch)
                if c in _RESERVED_LITERALS:
                    return match.group(0)
                val = int(c)
                if val < 0:
                    if normalize_arch_name(arch) == "aarch64":
                        return f"#-imm{canonical_to_id[c]}"
                    else:
                        return f"- imm{canonical_to_id[c]}"
                return f"{prefix}imm{canonical_to_id[c]}"

            result.append(pattern.sub(_replacer, line))
        return tuple(result)

    guest_result = _replace_side(guest_lines, guest_pattern, guest_arch_n, "#")
    host_result = _replace_side(host_lines, host_pattern, host_arch_n, "")

    # Derive host-only immediates from guest immediates.
    guest_imms = {
        m.group(1) for line in guest_result for m in _IMM_PLACEHOLDER_RE.finditer(line)
    }
    host_imms = {
        m.group(1) for line in host_result for m in _IMM_PLACEHOLDER_RE.finditer(line)
    }
    host_only = host_imms - guest_imms

    if host_only:
        guest_values = {
            k: v for k, v in value_by_id.items() if k in guest_imms or k in implicit_ids
        }
        host_result = _inline_derived_expressions(
            host_result,
            host_only,
            guest_values,
            scale_shifts,
            value_by_id,
            implicit_ids,
        )

    return guest_result, host_result


def _inline_derived_expressions(
    host_lines: tuple[str, ...],
    host_only_ids: set[str],
    guest_values: dict[str, int],
    scale_shifts: set[int],
    all_values: dict[str, int],
    implicit_ids: set[str],
) -> tuple[str, ...]:
    result: list[str] = []
    for line in host_lines:
        for m in _IMM_PLACEHOLDER_RE.finditer(line):
            imm_id = m.group(1)
            if imm_id not in host_only_ids:
                continue
            derived = _derive_host_expression(
                int(all_values[imm_id]),
                guest_values,
                scale_shifts,
                implicit_ids,
                all_values,
            )
            if derived is not None:
                line = line.replace(f"imm{imm_id}", f"${{{derived}}}")
        result.append(line)
    return tuple(result)


def _derive_host_expression(
    target_value: int,
    guest_values: dict[str, int],
    scale_shifts: set[int],
    implicit_ids: set[str],
    all_values: dict[str, int],
) -> str | None:
    """Search for an expression of guest immediates that equals *target_value*.

    Templates are tried by complexity; the first match wins.
    """
    items = list(guest_values.items())  # [(id, value), ...]
    candidate_shifts = scale_shifts if scale_shifts else {0, 16, 32, 48}

    def _operand(imm_id: str) -> str:
        """Return the literal value for implicit operands, otherwise immN."""
        if imm_id in implicit_ids:
            return str(all_values[imm_id])
        return f"imm{imm_id}"

    def _shift_operand(s: int) -> str:
        """Return ``immN`` if *s* matches a guest immediate, else the literal."""
        for imm_id, val in guest_values.items():
            if val == s:
                return _operand(imm_id)
        return str(s)

    # L1: (imm_a << s)  —  single-shifted immediate  (e.g. 1 << bitpos)
    for id_a, va in items:
        for s in sorted(candidate_shifts, reverse=True):
            if va << s == target_value:
                return f"({_operand(id_a)} << {_shift_operand(s)})"

    # L2: (imm_a << s) | imm_b  —  mov + movk → movabs
    for id_a, va in items:
        for id_b, vb in items:
            if id_a == id_b:
                continue
            for s in sorted(candidate_shifts, reverse=True):
                if (va << s) | vb == target_value:
                    return (
                        f"({_operand(id_a)} << {_shift_operand(s)}) | {_operand(id_b)}"
                    )

    # L3: imm_a + imm_b  —  add chain
    for id_a, va in items:
        for id_b, vb in items:
            if id_a == id_b:
                continue
            if va + vb == target_value:
                return f"{_operand(id_a)} + {_operand(id_b)}"
            if va - vb == target_value:
                return f"{_operand(id_a)} - {_operand(id_b)}"

    return None


def _imm_canonical(match: re.Match[str], arch: str) -> str:
    if normalize_arch_name(arch) == "aarch64":
        raw = match.group(1).strip().lower()
    else:
        raw = match.group(0).strip().lower()
    # Normalize "- 0xc" to "-0xc".
    raw = re.sub(r"-\s+", "-", raw)
    value = int(raw, 0)
    return str(value)


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


def _check_label_consistency(
    guest_lines: tuple[str, ...],
    host_lines: tuple[str, ...],
) -> None:
    """Check label consistency, preferring AST-based comparison."""
    from angr_rule_learning.rules.ast import Instruction as AstInstruction

    try:
        guest_insts = tuple(AstInstruction.from_text(line) for line in guest_lines)
        host_insts = tuple(AstInstruction.from_text(line) for line in host_lines)
        if not _labels_are_consistent_ast(guest_insts, host_insts):
            raise _RuleSkip("mismatched_branch_targets")
    except Exception:
        # Fall back to text-based check
        if not _labels_are_consistent(guest_lines, host_lines):
            raise _RuleSkip("mismatched_branch_targets")


_IMM_PLACEHOLDER_RE = re.compile(r"\bimm(\d+)\b")

_AARCH64_FRAME_REGS = frozenset({"sp", "wsp", "x29", "fp"})
_X86_64_FRAME_REGS = frozenset({"rsp", "esp", "sp", "rbp", "ebp", "bp"})


def _has_frame_relative_binding(candidate: VerificationCandidate) -> bool:
    for binding in candidate.memory.bindings:
        try:
            guest_expr = parse_address_binding(binding.guest_addr)
            host_expr = parse_address_binding(binding.host_addr)
        except ValueError:
            continue
        if (
            guest_expr.base in _AARCH64_FRAME_REGS
            and host_expr.base in _X86_64_FRAME_REGS
        ):
            return True
    return False


def _collect_immediates_ast(insts: tuple[Instruction, ...]) -> set[str]:
    """Collect immN IDs from AST instructions.

    Checks both typed ImmOp operands and LitOp/RegTextOp values that may
    contain embedded ``immN`` placeholders (e.g. ``dword ptr [fp64 - imm2]``).
    """
    from angr_rule_learning.rules.ast import ImmOp, LitOp, RegTextOp

    ids: set[str] = set()
    for inst in insts:
        for op in inst.operands:
            if isinstance(op, ImmOp) and op.id != 0:
                ids.add(str(op.id))
            elif isinstance(op, (LitOp, RegTextOp)):
                for m in _IMM_PLACEHOLDER_RE.finditer(op.to_text()):
                    ids.add(m.group(1))
    return ids


def _host_immediates_are_derivable(
    guest_lines: tuple[str, ...],
    host_lines: tuple[str, ...],
    candidate: VerificationCandidate,
) -> bool:
    if not candidate.memory.bindings:
        return True
    if not _has_frame_relative_binding(candidate):
        return True
    # Use AST-based collection for reliability
    from angr_rule_learning.rules.ast import Instruction as AstInstruction

    guest_insts = tuple(AstInstruction.from_text(line) for line in guest_lines)
    host_insts = tuple(AstInstruction.from_text(line) for line in host_lines)
    guest_imms = _collect_immediates_ast(guest_insts)
    host_imms = _collect_immediates_ast(host_insts)
    return host_imms <= guest_imms


def consolidate_rules(rules: list[GeneratedRule]) -> list[GeneratedRule]:
    """Remove rules that are subsumed by a more-parameterised rule.

    A rule *A* is subsumed by rule *B* when substituting one of *B*'s
    ``immN`` placeholders with a reserved literal value produces the
    exact same structure as *A*.

    Uses AST-based structural comparison so that difference in
    placeholder numbering does not prevent merging.
    """
    if len(rules) < 2:
        return rules

    from angr_rule_learning.rules.ast import (
        collect_imm_ids,
        substitute_imm,
        structurally_equal,
    )

    subsumed_ids: set[int] = set()
    for i, rule_a in enumerate(rules):
        for j, rule_b in enumerate(rules):
            if i == j:
                continue
            b_imms = collect_imm_ids(rule_b.rule)
            if not b_imms:
                continue
            for imm_id in b_imms:
                for literal_val in sorted(_RESERVED_LITERALS, key=len, reverse=True):
                    subbed = substitute_imm(rule_b.rule, imm_id, literal_val)
                    if structurally_equal(subbed, rule_a.rule):
                        subsumed_ids.add(rule_a.rule_id)
                        break
                if rule_a.rule_id in subsumed_ids:
                    break

    return [r for r in rules if r.rule_id not in subsumed_ids]


def _annotate_dead_writes(
    guest_insts: tuple[Instruction, ...],
    host_insts: tuple[Instruction, ...],
    candidate: VerificationCandidate,
    window: WindowPair,
    mapping: dict[str, str],
    guest_arch: str,
    host_arch: str,
) -> tuple[tuple[Instruction, ...], tuple[Instruction, ...]]:
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
                if (
                    reg not in output_regs
                    and reg not in first_write
                    and not mapping.get(reg, "").startswith("tmp")
                ):
                    first_write[reg] = idx
            for reg in inst.read_registers:
                if reg in first_write:
                    last_read[reg] = idx
        return first_write, last_read

    def _text_to_regop(placeholder: str) -> Operand:
        from angr_rule_learning.rules.ast import RegOp, TmpOp

        m = re.fullmatch(r"(i\d+)_reg(\d+)", placeholder)
        if m:
            bits = int(m.group(1)[1:])
            return RegOp(prefix=m.group(1), bits=bits, id=int(m.group(2)))
        m = re.fullmatch(r"(sp|fp)(\d+)", placeholder)
        if m:
            return RegOp(prefix=m.group(1), bits=int(m.group(2)), id=0)
        m = re.fullmatch(r"tmp(\d+)", placeholder)
        if m:
            return TmpOp(id=int(m.group(1)))
        raise ValueError(f"unknown placeholder format: {placeholder!r}")

    def _apply(
        insts: tuple[Instruction, ...],
        instructions: tuple[ExtractedInstruction, ...],
    ) -> tuple[Instruction, ...]:
        from angr_rule_learning.rules.ast import Instruction as AstInstruction, MetaOp

        first_write, last_read = _dead_write_info(instructions)
        if not first_write:
            return insts
        save_reg_ops = tuple(
            _text_to_regop(mapping.get(r, r))
            for r, idx in sorted(first_write.items(), key=lambda x: x[1])
        )
        result: list[Instruction] = []
        first_inst = AstInstruction(
            mnemonic=insts[0].mnemonic,
            operands=insts[0].operands,
            meta=(MetaOp(kind="save", regs=save_reg_ops),),
        )
        result.append(first_inst)
        for idx, inst in enumerate(insts[1:], start=1):
            restore_now = tuple(
                _text_to_regop(mapping.get(r, r))
                for r, last_idx in last_read.items()
                if last_idx == idx
            )
            if restore_now:
                inst = AstInstruction(
                    mnemonic=inst.mnemonic,
                    operands=inst.operands,
                    meta=inst.meta + (MetaOp(kind="restore", regs=restore_now),),
                )
            result.append(inst)
        return tuple(result)

    return (
        _apply(guest_insts, window.guest.instructions),
        _apply(host_insts, window.host.instructions),
    )


def _instructions_to_ast(
    instructions: tuple[ExtractedInstruction, ...],
) -> tuple[Instruction, ...]:
    from angr_rule_learning.rules.ast import Instruction as AstInstruction

    return tuple(
        AstInstruction.from_text(_instruction_text(inst)) for inst in instructions
    )


def _parse_placeholder(placeholder: str):
    """Parse a placeholder string into its AST operand type.

    Supports ``i32_reg1``, ``sp64``, ``fp64`` → RegOp, and ``tmp1`` → TmpOp.
    """
    from angr_rule_learning.rules.ast import RegOp, TmpOp

    m = re.fullmatch(r"(i\d+)_reg(\d+)", placeholder)
    if m:
        bits = int(m.group(1)[1:])
        return RegOp(prefix=m.group(1), bits=bits, id=int(m.group(2)))
    m = re.fullmatch(r"(sp|fp)(\d+)", placeholder)
    if m:
        return RegOp(prefix=m.group(1), bits=int(m.group(2)), id=0)
    m = re.fullmatch(r"tmp(\d+)", placeholder)
    if m:
        return TmpOp(id=int(m.group(1)))
    raise ValueError(f"unknown placeholder format: {placeholder!r}")


def _generalize_instructions_with_roles(
    insts: tuple[Instruction, ...],
    extracted: tuple[ExtractedInstruction, ...],
    mapping: dict[str, str],
    role_split: dict[str, tuple[str, str]],
    arch: str,
) -> tuple[Instruction, ...]:
    """Replace physical register operands in AST instructions with typed placeholders.

    Applies text-level regex replacement within LitOp/RegTextOp operand values,
    so that registers embedded in compound operands (``[rcx]``, ``[edi + esi]``)
    are correctly replaced.  Where an entire operand becomes a single register
    placeholder, the operand is replaced with a typed AST node (RegOp or TmpOp).

    Step 1: Handle role-split registers.
    Step 2: Replace remaining physical registers via *mapping*.
    Step 3: Validate no physical registers remain.
    """
    from angr_rule_learning.rules.ast import (
        Instruction as AstInstruction,
        LitOp,
        RegTextOp,
    )

    result: list[AstInstruction] = []

    for inst, ext in zip(insts, extracted, strict=True):
        # Work on a text copy so we can detect whether an operand became
        # a pure placeholder after all replacements are applied.
        inst_text = inst.to_text()
        rewritten = inst_text

        # Step 1: Handle role-split registers first (text-level).
        for register in sorted(role_split, key=lambda r: len(r), reverse=True):
            out_ph, in_ph = role_split[register]
            is_written = bool(ext.write_registers and register in ext.write_registers)
            is_read = bool(ext.read_registers and register in ext.read_registers)

            if is_written and is_read:
                occurrence = [0]

                def _repl(match: re.Match[str]) -> str:
                    occurrence[0] += 1
                    return out_ph if occurrence[0] == 1 else in_ph

                rewritten = re.sub(
                    rf"(?<![A-Za-z0-9_]){re.escape(register)}(?![A-Za-z0-9_])",
                    _repl,
                    rewritten,
                    flags=re.IGNORECASE,
                )
            elif is_written:
                rewritten = re.sub(
                    rf"(?<![A-Za-z0-9_]){re.escape(register)}(?![A-Za-z0-9_])",
                    out_ph,
                    rewritten,
                    flags=re.IGNORECASE,
                )
            elif is_read:
                rewritten = re.sub(
                    rf"(?<![A-Za-z0-9_]){re.escape(register)}(?![A-Za-z0-9_])",
                    in_ph,
                    rewritten,
                    flags=re.IGNORECASE,
                )
            else:
                occurrence = [0]

                def _repl_noinfo(match: re.Match[str]) -> str:
                    occurrence[0] += 1
                    return out_ph if occurrence[0] == 1 else in_ph

                rewritten = re.sub(
                    rf"(?<![A-Za-z0-9_]){re.escape(register)}(?![A-Za-z0-9_])",
                    _repl_noinfo,
                    rewritten,
                    flags=re.IGNORECASE,
                )

        # Step 2: Handle regular mapping (text-level).
        for register in sorted(mapping, key=lambda r: len(r), reverse=True):
            placeholder = mapping[register]
            rewritten = re.sub(
                rf"(?<![A-Za-z0-9_]){re.escape(register)}(?![A-Za-z0-9_])",
                placeholder,
                rewritten,
                flags=re.IGNORECASE,
            )

        # Re-parse the rewritten text into an Instruction, then upgrade
        # any LitOp/RegTextOp that is now a pure placeholder into its
        # typed AST node.
        parsed = AstInstruction.from_text(rewritten)
        new_operands: list = []
        for op in parsed.operands:
            if isinstance(op, (LitOp, RegTextOp)):
                text = op.to_text()
                try:
                    new_operands.append(_parse_placeholder(text))
                except ValueError:
                    new_operands.append(op)
            else:
                new_operands.append(op)

        result.append(
            AstInstruction(mnemonic=parsed.mnemonic, operands=tuple(new_operands))
        )

    # Step 3: Validate.
    _validate_no_remaining_registers(tuple(result), arch)

    return tuple(result)


def _validate_no_remaining_registers(
    insts: tuple[Instruction, ...],
    arch: str,
) -> None:
    from angr_rule_learning.rules.ast import LitOp, RegTextOp

    known = known_register_tokens(arch)
    for inst in insts:
        for op in inst.operands:
            if isinstance(op, (LitOp, RegTextOp)):
                text = normalize_register_name(op.to_text())
                if text in known and not is_allowed_literal_register(arch, text):
                    raise _RuleSkip("unmapped_register_surface")


def _instruction_lines(
    instructions: tuple[ExtractedInstruction, ...],
) -> tuple[str, ...]:
    return tuple(_instruction_text(inst) for inst in instructions)


def _identify_internal_temps(
    window: WindowPair,
    candidate: VerificationCandidate,
) -> dict[str, str]:
    """Map per-side internal temporary registers to tmpN placeholders.

    A register is an internal temp when it is **written** inside the
    window but does **not** appear as an output or input register of the
    candidate.  Literal registers (sp, xzr, …) and condition-code
    families are excluded.
    """
    from angr_rule_learning.extraction.liveness import (
        family_for_register,
        is_condition_family,
    )

    temps: dict[str, str] = {}
    next_tmp = 1

    guest_outputs = {normalize_register_name(r) for r, _ in candidate.output_registers}
    guest_inputs = {normalize_register_name(r) for r, _ in candidate.input_registers}
    host_outputs = {normalize_register_name(r) for _, r in candidate.output_registers}
    host_inputs = {normalize_register_name(r) for _, r in candidate.input_registers}

    for side, window_insts, arch, outputs, inputs in (
        (
            "guest",
            window.guest.instructions,
            candidate.guest.arch,
            guest_outputs,
            guest_inputs,
        ),
        (
            "host",
            window.host.instructions,
            candidate.host.arch,
            host_outputs,
            host_inputs,
        ),
    ):
        for inst in window_insts:
            for reg in inst.write_registers:
                reg_n = normalize_register_name(reg)
                if reg_n in outputs or reg_n in inputs:
                    continue
                if is_allowed_literal_register(arch, reg_n):
                    continue
                family = family_for_register(arch, reg_n)
                if is_condition_family(arch, family):
                    continue
                if reg_n not in temps:
                    temps[reg_n] = f"tmp{next_tmp}"
                    next_tmp += 1

    return temps
