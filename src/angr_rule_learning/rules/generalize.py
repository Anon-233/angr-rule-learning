from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from angr_rule_learning.arch.registers import (
    fixed_role_family,
    fixed_role_preserve_register,
    register_bit_range,
    register_family,
)
from angr_rule_learning.arch.registry import canonical_arch_name
from angr_rule_learning.extraction.models import ExtractedInstruction, WindowPair
from angr_rule_learning.extraction.liveness import family_for_register
from angr_rule_learning.rules.ast import (
    collect_instruction_imm_ids,
    labels_are_consistent,
    parse_placeholder,
)
from angr_rule_learning.rules.derivation import (
    DerivationContext,
    derive_host_expressions,
)
from angr_rule_learning.rules.register_views import resolve_register_views
from angr_rule_learning.rules.registers import (
    RegisterClass,
    RegisterClassError,
    UnsupportedRegisterClass,
    classify_register,
    frame_pointer_placeholder,
    is_allowed_literal_register,
    is_fixed_role_register,
    known_register_tokens,
    normalize_register_name,
    stack_pointer_placeholder,
)
from angr_rule_learning.verification.addressing import parse_address_binding
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport

if TYPE_CHECKING:
    from angr_rule_learning.rules.ast import Instruction, Operand, Rule as AstRule


_RESERVED_LITERALS = frozenset({"0", "00", "000"})


@dataclass(frozen=True)
class GeneratedRule:
    rule_id: int
    candidate_id: str
    rule: AstRule

    @property
    def guest_lines(self) -> tuple[str, ...]:
        result: list[str] = []
        for inst in self.rule.guest:
            for line in inst.to_text().split("\n"):
                result.append(line)
        return tuple(result)

    @property
    def host_lines(self) -> tuple[str, ...]:
        result: list[str] = []
        for inst in self.rule.host:
            for line in inst.to_text().split("\n"):
                result.append(line)
        return tuple(result)

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
    guest_lines_flat: list[str] = []
    for i in guest_insts:
        for line in i.to_text().split("\n"):
            guest_lines_flat.append(line)
    host_lines_flat: list[str] = []
    for i in host_insts:
        for line in i.to_text().split("\n"):
            host_lines_flat.append(line)
    return RuleSkipDetail(
        candidate_id=candidate.candidate_id,
        reason=reason,
        guest_lines=tuple(guest_lines_flat),
        host_lines=tuple(host_lines_flat),
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
        self._emitted_fingerprints: list[tuple[object, ...]] = []

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
            fixed_producers, fixed_sources = _require_fixed_role_producers(
                window, candidate
            )
            mapping, role_split = _build_placeholder_map(
                candidate, guest_arch, host_arch
            )
            internal_temps = _identify_internal_temps(window, candidate)
            mapping.update(internal_temps)
            # Fixed-role producer targets must retain their register-family
            # identity (e.g. ecx→cl); override any temp placeholders.
            for reg in fixed_producers:
                mapping[reg] = reg
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
                allowed_literals=fixed_producers,
            )
            # Verify each provenance source placeholder appears in Host AST.
            _verify_fixed_role_sources_in_host(host_insts, fixed_sources, mapping)
            # Annotate dead writes via MetaOp on AST, then apply label/immediate
            # replacement directly on AST.
            guest_insts, host_insts = _annotate_dead_writes(
                guest_insts,
                host_insts,
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
            guest_insts, host_insts = _replace_labels_ast(
                guest_insts,
                guest_arch,
                host_insts,
                host_arch,
                region_guest,
                region_host,
            )
            _check_label_consistency_ast(guest_insts, host_insts)
            guest_insts, host_insts = _replace_immediates_ast(
                guest_insts, guest_arch, host_insts, host_arch
            )
            if not _host_immediates_are_derivable(guest_insts, host_insts, candidate):
                raise _RuleSkip("unpaired_host_immediate")
            _verify_host_registers_bound(guest_insts, host_insts)
        except _RuleSkip as exc:
            self._record_skip(candidate, exc.reason, guest_raw_insts, host_raw_insts)
            return None

        # AST alpha-equivalence dedup: compare full Rules, not separate
        # guest/host sequences, so that guest↔host relationships are
        # preserved across the comparison.
        from angr_rule_learning.rules._fingerprint import build_rule_fingerprint
        from angr_rule_learning.rules.ast import Rule as AstRule

        candidate_fp = build_rule_fingerprint(
            AstRule(
                rule_id=0,
                candidate_id="",
                guest=guest_insts,
                host=host_insts,
            )
        )
        for existing_fp in self._emitted_fingerprints:
            if candidate_fp == existing_fp:
                self._record_skip(
                    candidate,
                    "duplicate_rule",
                    guest_insts,
                    host_insts,
                )
                return None
        self._emitted_fingerprints.append(candidate_fp)

        rule = GeneratedRule(
            rule_id=rule_id,
            candidate_id=candidate.candidate_id,
            rule=AstRule(
                rule_id=rule_id,
                candidate_id=candidate.candidate_id,
                guest=guest_insts,
                host=host_insts,
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


def _writer_covers_consumer(arch: str, writer: str, consumer: str) -> bool:
    """Return True if *writer* covers *consumer*: same register family AND
    the writer's bit range fully contains the consumer's bit range."""
    w_range = register_bit_range(arch, writer)
    c_range = register_bit_range(arch, consumer)
    if w_range is None or c_range is None:
        return False
    if register_family(arch, writer) != register_family(arch, consumer):
        return False
    return w_range[0] <= c_range[0] and w_range[1] >= c_range[1]


def _collect_fixed_role_sources(
    reg: str,
    before_idx: int,
    window: WindowPair,
    host_arch: str,
    host_inputs: frozenset[str],
    *,
    visited: frozenset[tuple[str, int]] = frozenset(),
) -> frozenset[str]:
    """Return the set of external input registers that feed into *reg*
    at instruction index *before_idx*.

    Each element of the returned set is a register name that appears in
    *host_inputs*.  Raises ``_RuleSkip("unbound_fixed_role_register")``
    if any dependency cannot be resolved to a mapped input.
    """
    reg_n = normalize_register_name(reg)
    state = (reg_n, before_idx)
    if state in visited:
        raise _RuleSkip("unbound_fixed_role_register")
    visited = visited | {state}

    # Search backward for the nearest covering writer FIRST.
    for prev_idx in range(before_idx - 1, -1, -1):
        prev_inst = window.host.instructions[prev_idx]
        for w in prev_inst.write_registers:
            w_n = normalize_register_name(w)
            if not _writer_covers_consumer(host_arch, w_n, reg_n):
                continue
            # Found a writer.  Resolve ALL of its read dependencies.
            all_sources: set[str] = set()
            for src in prev_inst.read_registers:
                src_n = normalize_register_name(src)
                sources = _collect_fixed_role_sources(
                    src_n,
                    prev_idx,
                    window,
                    host_arch,
                    host_inputs,
                    visited=visited,
                )
                all_sources.update(sources)
            if all_sources:
                return frozenset(all_sources)
            raise _RuleSkip("unbound_fixed_role_register")

    # No backward writer found.  Only at this point can an external
    # input serve as a provenance source, and only if it is NOT in
    # a fixed-role register family.
    in_fixed_family = (
        is_fixed_role_register(host_arch, reg_n)
        or fixed_role_family(host_arch, reg_n) is not None
    )
    if reg_n in host_inputs and not in_fixed_family:
        return frozenset({reg_n})

    raise _RuleSkip("unbound_fixed_role_register")


def _require_fixed_role_producers(
    window: WindowPair,
    candidate: VerificationCandidate,
) -> tuple[frozenset[str], frozenset[str]]:
    """Verify fixed-role provenance and return ``(producers, sources)``.

    *producers* are register names to keep as literals.
    *sources* are external input registers whose placeholders must
    appear in the emitted Host rule.
    """
    host_arch = candidate.host.arch
    host_inputs = frozenset(
        normalize_register_name(hr) for _gr, hr in candidate.input_registers
    )
    producers: set[str] = set()
    all_sources: set[str] = set()

    for inst_idx, inst in enumerate(window.host.instructions):
        for read_reg in inst.read_registers:
            read_n = normalize_register_name(read_reg)
            if not is_fixed_role_register(host_arch, read_n):
                continue

            # Find backward reaching definition.
            has_producer = False
            for prev_idx in range(inst_idx - 1, -1, -1):
                prev_inst = window.host.instructions[prev_idx]
                for w in prev_inst.write_registers:
                    w_n = normalize_register_name(w)
                    if _writer_covers_consumer(host_arch, w_n, read_n):
                        has_producer = True
                        producers.add(w_n)
                        # Collect ALL external sources.
                        deps = _collect_fixed_role_sources(
                            w_n,
                            prev_idx + 1,
                            window,
                            host_arch,
                            host_inputs,
                        )
                        all_sources.update(deps)
                        break
                if has_producer:
                    break

            if not has_producer:
                raise _RuleSkip("unbound_fixed_role_register")

    return frozenset(producers), frozenset(all_sources)


def _collect_ast_placeholders(insts: tuple[Instruction, ...]) -> frozenset[str]:
    """Return the set of placeholder strings appearing in *insts*, collected
    from operands, metadata, and tokenised compound operand text.

    For ``RegViewOp``, only the base placeholder is collected (e.g.
    ``i32_reg1`` from ``reg64(i32_reg1)``), because that is the semantic
    binding point.
    """
    from angr_rule_learning.rules.ast import LitOp, RegOp, RegTextOp, RegViewOp, TmpOp

    result: set[str] = set()
    for inst in insts:
        operands = list(inst.operands)
        for meta in inst.meta + inst.post_meta:
            operands.extend(meta.regs)
        for op in operands:
            if isinstance(op, (RegOp, TmpOp)):
                result.add(op.to_text())
            elif isinstance(op, RegViewOp):
                # Collect the *base* placeholder — the semantic binding,
                # not the view wrapper.
                result.add(op.base.to_text())
            elif isinstance(op, (LitOp, RegTextOp)):
                text = op.to_text()
                for token in _TOKEN_RE.findall(text):
                    if _PARAMETERIZED_TOKEN_RE.match(token):
                        result.add(token)
                    # Collect base placeholders nested inside reg64(...) text.
                    # The tokeniser splits reg64(i32_reg1) into "reg64"
                    # and "i32_reg1", but "i32_reg1" is already matched above.
                    # reg64 is not a binder itself, so skip it.
    return frozenset(result)


def _verify_host_registers_bound(
    guest_insts: tuple[Instruction, ...],
    host_insts: tuple[Instruction, ...],
) -> None:
    """Reject Host register parameters that cannot be supplied by Guest."""
    guest_registers = {
        token
        for token in _collect_ast_placeholders(guest_insts)
        if _GENERAL_REGISTER_PLACEHOLDER_RE.fullmatch(token)
    }
    host_registers = {
        token
        for token in _collect_ast_placeholders(host_insts)
        if _GENERAL_REGISTER_PLACEHOLDER_RE.fullmatch(token)
    }
    if not host_registers <= guest_registers:
        raise _RuleSkip("unbound_host_register")


def _verify_fixed_role_sources_in_host(
    host_insts: tuple[Instruction, ...],
    sources: frozenset[str],
    mapping: dict[str, str],
) -> None:
    """Verify that every provenance source's placeholder appears in the
    Host AST using exact token matching.  Missing mapping or placeholder
    causes rejection."""
    source_placeholders: set[str] = set()
    for s in sources:
        ph = mapping.get(normalize_register_name(s))
        if ph is None:
            raise _RuleSkip("unbound_fixed_role_register")
        source_placeholders.add(ph)

    host_tokens = _collect_ast_placeholders(host_insts)
    for ph in source_placeholders:
        if ph not in host_tokens:
            raise _RuleSkip("unbound_fixed_role_register")


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

        guest_fixed = is_fixed_role_register(guest_arch, guest_reg)
        host_fixed = is_fixed_role_register(host_arch, host_reg)
        if guest_fixed or host_fixed:
            # A fixed-role value must be established by an instruction inside
            # the corresponding fragment, not by a cross-ISA input binding.
            raise _RuleSkip("unsupported_rule_shape")

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
        elif host_existing is not None and guest_existing is None:
            existing = host_existing
        else:
            raise _RuleSkip("unsupported_rule_shape")

        guest_previous = mapping.get(guest_reg)
        if guest_previous is not None and guest_previous != existing:
            raise _RuleSkip("unsupported_rule_shape")
        mapping[guest_reg] = existing

        # Fixed-role Host registers stay literal so code generation retains
        # the ISA-required operand. Their producer is validated separately.
        if not host_fixed:
            host_previous = mapping.get(host_reg)
            if host_previous is not None and host_previous != existing:
                raise _RuleSkip("unsupported_rule_shape")
            mapping[host_reg] = existing
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


def normalize_arch_name(arch: str) -> str:
    return canonical_arch_name(arch)


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
    guest_insts: tuple[Instruction, ...],
    guest_arch: str,
    host_insts: tuple[Instruction, ...],
    host_arch: str,
    guest_instructions: tuple[ExtractedInstruction, ...] = (),
    host_instructions: tuple[ExtractedInstruction, ...] = (),
) -> tuple[tuple[Instruction, ...], tuple[Instruction, ...]]:
    """Replace hex branch targets in AST instructions with LabelOp placeholders.

    Assigns label IDs by matching branch targets to source locations.  Two
    branch targets that reference the same source location share a label ID.
    Unresolved targets are matched by position.
    """
    from angr_rule_learning.rules.ast import Instruction as AstInstruction, LabelOp

    guest_arch_n = normalize_arch_name(guest_arch)
    host_arch_n = normalize_arch_name(host_arch)

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

    # Collect targets from guest AST.
    guest_targets: list[tuple[str, tuple[str, int] | None]] = []
    for inst in guest_insts:
        if not _is_branch_instruction(inst, guest_arch):
            continue
        hex_info = _find_hex_operand(inst, guest_arch)
        if hex_info is not None:
            _idx, hex_val = hex_info
            sl = _resolve_source_line(hex_val, guest_lines_map)
            guest_targets.append((hex_val, sl))

    # Collect targets from host AST.
    host_targets: list[tuple[str, tuple[str, int] | None]] = []
    for inst in host_insts:
        if not _is_branch_instruction(inst, host_arch):
            continue
        hex_info = _find_hex_operand(inst, host_arch)
        if hex_info is not None:
            _idx, hex_val = hex_info
            sl = _resolve_source_line(hex_val, host_lines_map)
            host_targets.append((hex_val, sl))

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

    # Apply label IDs to guest instructions.
    guest_result: list[Instruction] = []
    gidx = 0
    for inst in guest_insts:
        if _is_branch_instruction(inst, guest_arch):
            hex_info = _find_hex_operand(inst, guest_arch)
            if hex_info is not None and gidx < len(guest_label_ids):
                op_idx, _hex_val = hex_info
                new_ops = list(inst.operands)
                is_aarch64 = guest_arch_n == "aarch64"
                new_ops[op_idx] = LabelOp(
                    id=guest_label_ids[gidx], aarch64_hash=is_aarch64
                )
                inst = AstInstruction(
                    mnemonic=inst.mnemonic,
                    operands=tuple(new_ops),
                    meta=inst.meta,
                    post_meta=inst.post_meta,
                )
                gidx += 1
        guest_result.append(inst)

    # Apply label IDs to host instructions.
    host_result: list[Instruction] = []
    hidx = 0
    for inst in host_insts:
        if _is_branch_instruction(inst, host_arch):
            hex_info = _find_hex_operand(inst, host_arch)
            if hex_info is not None and hidx < len(host_label_ids):
                op_idx, _hex_val = hex_info
                new_ops = list(inst.operands)
                is_aarch64 = host_arch_n == "aarch64"
                new_ops[op_idx] = LabelOp(
                    id=host_label_ids[hidx], aarch64_hash=is_aarch64
                )
                inst = AstInstruction(
                    mnemonic=inst.mnemonic,
                    operands=tuple(new_ops),
                    meta=inst.meta,
                    post_meta=inst.post_meta,
                )
                hidx += 1
        host_result.append(inst)

    return tuple(guest_result), tuple(host_result)


def _replace_immediates_ast(
    guest_insts: tuple[Instruction, ...],
    guest_arch: str,
    host_insts: tuple[Instruction, ...],
    host_arch: str,
) -> tuple[tuple[Instruction, ...], tuple[Instruction, ...]]:
    """Replace immediate values in AST instructions with ImmOp placeholders.

    Collection: scans instruction text for immediate values using the
    existing regex patterns and assigns IDs.

    Replacement: substitutes each matched immediate text in the instruction
    text with ``immN`` placeholders, then re-parses to AST.
    """
    from angr_rule_learning.rules.ast import Instruction as AstInstruction

    guest_arch_n = normalize_arch_name(guest_arch)
    host_arch_n = normalize_arch_name(host_arch)
    patterns = {
        "aarch64": _AARCH64_IMM_RE,
        "x86-64": _X86_64_IMM_RE,
    }
    try:
        guest_pattern = patterns[guest_arch_n]
        host_pattern = patterns[host_arch_n]
    except KeyError as exc:
        raise _RuleSkip("unsupported_rule_shape") from exc

    canonical_to_id: dict[str, int] = {}
    value_by_id: dict[str, int] = {}
    next_id = 1

    # ---- Phase 1: Collection ----
    for inst in guest_insts:
        line = inst.to_text()
        for m in guest_pattern.finditer(line):
            c = _imm_canonical(m, guest_arch)
            if c in _RESERVED_LITERALS:
                continue
            if c not in canonical_to_id:
                canonical_to_id[c] = next_id
                next_id += 1
            value_by_id[str(canonical_to_id[c])] = int(c)

    for inst in host_insts:
        line = inst.to_text()
        for m in host_pattern.finditer(line):
            c = _imm_canonical(m, host_arch)
            if c in _RESERVED_LITERALS:
                continue
            if c not in canonical_to_id:
                canonical_to_id[c] = next_id
                next_id += 1
            value_by_id[str(canonical_to_id[c])] = int(c)

    # ---- Phase 2: Replacement ----
    def _make_replacer(arch: str, prefix: str):
        def _replacer(match: re.Match[str]) -> str:
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

        return _replacer

    def _replace_operand(op: Operand, pattern: re.Pattern[str], replacer) -> Operand:
        """Apply immediate regex substitution to a single operand's text,
        rebuilding typed operands where possible."""
        from angr_rule_learning.rules.ast import (
            ImmOp,
            LitOp,
            RegTextOp,
        )

        text = op.to_text()
        new_text = pattern.sub(replacer, text)
        if new_text == text:
            return op

        # Try to re-parse the replaced text as a typed operand.
        # The Instruction._parse_operand static method handles this.
        parsed = AstInstruction._parse_operand(new_text)
        if isinstance(parsed, ImmOp):
            # Transfer ids; the parsed ImmOp may have a new id — trust the
            # replacer's assignment (the ImmOp's id field reflects the last
            # match's numbering, which is what we want).
            return parsed
        if isinstance(op, LitOp):
            return LitOp(value=new_text)
        if isinstance(op, RegTextOp):
            return RegTextOp(text=new_text)
        # Fallback: keep the parsed form if it changed type
        return parsed

    def _replace_side(
        insts: tuple[Instruction, ...],
        pattern: re.Pattern[str],
        arch: str,
        prefix: str,
    ) -> tuple[Instruction, ...]:
        replacer = _make_replacer(arch, prefix)
        result: list[Instruction] = []
        for inst in insts:
            new_operands = tuple(
                _replace_operand(op, pattern, replacer) for op in inst.operands
            )
            if new_operands != inst.operands:
                inst = AstInstruction(
                    mnemonic=inst.mnemonic,
                    operands=new_operands,
                    meta=inst.meta,
                    post_meta=inst.post_meta,
                )
            result.append(inst)
        return tuple(result)

    prefixes = {"aarch64": "#", "x86-64": ""}
    guest_result = _replace_side(
        guest_insts,
        guest_pattern,
        guest_arch_n,
        prefixes[guest_arch_n],
    )
    host_result = _replace_side(
        host_insts,
        host_pattern,
        host_arch_n,
        prefixes[host_arch_n],
    )

    # ---- Phase 3: Derivation ----
    ctx = DerivationContext(
        guest_insts=guest_result,
        host_insts=host_result,
        guest_arch=guest_arch_n,
        host_arch=host_arch_n,
        value_by_id=value_by_id,
    )
    host_result = derive_host_expressions(ctx)

    return guest_result, host_result


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


def _check_label_consistency_ast(
    guest_insts: tuple[Instruction, ...],
    host_insts: tuple[Instruction, ...],
) -> None:
    """Check label consistency directly on AST instructions."""
    if not labels_are_consistent(guest_insts, host_insts):
        raise _RuleSkip("mismatched_branch_targets")


def _host_immediates_are_derivable(
    guest_insts: tuple[Instruction, ...],
    host_insts: tuple[Instruction, ...],
    candidate: VerificationCandidate,
) -> bool:
    """Return True when every host immediate is either shared with the guest or
    has been expressed via a derivation strategy.

    This check is universal — it applies to all rule types, not just
    frame-relative memory rules.  ``collect_instruction_imm_ids`` already
    handles derived ImmOps correctly: for a derived ImmOp it collects the
    guest ``immN`` references from the derivation text rather than the
    ImmOp's own host-only id.
    """
    guest_imms = collect_instruction_imm_ids(guest_insts)
    host_imms = collect_instruction_imm_ids(host_insts)
    return host_imms <= guest_imms


def consolidate_rules(
    rules: list[GeneratedRule],
    diagnostics: RuleDiagnostics | None = None,
) -> list[GeneratedRule]:
    """Remove rules that are subsumed by a more-parameterised rule.

    A rule *A* is subsumed by rule *B* when substituting one of *B*'s
    ``immN`` placeholders with a reserved literal value produces the
    exact same structure as *A*.

    Uses AST-based structural comparison so that difference in
    placeholder numbering does not prevent merging.

    If *diagnostics* is provided, subsumed rules are recorded via
    ``diagnostics.record_subsumed()`` so that ``rules_emitted``
    reflects the final count after consolidation.
    """
    if len(rules) < 2:
        return rules

    from angr_rule_learning.rules.ast import (
        collect_imm_ids,
        rule_alpha_equal,
        substitute_imm,
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
                    if rule_alpha_equal(subbed, rule_a.rule):
                        subsumed_ids.add(rule_a.rule_id)
                        break
                if rule_a.rule_id in subsumed_ids:
                    break

    removed = len(subsumed_ids)
    if removed > 0 and diagnostics is not None:
        diagnostics.record_subsumed(removed)

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
    output_families = {
        family_for_register(arch, reg)
        for pair in candidate.output_registers
        for arch, reg in [
            (candidate.guest.arch, pair[0]),
            (candidate.host.arch, pair[1]),
        ]
    }
    cc_families = {"nzcv", "rflags"}

    def _dead_write_info(
        instructions: tuple[ExtractedInstruction, ...],
    ) -> tuple[dict[str, int], dict[str, int]]:
        """Return (first_write: reg→idx, last_access: reg→idx).

        Uses register *families* (w8≡x8, eax≡rax) as the identity for
        dead-write tracking.  A write to a family member after the first
        write is treated as a later access, not a separate saved register.
        """
        first_write: dict[str, int] = {}
        dead_families: set[str] = set()
        last_access: dict[str, int] = {}

        for idx, inst in enumerate(instructions):
            for reg in inst.write_registers:
                family = family_for_register(inst.arch, reg)
                if family in cc_families or is_allowed_literal_register(inst.arch, reg):
                    continue
                if (
                    family not in output_families
                    and family not in dead_families
                    and "_tmp" not in mapping.get(reg, "")
                ):
                    first_write[reg] = idx
                    dead_families.add(family)
                if family in dead_families:
                    for fw_reg in list(first_write.keys()):
                        fw_family = family_for_register(inst.arch, fw_reg)
                        if fw_family == family:
                            last_access[fw_reg] = idx
            for reg in inst.read_registers:
                family = family_for_register(inst.arch, reg)
                for fw_reg in list(first_write.keys()):
                    fw_family = family_for_register(inst.arch, fw_reg)
                    if fw_family == family:
                        last_access[fw_reg] = idx
        return first_write, last_access

    def _text_to_regop(placeholder: str, arch: str) -> Operand:
        from angr_rule_learning.rules.ast import LitOp, RegOp, RegViewOp, TmpOp

        # Handle reg64(i32_reg1) — parse the base and wrap in RegViewOp.
        m = re.fullmatch(r"reg(\d+)\((.+)\)", placeholder)
        if m:
            view_bits = int(m.group(1))
            base = _text_to_regop(m.group(2), arch)
            if isinstance(base, (RegOp, TmpOp)):
                return RegViewOp(base=base, view_bits=view_bits)
            raise ValueError(f"invalid base in register view: {placeholder!r}")

        m = re.fullmatch(r"(i\d+)_reg(\d+)", placeholder)
        if m:
            bits = int(m.group(1)[1:])
            return RegOp(prefix=m.group(1), bits=bits, id=int(m.group(2)))
        m = re.fullmatch(r"(sp|fp)(\d+)", placeholder)
        if m:
            return RegOp(prefix=m.group(1), bits=int(m.group(2)), id=0)
        m = re.fullmatch(r"(i\d+|f\d+|v\d+)_tmp(\d+)", placeholder)
        if m:
            prefix = m.group(1)
            bits = int(prefix[1:])
            return TmpOp(prefix=prefix, bits=bits, id=int(m.group(2)))
        # Fixed-role producer targets (validated by
        # _require_fixed_role_producers) are kept as literal register
        # names.  For save/restore, normalise to the widest family
        # register so that save rcx / restore rcx preserves the full
        # register even when the instruction writes a sub-register.
        # Only accept physical names belonging to this instruction stream.
        if re.fullmatch(r"[a-z][a-z0-9]+", placeholder, re.IGNORECASE):
            if placeholder in known_register_tokens(arch):
                normalized = fixed_role_preserve_register(arch, placeholder)
                return LitOp(value=normalized)
        raise ValueError(f"unknown placeholder format: {placeholder!r}")

    def _apply(
        insts: tuple[Instruction, ...],
        instructions: tuple[ExtractedInstruction, ...],
        arch: str,
    ) -> tuple[Instruction, ...]:
        from angr_rule_learning.rules.ast import Instruction as AstInstruction, MetaOp

        first_write, last_access = _dead_write_info(instructions)
        if not first_write:
            return insts

        result: list[Instruction] = []
        for idx, inst in enumerate(insts):
            new_meta = inst.meta
            new_post_meta = inst.post_meta

            # attach save to the first dead-write instruction
            first_writes_here = tuple(
                _text_to_regop(mapping.get(r, r), arch)
                for r, fw_idx in first_write.items()
                if fw_idx == idx
            )
            if first_writes_here:
                new_meta = new_meta + (MetaOp(kind="save", regs=first_writes_here),)

            # attach restore to the last-access instruction's post_meta
            restores_here = tuple(
                _text_to_regop(mapping.get(r, r), arch)
                for r, la_idx in last_access.items()
                if la_idx == idx
            )
            if restores_here:
                new_post_meta = new_post_meta + (
                    MetaOp(kind="restore", regs=restores_here),
                )

            if new_meta != inst.meta or new_post_meta != inst.post_meta:
                inst = AstInstruction(
                    mnemonic=inst.mnemonic,
                    operands=inst.operands,
                    meta=new_meta,
                    post_meta=new_post_meta,
                )
            result.append(inst)
        return tuple(result)

    return (
        _apply(guest_insts, window.guest.instructions, guest_arch),
        _apply(host_insts, window.host.instructions, host_arch),
    )


def _instructions_to_ast(
    instructions: tuple[ExtractedInstruction, ...],
) -> tuple[Instruction, ...]:
    from angr_rule_learning.rules.ast import Instruction as AstInstruction

    return tuple(
        AstInstruction.from_text(_instruction_text(inst)) for inst in instructions
    )


def _generalize_instructions_with_roles(
    insts: tuple[Instruction, ...],
    extracted: tuple[ExtractedInstruction, ...],
    mapping: dict[str, str],
    role_split: dict[str, tuple[str, str]],
    arch: str,
    *,
    allowed_literals: frozenset[str] = frozenset(),
) -> tuple[Instruction, ...]:
    """Replace physical register operands in AST instructions with typed placeholders.

    Applies text-level regex replacement within LitOp/RegTextOp operand values,
    so that registers embedded in compound operands (``[rcx]``, ``[edi + esi]``)
    are correctly replaced.  Where an entire operand becomes a single register
    placeholder, the operand is replaced with a typed AST node (RegOp or TmpOp).

    Step 1: Handle role-split registers.
    Step 2: Replace remaining physical registers via *mapping*.
    Step 3: Apply register-view replacements (e.g. rdi→reg64(i32_reg2)).
    Step 4: Validate no physical registers remain.
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

        # Step 3: Apply register-view replacements.
        # This replaces physical registers that are same-family wider
        # variants of mapped registers with reg64(i32_regN) text.
        views = resolve_register_views(arch, ext, mapping)
        for rv in sorted(views, key=lambda r: len(r.physical_register), reverse=True):
            rewritten = re.sub(
                rf"(?<![A-Za-z0-9_]){re.escape(rv.physical_register)}(?![A-Za-z0-9_])",
                rv.replacement_text,
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
                    new_operands.append(parse_placeholder(text))
                except ValueError:
                    new_operands.append(op)
            else:
                new_operands.append(op)

        result.append(
            AstInstruction(
                mnemonic=parsed.mnemonic,
                operands=tuple(new_operands),
                meta=inst.meta,
                post_meta=inst.post_meta,
            )
        )

    # Step 4: Validate.
    _validate_no_remaining_registers(
        tuple(result), arch, allowed_literals=allowed_literals
    )

    return tuple(result)


_PARAMETERIZED_TOKEN_RE = re.compile(
    r"^(?:[ifv]\d+_reg\d+|sp\d+|fp\d+|[ifv]\d+_tmp\d+|imm\d+|label\d+)$"
)
_GENERAL_REGISTER_PLACEHOLDER_RE = re.compile(r"^[ifv]\d+_reg\d+$")
_KEYWORD_TOKENS = frozenset({"dword", "word", "byte", "qword", "ptr", "lsl"})
# reg64/reg32/etc. are view-cast function keywords in rule text.
_VIEW_FUNCTION_TOKENS = re.compile(r"^reg\d+$")
_TOKEN_RE = re.compile(r"\[|\]|0x[0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[-+*/#]")


def _validate_no_remaining_registers(
    insts: tuple[Instruction, ...],
    arch: str,
    *,
    allowed_literals: frozenset[str] = frozenset(),
) -> None:
    from angr_rule_learning.rules.ast import LitOp, RegTextOp

    known = known_register_tokens(arch)
    for inst in insts:
        for op in inst.operands:
            if isinstance(op, (LitOp, RegTextOp)):
                text = op.to_text()
                # Tokenize: split into brackets, identifiers, numbers,
                # hex literals, and operators.
                tokens = _TOKEN_RE.findall(text)
                for token in tokens:
                    # Skip brackets and operators.
                    if token in {"[", "]", "+", "-", "*", "/", "#"}:
                        continue
                    token_n = normalize_register_name(token)
                    if token_n in _KEYWORD_TOKENS:
                        continue
                    if _PARAMETERIZED_TOKEN_RE.match(token_n):
                        continue
                    if _VIEW_FUNCTION_TOKENS.match(token_n):
                        continue
                    if is_allowed_literal_register(arch, token_n):
                        continue
                    if _RESERVED_LITERALS and token_n in _RESERVED_LITERALS:
                        continue
                    # Fixed-role host registers (e.g. cl for shift counts)
                    # are emitted as literals and should not trigger
                    # unmapped-register errors.
                    if is_fixed_role_register(arch, token_n):
                        continue
                    # Fixed-role producer targets (e.g. ecx that feeds cl)
                    # are kept as literals to preserve register-family identity.
                    if token_n in allowed_literals:
                        continue
                    # Skip bare numeric tokens (decimal or hex).
                    try:
                        int(token_n, 0)
                        continue
                    except ValueError:
                        pass
                    if token_n in known:
                        raise _RuleSkip("unmapped_register_surface")


def _instruction_lines(
    instructions: tuple[ExtractedInstruction, ...],
) -> tuple[str, ...]:
    return tuple(_instruction_text(inst) for inst in instructions)


def _identify_internal_temps(
    window: WindowPair,
    candidate: VerificationCandidate,
) -> dict[str, str]:
    """Map per-side internal temporary registers to typed tmpN placeholders.

    A register is an internal temp when it is **written** inside the
    window but does **not** appear as an output or input register of the
    candidate.  Literal registers (sp, xzr, …) and condition-code
    families are excluded.

    Each temp carries type/width information (e.g. ``i32_tmp1``)
    derived from the register's classification via ``_classify_for_rule``.
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
                    reg_class = _classify_for_rule(arch, reg_n)
                    placeholder = f"{reg_class.placeholder_prefix}_tmp{next_tmp}"
                    temps[reg_n] = placeholder
                    next_tmp += 1

    return temps
