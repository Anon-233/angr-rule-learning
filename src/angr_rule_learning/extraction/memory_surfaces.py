from __future__ import annotations

import re
from dataclasses import dataclass

from angr_rule_learning.extraction.liveness import family_for_register
from angr_rule_learning.extraction.memory_operands import (
    MemoryOperand,
    _AARCH64_PAIR_POST_RE,
    _AARCH64_PAIR_PRE_OR_OFFSET_RE,
    _X86_PUSH_IMM_RE,
    _X86_PUSH_POP_REG_RE,
    _parse_displacement,
    _x86_push_pop_width,
    extract_memory_operands,
    has_any_memory_access,
)
from angr_rule_learning.verification.addressing import AddressExpr
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    WindowPair,
)
from angr_rule_learning.verification.candidate import (
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
)


@dataclass(frozen=True)
class _CollectedMemoryOperand:
    instruction: ExtractedInstruction
    operand: MemoryOperand


@dataclass(frozen=True)
class MemorySurface:
    spec: MemorySpec
    input_registers: tuple[tuple[str, str], ...] = ()
    address_registers: tuple[tuple[str, str], ...] = ()
    skip_reason: str | None = None
    skip_detail: str | None = None
    guest_operands: tuple[MemoryOperand, ...] = ()
    host_operands: tuple[MemoryOperand, ...] = ()

    @property
    def has_memory(self) -> bool:
        return bool(self.guest_operands or self.host_operands)


def infer_memory_surface(pair: WindowPair) -> MemorySurface:
    guest_collected = _collect(pair.guest)
    host_collected = _collect(pair.host)
    guest_operands = tuple(item.operand for item in guest_collected)
    host_operands = tuple(item.operand for item in host_collected)

    if _has_unparsed_memory(pair.guest, guest_operands) or _has_unparsed_memory(
        pair.host, host_operands
    ):
        return MemorySurface(
            MemorySpec(),
            skip_reason="unsupported_memory_surface",
            skip_detail="unparsed_memory_access",
            guest_operands=guest_operands,
            host_operands=host_operands,
        )

    if not guest_operands and not host_operands:
        return MemorySurface(MemorySpec())
    if not guest_operands or not host_operands:
        return MemorySurface(
            MemorySpec(),
            skip_reason="unsupported_memory_surface",
            skip_detail="one_sided_memory_access",
        )
    if len(guest_operands) != len(host_operands):
        return MemorySurface(
            MemorySpec(),
            skip_reason="unsupported_memory_surface",
            skip_detail="memory_access_count_mismatch",
            guest_operands=guest_operands,
            host_operands=host_operands,
        )

    slots: list[MemorySlot] = []
    bindings: list[MemoryBinding] = []
    accesses: list[MemoryAccessExpectation] = []
    input_registers: list[tuple[str, str]] = []

    for index, (guest_item, host_item) in enumerate(
        zip(guest_collected, host_collected, strict=True)
    ):
        guest = guest_item.operand
        host = host_item.operand
        if guest.kind != host.kind:
            return MemorySurface(
                MemorySpec(),
                skip_reason="unsupported_memory_surface",
                skip_detail="memory_kind_mismatch",
                guest_operands=guest_operands,
                host_operands=host_operands,
            )
        if guest.width != host.width:
            return MemorySurface(
                MemorySpec(),
                skip_reason="unsupported_memory_surface",
                skip_detail="memory_width_mismatch",
                guest_operands=guest_operands,
                host_operands=host_operands,
            )
        slot_name = f"mem{index}"
        slots.append(MemorySlot(slot_name, guest.width))
        bindings.append(
            MemoryBinding(
                slot_name,
                guest.address.canonical(),
                host.address.canonical(),
                guest.kind,
            )
        )
        accesses.append(MemoryAccessExpectation(slot_name, guest.kind, guest.width))
        guest_addr_regs = guest.address.registers()
        host_addr_regs = host.address.registers()
        if len(guest_addr_regs) != len(host_addr_regs):
            return MemorySurface(
                MemorySpec(),
                skip_reason="unsupported_memory_surface",
                skip_detail="memory_address_register_count_mismatch",
                guest_operands=guest_operands,
                host_operands=host_operands,
            )
        for guest_reg, host_reg in zip(guest_addr_regs, host_addr_regs, strict=True):
            if _is_frame_address_pair(guest_reg, host_reg):
                continue
            input_registers.append((guest_reg, host_reg))
        if guest.kind == "write":
            if guest.value_register is None or host.value_register is None:
                return MemorySurface(
                    MemorySpec(),
                    skip_reason="unsupported_memory_surface",
                    skip_detail="store_value_immediate_unsupported",
                    guest_operands=guest_operands,
                    host_operands=host_operands,
                )
            guest_value_internal = _value_is_defined_before(pair.guest, guest_item)
            host_value_internal = _value_is_defined_before(pair.host, host_item)
            if guest_value_internal != host_value_internal:
                return MemorySurface(
                    MemorySpec(),
                    skip_reason="unsupported_memory_surface",
                    skip_detail="store_value_internality_mismatch",
                    guest_operands=guest_operands,
                    host_operands=host_operands,
                )
            if guest_value_internal:
                guest_sources = _producer_external_sources(pair.guest, guest_item)
                host_sources = _producer_external_sources(pair.host, host_item)
                if len(guest_sources) != len(host_sources):
                    return MemorySurface(
                        MemorySpec(),
                        skip_reason="unsupported_memory_surface",
                        skip_detail="store_producer_source_count_mismatch",
                        guest_operands=guest_operands,
                        host_operands=host_operands,
                    )
                input_registers.extend(zip(guest_sources, host_sources, strict=True))
            else:
                input_registers.append((guest.value_register, host.value_register))

    return MemorySurface(
        MemorySpec(tuple(slots), tuple(bindings), tuple(accesses), ()),
        input_registers=tuple(input_registers),
        guest_operands=guest_operands,
        host_operands=host_operands,
    )


_STACK_POINTERS = frozenset({"sp", "wsp", "rsp", "esp"})

_AARCH64_SP_ADDSUB_RE = re.compile(
    r"^sp\s*,\s*sp\s*,\s*#(?P<imm>(?:0x[0-9a-fA-F]+|\d+))$",
    re.IGNORECASE,
)
_X86_SP_ADDSUB_RE = re.compile(
    r"^rsp\s*,\s*(?P<imm>(?:0x[0-9a-fA-F]+|\d+))$",
    re.IGNORECASE,
)


def _instruction_sp_delta(inst: ExtractedInstruction) -> int:
    """Return the net change in the stack pointer caused by *inst*."""
    arch = inst.arch.strip().lower()
    mnemonic = inst.mnemonic.strip().lower()
    op_str = inst.op_str.strip()
    if arch == "x86-64":
        return _x86_sp_delta(mnemonic, op_str)
    if arch == "aarch64":
        return _aarch64_sp_delta(mnemonic, op_str)
    return 0


def _x86_sp_delta(mnemonic: str, op_str: str) -> int:
    if mnemonic == "push":
        match = _X86_PUSH_POP_REG_RE.search(op_str)
        if match:
            reg = match.group("reg").lower()
            width = _x86_push_pop_width(reg)
            return -(width or 8)
        match = _X86_PUSH_IMM_RE.search(op_str)
        if match:
            return -8
        return 0
    if mnemonic == "pop":
        match = _X86_PUSH_POP_REG_RE.search(op_str)
        if match:
            reg = match.group("reg").lower()
            width = _x86_push_pop_width(reg)
            return width or 8
        return 0
    if mnemonic in {"add", "sub"}:
        match = _X86_SP_ADDSUB_RE.match(op_str)
        if match:
            imm = int(match.group("imm"), 0)
            return imm if mnemonic == "add" else -imm
    return 0


def _aarch64_sp_delta(mnemonic: str, op_str: str) -> int:
    if mnemonic in {"stp", "stnp"}:
        # ldnp/stnp do not support writeback (rejected at extraction).
        match = _AARCH64_PAIR_PRE_OR_OFFSET_RE.match(op_str)
        if match and match.group("writeback"):
            offset_str = match.group("offset")
            return _parse_displacement(offset_str, "+") if offset_str else 0
        return 0
    if mnemonic in {"ldp", "ldnp"}:
        # Non-temporal post-index is rejected at extraction.
        match = _AARCH64_PAIR_POST_RE.match(op_str)
        if match:
            return _parse_displacement(match.group("offset"), "+")
        return 0
    if mnemonic in {"add", "sub"}:
        match = _AARCH64_SP_ADDSUB_RE.match(op_str)
        if match:
            imm = int(match.group("imm"), 0)
            return imm if mnemonic == "add" else -imm
    return 0


def _adjust_for_sp_delta(op: MemoryOperand, delta: int) -> MemoryOperand:
    """If *op* uses a stack-pointer base register, adjust its displacement
    by the cumulative *delta* from preceding instructions."""
    if delta == 0 or op.address.base not in _STACK_POINTERS:
        return op
    return MemoryOperand(
        kind=op.kind,
        width=op.width,
        address=AddressExpr(
            base=op.address.base,
            index=op.address.index,
            scale=op.address.scale,
            displacement=op.address.displacement + delta,
        ),
        text=op.text,
        value_register=op.value_register,
        value_immediate=op.value_immediate,
    )


def _collect(window: InstructionWindow) -> tuple[_CollectedMemoryOperand, ...]:
    operands: list[_CollectedMemoryOperand] = []
    sp_delta = 0
    for instruction in window.instructions:
        for operand in extract_memory_operands(instruction):
            adjusted = _adjust_for_sp_delta(operand, sp_delta)
            operands.append(_CollectedMemoryOperand(instruction, adjusted))
        sp_delta += _instruction_sp_delta(instruction)
    return tuple(operands)


def _value_is_defined_before(
    window: InstructionWindow,
    target: _CollectedMemoryOperand,
) -> bool:
    return _find_value_producer(window, target) is not None


def _find_value_producer(
    window: InstructionWindow,
    target: _CollectedMemoryOperand,
) -> ExtractedInstruction | None:
    value_family = family_for_register(
        target.instruction.arch,
        target.operand.value_register,
    )
    return _find_most_recent_writer(window, value_family, target.instruction)


def _find_most_recent_writer(
    window: InstructionWindow,
    reg_family: str,
    before: ExtractedInstruction,
) -> ExtractedInstruction | None:
    """Return the instruction that most recently wrote to *reg_family*,
    scanning backward from (but not including) *before*."""
    found = False
    for instruction in reversed(window.instructions):
        if instruction is before:
            found = True
            continue
        if not found:
            continue
        written = {
            family_for_register(instruction.arch, register)
            for register in instruction.write_registers
        }
        if reg_family in written:
            return instruction
    return None


def _producer_external_sources(
    window: InstructionWindow,
    target: _CollectedMemoryOperand,
) -> list[str]:
    """Return the ultimate external read registers feeding the store value,
    tracing through a chain of internally-defined value producers.

    Returns an empty list if the value has no producer.  Callers must pair
    guest and host source lists; if lengths differ the call site returns
    ``unsupported_memory_surface``.
    """
    producer = _find_value_producer(window, target)
    if producer is None:
        return []

    # Guard recursion depth for safety (arbitrary but prevents bugs from
    # hanging in a pathological cycle — cycles shouldn't happen in
    # straight-line code but this is a belt-and-suspenders check).
    return _collect_external_sources(window, producer, depth=0, max_depth=8)


def _collect_external_sources(
    window: InstructionWindow,
    producer: ExtractedInstruction,
    *,
    depth: int,
    max_depth: int,
) -> list[str]:
    if depth > max_depth:
        return []  # safety valve

    external: list[str] = []
    for read_reg in producer.read_registers:
        family = family_for_register(producer.arch, read_reg)
        inner = _find_most_recent_writer(window, family, producer)
        if inner is not None:
            inner_sources = _collect_external_sources(
                window, inner, depth=depth + 1, max_depth=max_depth
            )
            external.extend(inner_sources)
        else:
            external.append(read_reg)
    return external


_AARCH64_FRAME_REGS = {"sp", "wsp", "x29", "fp"}
_X86_64_FRAME_REGS = {"rsp", "esp", "sp", "rbp", "ebp", "bp"}


def _is_frame_address_pair(guest_reg: str, host_reg: str) -> bool:
    return (
        guest_reg.lower() in _AARCH64_FRAME_REGS
        and host_reg.lower() in _X86_64_FRAME_REGS
    )


def _has_unparsed_memory(
    window: InstructionWindow,
    parsed: tuple[MemoryOperand, ...],
) -> bool:
    parsed_count = len(parsed)
    memory_inst_count = sum(
        1 for inst in window.instructions if has_any_memory_access(inst)
    )
    return memory_inst_count > parsed_count
