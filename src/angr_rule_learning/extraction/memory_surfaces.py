from __future__ import annotations

from dataclasses import dataclass

from angr_rule_learning.extraction.liveness import family_for_register
from angr_rule_learning.extraction.memory_operands import (
    MemoryOperand,
    extract_memory_operands,
    has_any_memory_access,
)
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
            guest_operands=guest_operands,
            host_operands=host_operands,
        )

    if not guest_operands and not host_operands:
        return MemorySurface(MemorySpec())
    if not guest_operands or not host_operands:
        return MemorySurface(MemorySpec(), skip_reason="unsupported_memory_surface")
    if len(guest_operands) != len(host_operands):
        return MemorySurface(
            MemorySpec(),
            skip_reason="unsupported_memory_surface",
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
        if guest.kind != host.kind or guest.width != host.width:
            return MemorySurface(
                MemorySpec(),
                skip_reason="unsupported_memory_surface",
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
                guest_operands=guest_operands,
                host_operands=host_operands,
            )
        input_registers.extend(zip(guest_addr_regs, host_addr_regs, strict=True))
        if guest.kind == "write":
            guest_value_internal = _value_is_defined_before(pair.guest, guest_item)
            host_value_internal = _value_is_defined_before(pair.host, host_item)
            if guest_value_internal != host_value_internal:
                return MemorySurface(
                    MemorySpec(),
                    skip_reason="unsupported_memory_surface",
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


def _collect(window: InstructionWindow) -> tuple[_CollectedMemoryOperand, ...]:
    operands: list[_CollectedMemoryOperand] = []
    for instruction in window.instructions:
        operands.extend(
            _CollectedMemoryOperand(instruction, operand)
            for operand in extract_memory_operands(instruction)
        )
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
    for instruction in window.instructions:
        if instruction is target.instruction:
            return None
        written = {
            family_for_register(instruction.arch, register)
            for register in instruction.write_registers
        }
        if value_family in written:
            return instruction
    return None


def _producer_external_sources(
    window: InstructionWindow,
    target: _CollectedMemoryOperand,
) -> list[str]:
    """Return the read registers of the value producer that are externally
    sourced (not defined by any prior instruction in the window)."""
    producer = _find_value_producer(window, target)
    if producer is None:
        return []
    external: list[str] = []
    for read_reg in producer.read_registers:
        family = family_for_register(producer.arch, read_reg)
        defined_before = False
        for instruction in window.instructions:
            if instruction is producer:
                break
            if family in {
                family_for_register(instruction.arch, reg)
                for reg in instruction.write_registers
            }:
                defined_before = True
                break
        if not defined_before:
            external.append(read_reg)
    return external


def _has_unparsed_memory(
    window: InstructionWindow,
    parsed: tuple[MemoryOperand, ...],
) -> bool:
    parsed_count = len(parsed)
    memory_inst_count = sum(
        1 for inst in window.instructions if has_any_memory_access(inst)
    )
    return memory_inst_count > parsed_count
