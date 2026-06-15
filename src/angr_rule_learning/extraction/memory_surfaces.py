from __future__ import annotations

from dataclasses import dataclass

from angr_rule_learning.extraction.memory_operands import (
    MemoryOperand,
    extract_memory_operands,
    has_any_memory_access,
)
from angr_rule_learning.extraction.models import InstructionWindow, WindowPair
from angr_rule_learning.verification.candidate import (
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
)


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
    guest_operands = _collect(pair.guest)
    host_operands = _collect(pair.host)

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

    for index, (guest, host) in enumerate(
        zip(guest_operands, host_operands, strict=True)
    ):
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
            input_registers.append((guest.value_register, host.value_register))

    return MemorySurface(
        MemorySpec(tuple(slots), tuple(bindings), tuple(accesses), ()),
        input_registers=tuple(input_registers),
        guest_operands=guest_operands,
        host_operands=host_operands,
    )


def _collect(window: InstructionWindow) -> tuple[MemoryOperand, ...]:
    operands: list[MemoryOperand] = []
    for instruction in window.instructions:
        operands.extend(extract_memory_operands(instruction))
    return tuple(operands)


def _has_unparsed_memory(
    window: InstructionWindow,
    parsed: tuple[MemoryOperand, ...],
) -> bool:
    parsed_count = len(parsed)
    memory_inst_count = sum(
        1 for inst in window.instructions if has_any_memory_access(inst)
    )
    return memory_inst_count > parsed_count
