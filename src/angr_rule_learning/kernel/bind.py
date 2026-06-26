from __future__ import annotations

from angr_rule_learning.arch.registry import canonical_arch_name
from angr_rule_learning.extraction.models import InstructionWindow, WindowPair
from angr_rule_learning.kernel.models import BindingSpec, IRKernel, SnippetPair
from angr_rule_learning.verification.candidate import (
    Clobbers,
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    RegisterBindingRole,
    VerificationCandidate,
)


_AARCH64_ARGS = {
    32: ("w0", "w1", "w2", "w3"),
    64: ("x0", "x1", "x2", "x3"),
}
_AARCH64_RET = {32: "w0", 64: "x0"}

_X86_64_ARGS = {
    32: ("edi", "esi", "edx", "ecx"),
    64: ("rdi", "rsi", "rdx", "rcx"),
}
_X86_64_RET = {32: "eax", 64: "rax"}


class KernelBindingBuilder:
    def build_spec(
        self, kernel: IRKernel, guest_arch: str, host_arch: str
    ) -> BindingSpec:
        guest_arch = canonical_arch_name(guest_arch)
        host_arch = canonical_arch_name(host_arch)
        inputs = tuple(
            (
                value.name,
                _argument_register(guest_arch, value.bit_width, index),
                _argument_register(host_arch, value.bit_width, index),
            )
            for index, value in enumerate(kernel.signature.inputs)
        )
        outputs = tuple(
            (
                value.name,
                _return_register(guest_arch, value.bit_width),
                _return_register(host_arch, value.bit_width),
            )
            for value in kernel.signature.outputs
        )
        return BindingSpec(inputs=inputs, outputs=outputs)

    def build_candidate(
        self, kernel: IRKernel, snippets: SnippetPair
    ) -> tuple[WindowPair, VerificationCandidate]:
        spec = self.build_spec(kernel, snippets.guest.arch, snippets.host.arch)
        guest_window = InstructionWindow(
            kernel.id, "guest", snippets.guest.instructions
        )
        host_window = InstructionWindow(kernel.id, "host", snippets.host.instructions)
        pair = WindowPair(
            region_id=kernel.id,
            stage=(guest_window.instruction_count, host_window.instruction_count),
            guest=guest_window,
            host=host_window,
        )

        # Build register role hints from the binding spec.
        register_roles: list[RegisterBindingRole] = []
        for name, guest_reg, host_reg in spec.inputs:
            value_obj = _find_value(kernel.signature.inputs, name)
            register_roles.append(
                RegisterBindingRole(
                    guest=guest_reg,
                    host=host_reg,
                    value_name=name,
                    value_type=value_obj.type if value_obj else "i64",
                )
            )
        for name, guest_reg, host_reg in spec.outputs:
            value_obj = _find_value(kernel.signature.outputs, name)
            register_roles.append(
                RegisterBindingRole(
                    guest=guest_reg,
                    host=host_reg,
                    value_name=name,
                    value_type=value_obj.type if value_obj else "i64",
                )
            )

        # Build memory spec from kernel declarations.
        memory = _build_memory_spec(kernel, spec) if kernel.has_memory else MemorySpec()

        candidate = VerificationCandidate(
            candidate_id=kernel.id,
            guest=_fragment_for_window(guest_window),
            host=_fragment_for_window(host_window),
            input_registers=spec.input_registers,
            output_registers=spec.output_registers,
            clobbers=Clobbers(),
            memory=memory,
            register_roles=tuple(register_roles),
        )
        return pair, candidate


def _argument_register(arch: str, width: int, index: int) -> str:
    registers = _register_table(arch, _AARCH64_ARGS, _X86_64_ARGS).get(width)
    if registers is None:
        raise ValueError(f"unsupported ABI argument width: {arch}:{width}")
    try:
        return registers[index]
    except IndexError as exc:
        raise ValueError("kernel has too many register arguments for MVP ABI") from exc


def _return_register(arch: str, width: int) -> str:
    register = _register_table(arch, _AARCH64_RET, _X86_64_RET).get(width)
    if register is None:
        raise ValueError(f"unsupported ABI return width: {arch}:{width}")
    return register


def _register_table(arch: str, aarch64_table, x86_64_table):
    arch = canonical_arch_name(arch)
    if arch == "aarch64":
        return aarch64_table
    if arch == "x86-64":
        return x86_64_table
    raise ValueError(f"unsupported kernel ABI architecture: {arch}")


def _find_value(values, name: str):
    """Find a ``KernelValue`` by name in a tuple of values."""
    for v in values:
        if v.name == name:
            return v
    return None


def _build_memory_spec(kernel, spec):
    """Construct a ``MemorySpec`` from kernel memory declarations."""
    # Build name → (guest_reg, host_reg) lookup.
    reg_map: dict[str, tuple[str, str]] = {}
    for name, g, h in spec.inputs:
        reg_map[name] = (g, h)

    slots: list[MemorySlot] = []
    bindings: list[MemoryBinding] = []
    accesses: list[MemoryAccessExpectation] = []
    slot_index = 0

    for mem_access in kernel.memory_accesses:
        slot_name = f"mem{slot_index}"
        width_bytes = mem_access.width_bits // 8

        slots.append(MemorySlot(slot_name, width_bytes))

        addr = mem_access.address
        guest_addr = _build_addr_str(addr, reg_map, side="guest")
        host_addr = _build_addr_str(addr, reg_map, side="host")

        access_kind = "read" if mem_access.kind == "load" else "write"
        bindings.append(MemoryBinding(slot_name, guest_addr, host_addr, access_kind))
        accesses.append(MemoryAccessExpectation(slot_name, access_kind, width_bytes))
        slot_index += 1

    return MemorySpec(
        slots=tuple(slots), bindings=tuple(bindings), accesses=tuple(accesses)
    )


def _build_addr_str(addr, reg_map, side: str) -> str:
    """Build an address expression string for *side* from a ``KernelAddressSpec``.

    *side* is ``"guest"`` or ``"host"``.  The register names are looked
    up from *reg_map* which stores ``(guest_reg, host_reg)`` tuples.
    """
    pair = reg_map.get(addr.base, ("x0", "rdi"))
    base_reg = pair[0] if side == "guest" else pair[1]

    if addr.index is None:
        return base_reg

    index_pair = reg_map.get(addr.index, ("x1", "rsi"))
    index_reg = index_pair[0] if side == "guest" else index_pair[1]

    if addr.scale == 1:
        return f"{base_reg} + {index_reg}"
    return f"{base_reg} + {index_reg} * {addr.scale}"


def _fragment_for_window(window: InstructionWindow) -> CodeFragment:
    return CodeFragment(
        arch=window.instructions[0].arch,
        address=window.address,
        code_hex=window.code_hex,
        instruction_count=window.instruction_count,
    )
