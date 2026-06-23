from __future__ import annotations

from angr_rule_learning.arch.registry import canonical_arch_name
from angr_rule_learning.extraction.models import InstructionWindow, WindowPair
from angr_rule_learning.kernel.models import BindingSpec, IRKernel, SnippetPair
from angr_rule_learning.verification.candidate import (
    Clobbers,
    CodeFragment,
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
        guest_window = InstructionWindow(kernel.id, "guest", snippets.guest.instructions)
        host_window = InstructionWindow(kernel.id, "host", snippets.host.instructions)
        pair = WindowPair(
            region_id=kernel.id,
            stage=(guest_window.instruction_count, host_window.instruction_count),
            guest=guest_window,
            host=host_window,
        )
        candidate = VerificationCandidate(
            candidate_id=kernel.id,
            guest=_fragment_for_window(guest_window),
            host=_fragment_for_window(host_window),
            input_registers=spec.input_registers,
            output_registers=spec.output_registers,
            clobbers=Clobbers(),
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


def _fragment_for_window(window: InstructionWindow) -> CodeFragment:
    return CodeFragment(
        arch=window.instructions[0].arch,
        address=window.address,
        code_hex=window.code_hex,
        instruction_count=window.instruction_count,
    )
