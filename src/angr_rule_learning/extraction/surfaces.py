from __future__ import annotations

import re

from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.liveness import (
    LivenessIndex,
    WindowSurfaceInferer,
)
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    WindowPair,
)
from angr_rule_learning.verification.candidate import (
    Clobbers,
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)


class SurfaceInferer:
    def __init__(
        self,
        diagnostics: MiningDiagnostics,
        liveness: LivenessIndex,
    ) -> None:
        self._diagnostics = diagnostics
        self._surface_inferer = WindowSurfaceInferer(liveness)

    def infer(self, pair: WindowPair) -> VerificationCandidate | None:
        if _has_unsupported_control_flow(pair.guest) or _has_unsupported_control_flow(
            pair.host
        ):
            self._diagnostics.record_window_skipped("unsupported_control_flow_surface")
            return None

        has_memory = _has_memory_access(pair.guest) or _has_memory_access(pair.host)
        memory_spec, mem_skip = _infer_stack_memory_surface(pair)
        if mem_skip is not None:
            self._diagnostics.record_window_skipped(mem_skip)
            return None
        if has_memory and not memory_spec.slots:
            self._diagnostics.record_window_skipped("unsupported_memory_surface")
            return None

        guest_surface = self._surface_inferer.infer(pair.guest)
        host_surface = self._surface_inferer.infer(pair.host)
        for surface in (guest_surface, host_surface):
            if surface.skip_reason is not None:
                self._diagnostics.record_window_skipped(surface.skip_reason)
                return None

        if len(guest_surface.inputs) != len(host_surface.inputs) or len(
            guest_surface.outputs
        ) != len(host_surface.outputs):
            self._diagnostics.record_window_skipped("ambiguous_register_surface")
            return None
        if guest_surface.kind != host_surface.kind:
            self._diagnostics.record_window_skipped("ambiguous_register_surface")
            return None

        candidate = VerificationCandidate(
            candidate_id=_candidate_id(pair),
            guest=CodeFragment(
                pair.guest.instructions[0].arch,
                pair.guest.address,
                pair.guest.code_hex,
                pair.guest.instruction_count,
            ),
            host=CodeFragment(
                pair.host.instructions[0].arch,
                pair.host.address,
                pair.host.code_hex,
                pair.host.instruction_count,
            ),
            input_registers=tuple(
                zip(guest_surface.inputs, host_surface.inputs, strict=True)
            ),
            output_registers=tuple(
                zip(guest_surface.outputs, host_surface.outputs, strict=True)
            ),
            output_flags=(),
            memory=memory_spec,
            preconditions=(),
            clobbers=Clobbers(),
        )
        self._diagnostics.record_window_emitted(
            pair.guest.instruction_count,
            pair.host.instruction_count,
            ("branch",)
            if guest_surface.kind == "branch" and not guest_surface.outputs
            else ("register",),
        )
        return candidate


def _ordered_unique(values) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def _has_terminal_conditional_branch(pair: WindowPair) -> bool:
    return _is_conditional(pair.guest.instructions[-1]) and _is_conditional(
        pair.host.instructions[-1]
    )


def _is_conditional(instruction: ExtractedInstruction) -> bool:
    mnemonic = instruction.mnemonic.lower()
    if instruction.arch == "aarch64":
        return mnemonic.startswith(("b.", "cbz", "cbnz", "tbz", "tbnz"))
    if instruction.arch == "x86-64":
        return mnemonic.startswith("j") and mnemonic != "jmp"
    return False


def _candidate_id(pair: WindowPair) -> str:
    return (
        f"{pair.region_id}:"
        f"g{pair.guest.instructions[0].address:x}"
        f"-{pair.guest.instructions[-1].end_address:x}:"
        f"h{pair.host.instructions[0].address:x}"
        f"-{pair.host.instructions[-1].end_address:x}"
    )


_STACK_BASE_REGS = {
    "aarch64": {"sp", "wsp", "fp", "x29"},
    "x86-64": {"rsp", "esp", "rbp", "ebp"},
}

_STACK_LOAD_STORE_RE = re.compile(
    r"\[(?P<base>[a-z0-9]+)\s*,\s*#?-?"
    r"(?P<offset>0x[0-9a-fA-F]+|\d+)\]"
)


def _parse_stack_access(op_str: str, arch: str) -> tuple[str, int] | None:
    base_regs = _STACK_BASE_REGS.get(arch, set())
    for m in _STACK_LOAD_STORE_RE.finditer(op_str):
        base = m.group("base").lower()
        if base in base_regs:
            off_text = m.group("offset")
            offset = (
                int(off_text, 16)
                if off_text.startswith(("0x", "0X"))
                else int(off_text)
            )
            if m.group(0).count("-") > m.group(0).count("#"):
                offset = -offset
            return (base, offset)
    for m in re.finditer(
        r"\[(?P<base>[a-z0-9]+)\s*(?P<sign>[-+])\s*"
        r"(?P<offset>0x[0-9a-fA-F]+|\d+)\]",
        op_str,
    ):
        base = m.group("base").lower()
        if base in base_regs:
            off_text = m.group("offset")
            if off_text.startswith("0x") or off_text.startswith("0X"):
                offset = int(off_text, 16)
            else:
                offset = int(off_text)
            if m.group("sign") == "-":
                offset = -offset
            return (base, offset)
    return None


def _infer_stack_memory_surface(
    pair: WindowPair,
) -> tuple[MemorySpec, str | None]:
    guest_accesses = _collect_stack_accesses(pair.guest)
    host_accesses = _collect_stack_accesses(pair.host)

    if not guest_accesses and not host_accesses:
        return MemorySpec(), None

    if not guest_accesses or not host_accesses:
        return MemorySpec(), "unsupported_memory_surface"

    slots: list[MemorySlot] = []
    bindings: list[MemoryBinding] = []
    accesses: list[MemoryAccessExpectation] = []

    count = min(len(guest_accesses), len(host_accesses))
    for idx in range(count):
        g_base, g_offset, g_kind, g_width = guest_accesses[idx]
        h_base, h_offset, h_kind, h_width = host_accesses[idx]
        if g_kind != h_kind:
            continue
        if g_width != h_width:
            continue
        slot_name = f"mem{len(slots)}"
        slots.append(MemorySlot(slot_name, g_width))
        bindings.append(
            MemoryBinding(
                slot_name,
                f"{g_base} + {g_offset}",
                f"{h_base} + {h_offset}",
                g_kind,
            )
        )
        accesses.append(MemoryAccessExpectation(slot_name, g_kind, g_width))

    if not slots:
        return MemorySpec(), "unsupported_memory_surface"

    return (
        MemorySpec(tuple(slots), tuple(bindings), tuple(accesses), ()),
        None,
    )


def _collect_stack_accesses(
    window: InstructionWindow,
) -> list[tuple[str, int, str, int]]:
    result: list[tuple[str, int, str, int]] = []
    for inst in window.instructions:
        parsed = _parse_stack_access(inst.op_str, inst.arch)
        if parsed is None:
            continue
        base, offset = parsed
        mnemonic = inst.mnemonic.lower()
        op_lower = inst.op_str.lower()
        width = _memory_access_width(inst.arch, mnemonic, op_lower)
        if width is None:
            continue
        if inst.arch == "aarch64":
            if mnemonic.startswith(("ldr", "ldp", "ldur")):
                kind = "read"
            elif mnemonic.startswith(("str", "stp", "stur")):
                kind = "write"
            else:
                continue
        elif inst.arch == "x86-64":
            if "[" in op_lower and "mov" in mnemonic:
                if "[" in op_lower.split(",")[-1]:
                    kind = "read"
                else:
                    kind = "write"
            else:
                continue
        else:
            continue
        result.append((base, offset, kind, width))
    return result


def _memory_access_width(arch: str, mnemonic: str, op_str: str) -> int | None:
    if arch == "aarch64":
        if any(r in op_str for r in ("w", "s")):
            return 4
        if any(r in op_str for r in ("x", "d")):
            return 8
        if "b" in op_str.split(",")[0]:
            return 1
        if "h" in op_str.split(",")[0]:
            return 2
        return 4
    if arch == "x86-64":
        if "qword" in op_str:
            return 8
        if "dword" in op_str:
            return 4
        if "word" in op_str:
            return 2
        if "byte" in op_str:
            return 1
        if "ecx" in op_str or "eax" in op_str or "esi" in op_str:
            return 4
        return 4
    return None


def _has_memory_access(window: InstructionWindow) -> bool:
    for inst in window.instructions:
        if inst.arch == "aarch64":
            if inst.mnemonic.lower().startswith(
                ("ldr", "str", "ldp", "stp", "ldur", "stur")
            ):
                return True
            if "[" in inst.op_str or "]" in inst.op_str:
                return True
        elif inst.arch == "x86-64":
            if inst.mnemonic.lower() in ("push", "pop"):
                return True
            op_str_lower = inst.op_str.lower()
            if "[" in op_str_lower or "]" in op_str_lower or "ptr" in op_str_lower:
                return True
    return False


_UNSUPPORTED_CONTROL_FLOW = {
    "aarch64": frozenset(("b", "bl", "br", "blr", "ret")),
    "x86-64": frozenset(("jmp", "ret", "call")),
}


def _has_unsupported_control_flow(window: InstructionWindow) -> bool:
    for inst in window.instructions:
        mnemonic = inst.mnemonic.lower()
        arch = inst.arch
        if arch in _UNSUPPORTED_CONTROL_FLOW:
            if mnemonic in _UNSUPPORTED_CONTROL_FLOW[arch]:
                return True
    return False


_FLAG_REGISTERS = frozenset(("nzcv", "rflags"))


def _has_flag_surface(window: InstructionWindow) -> bool:
    for inst in window.instructions:
        for reg in inst.read_registers:
            if reg in _FLAG_REGISTERS:
                return True
        for reg in inst.write_registers:
            if reg in _FLAG_REGISTERS:
                return True
    return False
