from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from angr_rule_learning.extraction.models import (
    ExtractedFunction,
    ExtractedInstruction,
)


_X86_64_ALIASES: dict[str, str] = {
    "al": "rax",
    "ah": "rax",
    "ax": "rax",
    "eax": "rax",
    "rax": "rax",
    "bl": "rbx",
    "bh": "rbx",
    "bx": "rbx",
    "ebx": "rbx",
    "rbx": "rbx",
    "cl": "rcx",
    "ch": "rcx",
    "cx": "rcx",
    "ecx": "rcx",
    "rcx": "rcx",
    "dl": "rdx",
    "dh": "rdx",
    "dx": "rdx",
    "edx": "rdx",
    "rdx": "rdx",
    "sil": "rsi",
    "si": "rsi",
    "esi": "rsi",
    "rsi": "rsi",
    "dil": "rdi",
    "di": "rdi",
    "edi": "rdi",
    "rdi": "rdi",
    "bpl": "rbp",
    "bp": "rbp",
    "ebp": "rbp",
    "rbp": "rbp",
    "spl": "rsp",
    "sp": "rsp",
    "esp": "rsp",
    "rsp": "rsp",
    "rip": "rip",
    "eip": "rip",
    "ip": "rip",
}

_X86_FLAG_ALIASES = frozenset(
    {
        "rflags",
        "eflags",
        "flags",
        "cf",
        "pf",
        "af",
        "zf",
        "sf",
        "of",
        "df",
        "if",
    }
)


def family_for_register(arch: str, register: str) -> str:
    normalized_arch = _normalize_arch(arch)
    reg = register.strip().lower()
    if normalized_arch == "aarch64":
        return _aarch64_family(reg)
    if normalized_arch == "x86-64":
        return _x86_64_family(reg)
    return reg


def families_for_registers(arch: str, registers: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for register in registers:
        family = family_for_register(arch, register)
        if family and family not in seen:
            seen.add(family)
            result.append(family)
    return tuple(result)


def is_condition_family(arch: str, family: str) -> bool:
    normalized_arch = _normalize_arch(arch)
    normalized_family = family.strip().lower()
    if normalized_arch == "aarch64":
        return normalized_family == "nzcv"
    if normalized_arch == "x86-64":
        return normalized_family == "rflags"
    return False


def abi_exit_live_out(arch: str) -> frozenset[str]:
    normalized_arch = _normalize_arch(arch)
    if normalized_arch == "aarch64":
        return frozenset(
            {
                "x0",
                "x19",
                "x20",
                "x21",
                "x22",
                "x23",
                "x24",
                "x25",
                "x26",
                "x27",
                "x28",
                "x29",
                "x30",
                "sp",
            }
        )
    if normalized_arch == "x86-64":
        return frozenset({"rax", "rbx", "rbp", "r12", "r13", "r14", "r15", "rsp"})
    return frozenset()


def _normalize_arch(arch: str) -> str:
    normalized = arch.strip().lower()
    if normalized in {"amd64", "x86_64"}:
        return "x86-64"
    if normalized == "arm64":
        return "aarch64"
    return normalized


def _aarch64_family(register: str) -> str:
    if register == "nzcv":
        return "nzcv"
    if register == "fp":
        return "x29"
    if register == "lr":
        return "x30"
    if register in {"sp", "wsp"}:
        return "sp"
    match = re.fullmatch(r"[wx](\d+)", register)
    if match:
        return f"x{match.group(1)}"
    return register


def _x86_64_family(register: str) -> str:
    if register in _X86_FLAG_ALIASES:
        return "rflags"
    if register in _X86_64_ALIASES:
        return _X86_64_ALIASES[register]
    match = re.fullmatch(r"r(8|9|10|11|12|13|14|15)(b|w|d)?", register)
    if match:
        return f"r{match.group(1)}"
    return register


@dataclass(frozen=True)
class InstructionLiveness:
    live_in: frozenset[str]
    live_out: frozenset[str]
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    successor_addresses: tuple[int, ...]
    unsupported: bool = False


class LivenessIndex:
    def __init__(
        self, entries: dict[tuple[str, str, int], InstructionLiveness]
    ) -> None:
        self._entries = dict(entries)

    @classmethod
    def empty(cls) -> "LivenessIndex":
        return cls({})

    def for_instruction(
        self, instruction: ExtractedInstruction
    ) -> InstructionLiveness | None:
        return self._entries.get(
            (instruction.arch, instruction.function, instruction.address)
        )

    def require_instruction(
        self, instruction: ExtractedInstruction
    ) -> InstructionLiveness:
        liveness = self.for_instruction(instruction)
        if liveness is None:
            raise KeyError(
                f"missing liveness for {instruction.arch}:"
                f"{instruction.function}:{instruction.address:x}"
            )
        return liveness

    def has_instruction(self, instruction: ExtractedInstruction) -> bool:
        return self.for_instruction(instruction) is not None


class LivenessAnalyzer:
    def analyze(self, functions: Iterable[ExtractedFunction]) -> LivenessIndex:
        entries: dict[tuple[str, str, int], InstructionLiveness] = {}
        for function in functions:
            entries.update(_analyze_function(function))
        return LivenessIndex(entries)


def _analyze_function(
    function: ExtractedFunction,
) -> dict[tuple[str, str, int], InstructionLiveness]:
    instructions = function.instructions
    if not instructions:
        return {}

    successors = _successor_map(function)
    reads = {
        inst.address: families_for_registers(function.arch, inst.read_registers)
        for inst in instructions
    }
    writes = {
        inst.address: families_for_registers(function.arch, inst.write_registers)
        for inst in instructions
    }
    live_in: dict[int, frozenset[str]] = {
        inst.address: frozenset() for inst in instructions
    }
    live_out: dict[int, frozenset[str]] = {
        inst.address: _exit_seed(function, inst, successors[inst.address])
        for inst in instructions
    }
    by_address = {inst.address: inst for inst in instructions}

    changed = True
    while changed:
        changed = False
        for inst in reversed(instructions):
            succ_live = set(_exit_seed(function, inst, successors[inst.address]))
            for succ in successors[inst.address]:
                if succ in by_address:
                    succ_live.update(live_in[succ])
            next_live_out = frozenset(succ_live)
            next_live_in = frozenset(
                set(reads[inst.address])
                | (set(next_live_out) - set(writes[inst.address]))
            )
            if (
                next_live_out != live_out[inst.address]
                or next_live_in != live_in[inst.address]
            ):
                live_out[inst.address] = next_live_out
                live_in[inst.address] = next_live_in
                changed = True

    return {
        (function.arch, function.name, inst.address): InstructionLiveness(
            live_in=live_in[inst.address],
            live_out=live_out[inst.address],
            reads=reads[inst.address],
            writes=writes[inst.address],
            successor_addresses=successors[inst.address],
            unsupported=_is_unresolved_indirect_control_flow(function.arch, inst),
        )
        for inst in instructions
    }


def _successor_map(
    function: ExtractedFunction,
) -> dict[int, tuple[int, ...]]:
    instructions = function.instructions
    addresses = {inst.address for inst in instructions}
    result: dict[int, tuple[int, ...]] = {}
    for index, inst in enumerate(instructions):
        fallthrough = (
            instructions[index + 1].address if index + 1 < len(instructions) else None
        )
        mnemonic = inst.mnemonic.strip().lower()
        target = _parse_direct_target(inst.op_str, addresses)
        successors: list[int] = []

        if _is_return(function.arch, mnemonic):
            result[inst.address] = ()
            continue
        if _is_conditional_branch(function.arch, mnemonic):
            if target is not None:
                successors.append(target)
            if fallthrough is not None:
                successors.append(fallthrough)
            result[inst.address] = tuple(successors)
            continue
        if _is_direct_unconditional_branch(function.arch, mnemonic):
            result[inst.address] = (target,) if target is not None else ()
            continue
        if fallthrough is not None:
            successors.append(fallthrough)
        result[inst.address] = tuple(successors)
    return result


def _parse_direct_target(op_str: str, valid_addresses: set[int]) -> int | None:
    match = re.search(r"#?(-?0x[0-9a-fA-F]+|-?\d+)", op_str)
    if match is None:
        return None
    value = int(match.group(1), 0)
    return value if value in valid_addresses else None


def _exit_seed(
    function: ExtractedFunction,
    instruction: ExtractedInstruction,
    successors: tuple[int, ...],
) -> frozenset[str]:
    if successors:
        return frozenset()
    if _is_return(function.arch, instruction.mnemonic.strip().lower()):
        return abi_exit_live_out(function.arch)
    return frozenset()


def _is_conditional_branch(arch: str, mnemonic: str) -> bool:
    normalized_arch = _normalize_arch(arch)
    if normalized_arch == "aarch64":
        return mnemonic.startswith(("b.", "cbz", "cbnz", "tbz", "tbnz"))
    if normalized_arch == "x86-64":
        return mnemonic.startswith("j") and mnemonic != "jmp"
    return False


def _is_direct_unconditional_branch(arch: str, mnemonic: str) -> bool:
    normalized_arch = _normalize_arch(arch)
    if normalized_arch == "aarch64":
        return mnemonic == "b"
    if normalized_arch == "x86-64":
        return mnemonic == "jmp"
    return False


def _is_return(arch: str, mnemonic: str) -> bool:
    normalized_arch = _normalize_arch(arch)
    if normalized_arch == "aarch64":
        return mnemonic == "ret"
    if normalized_arch == "x86-64":
        return mnemonic == "ret"
    return False


def _is_unresolved_indirect_control_flow(
    arch: str, instruction: ExtractedInstruction
) -> bool:
    normalized_arch = _normalize_arch(arch)
    mnemonic = instruction.mnemonic.strip().lower()
    if normalized_arch == "aarch64":
        return mnemonic in {"br", "blr", "eret"}
    if normalized_arch == "x86-64":
        return (
            mnemonic == "jmp"
            and _parse_direct_target(instruction.op_str, set()) is None
        )
    return False
