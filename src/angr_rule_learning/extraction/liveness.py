from __future__ import annotations

import re


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
