from __future__ import annotations

import re

from angr_rule_learning.arch.registry import canonical_arch_name


_X86_64_CLASSIC_FAMILIES = {
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

_X86_64_FLAG_ALIASES = frozenset(
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

_STACK_POINTER_WIDTHS = {
    "aarch64": {"sp": 64, "wsp": 32},
    "x86-64": {"rsp": 64, "esp": 32, "sp": 16},
}

_FRAME_POINTER_WIDTHS = {
    "aarch64": {"x29": 64, "fp": 64},
    "x86-64": {"rbp": 64, "ebp": 32, "bp": 16},
}

_FIXED_ROLE_REGISTERS = {
    "x86-64": frozenset({"cl"}),
}

_FIXED_ROLE_FAMILIES = {
    "x86-64": frozenset({"rcx"}),
}


def normalize_register_name(register: str) -> str:
    return register.strip().lower()


def register_family(arch: str, register: str) -> str:
    canonical = canonical_arch_name(arch)
    reg = normalize_register_name(register)
    if canonical == "aarch64":
        if reg == "nzcv":
            return "nzcv"
        if reg == "fp":
            return "x29"
        if reg == "lr":
            return "x30"
        if reg in {"sp", "wsp"}:
            return "sp"
        match = re.fullmatch(r"[wx](\d+)", reg)
        if match:
            return f"x{match.group(1)}"
        return reg
    if canonical == "x86-64":
        if reg in _X86_64_FLAG_ALIASES:
            return "rflags"
        if reg in _X86_64_CLASSIC_FAMILIES:
            return _X86_64_CLASSIC_FAMILIES[reg]
        match = re.fullmatch(r"r(8|9|10|11|12|13|14|15)(?:b|w|d)?", reg)
        if match:
            return f"r{match.group(1)}"
    return reg


def register_bit_range(arch: str, register: str) -> tuple[int, int] | None:
    canonical = canonical_arch_name(arch)
    reg = normalize_register_name(register)
    if canonical == "aarch64":
        if re.fullmatch(r"w(?:[0-9]|[12][0-9]|30)", reg) or reg == "wsp":
            return (0, 31)
        if re.fullmatch(r"x(?:[0-9]|[12][0-9]|30)", reg) or reg in {
            "sp",
            "fp",
            "lr",
        }:
            return (0, 63)
        return None
    if canonical != "x86-64":
        return None
    if reg in {"ah", "bh", "ch", "dh"}:
        return (8, 15)
    if reg in {"al", "bl", "cl", "dl", "spl", "bpl", "sil", "dil"}:
        return (0, 7)
    if reg in {"ax", "bx", "cx", "dx", "sp", "bp", "si", "di", "ip"}:
        return (0, 15)
    if reg in {
        "eax",
        "ebx",
        "ecx",
        "edx",
        "esp",
        "ebp",
        "esi",
        "edi",
        "eip",
    }:
        return (0, 31)
    if reg in {
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsp",
        "rbp",
        "rsi",
        "rdi",
        "rip",
    }:
        return (0, 63)
    extended = re.fullmatch(r"r(8|9|10|11|12|13|14|15)(b|w|d)?", reg)
    if extended:
        suffix = extended.group(2)
        return {
            "b": (0, 7),
            "w": (0, 15),
            "d": (0, 31),
            None: (0, 63),
        }[suffix]
    return None


def stack_pointer_width(arch: str, register: str | None) -> int | None:
    if register is None:
        return None
    canonical = canonical_arch_name(arch)
    return _STACK_POINTER_WIDTHS.get(canonical, {}).get(
        normalize_register_name(register)
    )


def frame_pointer_width(arch: str, register: str | None) -> int | None:
    if register is None:
        return None
    canonical = canonical_arch_name(arch)
    return _FRAME_POINTER_WIDTHS.get(canonical, {}).get(
        normalize_register_name(register)
    )


def frame_base_width(arch: str, register: str | None) -> int | None:
    return stack_pointer_width(arch, register) or frame_pointer_width(arch, register)


def is_stack_pointer(arch: str, register: str | None) -> bool:
    return stack_pointer_width(arch, register) is not None


def is_frame_pointer(arch: str, register: str | None) -> bool:
    return frame_pointer_width(arch, register) is not None


def is_frame_base(arch: str, register: str | None) -> bool:
    return frame_base_width(arch, register) is not None


def stack_pointer_placeholder(arch: str, register: str | None) -> str | None:
    width = stack_pointer_width(arch, register)
    return None if width is None else f"sp{width}"


def frame_pointer_placeholder(arch: str, register: str | None) -> str | None:
    width = frame_pointer_width(arch, register)
    return None if width is None else f"fp{width}"


def is_fixed_role_register(arch: str, register: str) -> bool:
    canonical = canonical_arch_name(arch)
    return normalize_register_name(register) in _FIXED_ROLE_REGISTERS.get(
        canonical, frozenset()
    )


def fixed_role_family(arch: str, register: str) -> str | None:
    canonical = canonical_arch_name(arch)
    family = register_family(canonical, register)
    if family in _FIXED_ROLE_FAMILIES.get(canonical, frozenset()):
        return family
    return None


def fixed_role_preserve_register(arch: str, register: str) -> str:
    return fixed_role_family(arch, register) or normalize_register_name(register)


def is_compatible_frame_base_pair(
    left_arch: str,
    left_register: str | None,
    right_arch: str,
    right_register: str | None,
) -> bool:
    if left_register is None or right_register is None:
        return False
    left_width = frame_base_width(left_arch, left_register)
    right_width = frame_base_width(right_arch, right_register)
    return left_width is not None and left_width == right_width
