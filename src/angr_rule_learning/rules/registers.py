from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from archinfo import ArchNotFound, arch_from_id


RegisterKind = Literal["i", "f", "v"]


class RegisterClassError(ValueError):
    """Raised when a register cannot be used for rule generalization."""


class UnsupportedRegisterClass(RegisterClassError):
    """Raised when a known register belongs to a class this stage skips."""


@dataclass(frozen=True)
class RegisterClass:
    kind: RegisterKind
    bits: int

    @property
    def placeholder_prefix(self) -> str:
        return f"{self.kind}{self.bits}"


_ARCHINFO_IDS = {
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "amd64": "amd64",
    "x86_64": "amd64",
    "x86-64": "amd64",
}

_ALLOWED_LITERAL_REGISTERS = {
    "aarch64": frozenset({"xzr", "wzr", "sp", "wsp", "fp"}),
    "x86-64": frozenset({"rsp", "esp", "sp", "rbp", "ebp", "bp"}),
}

_UNSUPPORTED_PREFIXES = {
    "aarch64": ("s", "d", "q", "v"),
    "x86-64": ("xmm", "ymm", "zmm", "st", "mm"),
}

_X86_64_INTEGER_FALLBACKS = {
    "al": 8,
    "ah": 8,
    "bl": 8,
    "bh": 8,
    "cl": 8,
    "ch": 8,
    "dl": 8,
    "dh": 8,
    "spl": 8,
    "bpl": 8,
    "sil": 8,
    "dil": 8,
    "ax": 16,
    "bx": 16,
    "cx": 16,
    "dx": 16,
    "sp": 16,
    "bp": 16,
    "si": 16,
    "di": 16,
    "eax": 32,
    "ebx": 32,
    "ecx": 32,
    "edx": 32,
    "esp": 32,
    "ebp": 32,
    "esi": 32,
    "edi": 32,
    "rax": 64,
    "rbx": 64,
    "rcx": 64,
    "rdx": 64,
    "rsp": 64,
    "rbp": 64,
    "rsi": 64,
    "rdi": 64,
}

for index in range(8, 16):
    _X86_64_INTEGER_FALLBACKS[f"r{index}b"] = 8
    _X86_64_INTEGER_FALLBACKS[f"r{index}w"] = 16
    _X86_64_INTEGER_FALLBACKS[f"r{index}d"] = 32
    _X86_64_INTEGER_FALLBACKS[f"r{index}"] = 64

_AARCH64_INTEGER_PATTERN = re.compile(r"^(?:w|x)(?:[0-9]|[12][0-9]|30)$")


def normalize_register_name(register: str) -> str:
    return register.strip().lower()


def canonical_arch_name(arch: str) -> str:
    normalized = arch.strip().lower()
    if normalized in {"amd64", "x86_64", "x86-64"}:
        return "x86-64"
    if normalized in {"aarch64", "arm64"}:
        return "aarch64"
    return normalized


def _archinfo_id(arch: str) -> str:
    return _ARCHINFO_IDS.get(canonical_arch_name(arch), arch.strip().lower())


_STACK_POINTER_WIDTHS = {
    "aarch64": {"sp": 64, "wsp": 32},
    "x86-64": {"rsp": 64, "esp": 32, "sp": 16},
}


def stack_pointer_placeholder(arch: str, register: str) -> str | None:
    canonical = canonical_arch_name(arch)
    reg = normalize_register_name(register)
    width = _STACK_POINTER_WIDTHS.get(canonical, {}).get(reg)
    if width is None:
        return None
    return f"sp{width}"


def is_allowed_literal_register(arch: str, register: str) -> bool:
    canonical = canonical_arch_name(arch)
    return normalize_register_name(register) in _ALLOWED_LITERAL_REGISTERS.get(
        canonical, frozenset()
    )


def classify_register(arch: str, register: str) -> RegisterClass:
    canonical = canonical_arch_name(arch)
    reg = normalize_register_name(register)
    if is_allowed_literal_register(canonical, reg):
        raise RegisterClassError(f"unknown register class for literal register: {reg}")
    if _is_unsupported_register(canonical, reg):
        raise UnsupportedRegisterClass(f"unsupported register class: {canonical}:{reg}")
    if canonical == "aarch64":
        fallback = _classify_aarch64_integer(reg)
        if fallback is not None:
            return fallback
    if canonical == "x86-64" and reg in _X86_64_INTEGER_FALLBACKS:
        return RegisterClass("i", _X86_64_INTEGER_FALLBACKS[reg])

    width_bytes = _archinfo_register_size(canonical, reg)
    if width_bytes is not None:
        return RegisterClass("i", width_bytes * 8)
    raise RegisterClassError(f"unknown register class: {canonical}:{reg}")


def known_register_tokens(arch: str) -> frozenset[str]:
    canonical = canonical_arch_name(arch)
    tokens: set[str] = set(_ALLOWED_LITERAL_REGISTERS.get(canonical, frozenset()))
    tokens.update(_archinfo_register_names(canonical))
    if canonical == "aarch64":
        tokens.update({"sp", "fp", "lr"})
        tokens.update(f"w{index}" for index in range(31))
        tokens.update(f"x{index}" for index in range(31))
    if canonical == "x86-64":
        tokens.update(_X86_64_INTEGER_FALLBACKS)
    return frozenset(tokens)


def _classify_aarch64_integer(reg: str) -> RegisterClass | None:
    if reg in {"sp", "fp", "lr"}:
        return RegisterClass("i", 64)
    if _AARCH64_INTEGER_PATTERN.match(reg):
        return RegisterClass("i", 32 if reg.startswith("w") else 64)
    return None


def _is_unsupported_register(arch: str, reg: str) -> bool:
    prefixes = _UNSUPPORTED_PREFIXES.get(arch, ())
    if not prefixes:
        return False
    return reg.startswith(prefixes) and any(char.isdigit() for char in reg)


@lru_cache(maxsize=None)
def _archinfo_register_names(arch: str) -> frozenset[str]:
    try:
        return frozenset(arch_from_id(_archinfo_id(arch)).registers)
    except ArchNotFound:
        return frozenset()


@lru_cache(maxsize=None)
def _archinfo_register_size(arch: str, reg: str) -> int | None:
    try:
        register = arch_from_id(_archinfo_id(arch)).registers.get(reg)
    except ArchNotFound:
        return None
    if register is None:
        return None
    return int(register[1])
