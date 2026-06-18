from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _Architecture:
    name: str
    angr_name: str
    clang_target: str | None = None


_ARCHITECTURES = {
    "arm": _Architecture("arm", "ARMEL"),
    "x86": _Architecture("x86", "X86"),
    "aarch64": _Architecture("aarch64", "AARCH64", "aarch64-linux-gnu"),
    "x86-64": _Architecture("x86-64", "AMD64", "x86_64-linux-gnu"),
}

_ALIASES = {
    "arm": "arm",
    "armel": "arm",
    "x86": "x86",
    "i386": "x86",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "amd64": "x86-64",
    "x86_64": "x86-64",
    "x86-64": "x86-64",
}


def canonical_arch_name(arch: str) -> str:
    try:
        return _ALIASES[arch.strip().lower()]
    except KeyError as exc:
        raise ValueError(f"unsupported architecture: {arch}") from exc


def angr_arch_name(arch: str) -> str:
    return _ARCHITECTURES[canonical_arch_name(arch)].angr_name


def clang_target(arch: str) -> str:
    canonical = canonical_arch_name(arch)
    target = _ARCHITECTURES[canonical].clang_target
    if target is None:
        raise ValueError(f"unsupported extraction target: {arch}")
    return target
