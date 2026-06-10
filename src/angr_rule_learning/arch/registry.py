from __future__ import annotations


_ANGR_ARCH_NAMES = {
    "arm": "ARMEL",
    "armel": "ARMEL",
    "x86": "X86",
    "i386": "X86",
    "amd64": "AMD64",
    "x86_64": "AMD64",
    "x86-64": "AMD64",
    "aarch64": "AARCH64",
    "arm64": "AARCH64",
}


def angr_arch_name(arch: str) -> str:
    try:
        return _ANGR_ARCH_NAMES[arch.strip().lower()]
    except KeyError as exc:
        raise ValueError(f"unsupported architecture: {arch}") from exc
