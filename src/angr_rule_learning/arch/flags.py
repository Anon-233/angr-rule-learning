from __future__ import annotations

import claripy


X86_FLAG_BITS = {
    "cf": 0,
    "zf": 6,
    "sf": 7,
    "of": 11,
}

AARCH64_NZCV_BITS = {
    "n": 31,
    "z": 30,
    "c": 29,
    "v": 28,
}


def read_flag(state: object, flag: str) -> claripy.ast.BV:
    normalized = flag.strip().lower()
    if normalized.startswith("nzcv."):
        name = normalized.split(".", 1)[1]
        if name not in AARCH64_NZCV_BITS:
            raise ValueError(f"unsupported flag: {flag}")
        try:
            nzcv = state.regs.flags
        except (AttributeError, KeyError) as exc:
            raise ValueError(f"unsupported flag: {flag}") from exc
        return nzcv[AARCH64_NZCV_BITS[name] : AARCH64_NZCV_BITS[name]]
    if normalized in X86_FLAG_BITS:
        try:
            eflags = state.regs.eflags
        except (AttributeError, KeyError) as exc:
            raise ValueError(f"unsupported flag: {flag}") from exc
        bit = X86_FLAG_BITS[normalized]
        return eflags[bit:bit]
    raise ValueError(f"unsupported flag: {flag}")
