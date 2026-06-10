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
        try:
            bit = AARCH64_NZCV_BITS[name]
        except KeyError as exc:
            raise ValueError(f"unsupported flag: {flag}") from exc
        nzcv = state.regs.flags
        return nzcv[bit:bit]
    try:
        bit = X86_FLAG_BITS[normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported flag: {flag}") from exc
    eflags = state.regs.eflags
    return eflags[bit:bit]
