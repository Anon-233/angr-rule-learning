from __future__ import annotations

import re

from angr_rule_learning.extraction.models import ExtractedInstruction


_HEX_RE = re.compile(r"(?<![A-Za-z0-9_])-?0x[0-9a-fA-F]+")
_DEC_RE = re.compile(r"(?<![A-Za-z0-9_])-?\d+(?![A-Za-z0-9_])")


def instruction_text(instruction: ExtractedInstruction) -> str:
    mnemonic = instruction.mnemonic.strip()
    op_str = instruction.op_str.strip()
    if op_str:
        return f"{mnemonic} {op_str}"
    return mnemonic


def normalize_instruction_text(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text.strip().lower())
    normalized = _HEX_RE.sub("IMM", normalized)
    normalized = _DEC_RE.sub("IMM", normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized
