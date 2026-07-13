"""Text parser for the serialized Rule AST language."""

from __future__ import annotations

import re

from angr_rule_learning.rules.ast import (
    BitSliceOp,
    ExtOp,
    GuestRegViewOp,
    ImmOp,
    Instruction,
    LabelOp,
    LitOp,
    MemoryOperand,
    MetaOp,
    Operand,
    ReadWriteOp,
    RegOp,
    RegViewOp,
    TmpOp,
)


_X86_MEMORY_RE = re.compile(
    r"^(?:(?P<size>byte|word|dword|qword)\s+ptr\s+)?(?P<addr>\[.+\])$",
    re.IGNORECASE,
)


def parse_instruction(line: str, *, arch: str | None = None) -> Instruction:
    tokens = line.strip().split(maxsplit=1)
    if not tokens:
        raise ValueError("instruction text must not be empty")
    mnemonic = tokens[0]
    operands = parse_operands(tokens[1] if len(tokens) > 1 else "", arch=arch)
    return Instruction(mnemonic=mnemonic, operands=tuple(operands))


def parse_operands(text: str, *, arch: str | None = None) -> list[Operand]:
    if not text:
        return []
    parts = split_operands(text)
    result = [parse_operand(part.strip(), arch=arch) for part in parts]
    from angr_rule_learning.arch.rule_memory import combine_rule_memory_operands

    return combine_rule_memory_operands(result)


def split_operands(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth < 0:
                raise ValueError(f"unbalanced operand delimiters: {text!r}")
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if depth != 0:
        raise ValueError(f"unbalanced operand delimiters: {text!r}")
    if current:
        parts.append("".join(current))
    return parts


def parse_operand(text: str, *, arch: str | None = None) -> Operand:
    text = text.strip()
    if not text:
        raise ValueError("operand text must not be empty")

    memory = _parse_memory_operand(text, syntax_hint=_memory_syntax_for_arch(arch))
    if memory is not None:
        return memory

    match = re.fullmatch(r"(#?)label(\d+)", text)
    if match:
        return LabelOp(id=int(match.group(2)), aarch64_hash=bool(match.group(1)))

    match = re.fullmatch(r"(i\d+|f\d+|v\d+)_tmp(\d+)", text)
    if match:
        prefix = match.group(1)
        return TmpOp(prefix=prefix, bits=int(prefix[1:]), id=int(match.group(2)))

    match = re.fullmatch(r"(#?)(-?)\$\{.*\}", text)
    if match:
        derived_text = text[len(match.group(1)) + len(match.group(2)) :]
        return ImmOp(
            id=0,
            derived=derived_text,
            aarch64_hash=bool(match.group(1)),
            neg=bool(match.group(2)),
        )

    match = re.fullmatch(r"(#?)(-?)imm(\d+)", text)
    if match:
        return ImmOp(
            id=int(match.group(3)),
            aarch64_hash=bool(match.group(1)),
            neg=bool(match.group(2)),
        )

    match = re.fullmatch(r"lo(\d+)\((guest|host)\.([A-Za-z][A-Za-z0-9]*)\)", text)
    if match:
        return GuestRegViewOp(
            scope=match.group(2).lower(),
            register=match.group(3).lower(),
            bits=int(match.group(1)),
        )

    match = re.fullmatch(r"rw\((.*)\)", text)
    if match:
        parts = split_operands(match.group(1))
        if len(parts) != 2:
            raise ValueError(f"read/write operand requires two roles: {text!r}")
        read = parse_operand(parts[0])
        write = parse_operand(parts[1])
        if not isinstance(write, (RegOp, TmpOp)):
            raise ValueError(f"read/write destination is not assignable: {text!r}")
        return ReadWriteOp(read=read, write=write)

    match = re.fullmatch(r"(zext|sext)(\d+)\((.+)\)", text)
    if match:
        return ExtOp(
            kind=match.group(1),
            bits=int(match.group(2)),
            value=parse_operand(match.group(3)),
        )

    match = re.fullmatch(r"lo(\d+)\((.+)\)", text)
    if match:
        return BitSliceOp(base=parse_operand(match.group(2)), bits=int(match.group(1)))

    match = re.fullmatch(r"reg(\d+)\((.+)\)", text)
    if match:
        base = parse_operand(match.group(2))
        if isinstance(base, (RegOp, TmpOp)):
            return RegViewOp(base=base, view_bits=int(match.group(1)))

    try:
        return parse_placeholder(text)
    except ValueError:
        return LitOp(value=text)


def parse_placeholder(
    placeholder: str,
) -> RegOp | TmpOp | RegViewOp | BitSliceOp | ExtOp | ReadWriteOp:
    match = re.fullmatch(r"rw\((.*)\)", placeholder)
    if match:
        parsed = parse_operand(placeholder)
        if isinstance(parsed, ReadWriteOp):
            return parsed
        raise ValueError(f"invalid read/write placeholder: {placeholder!r}")
    match = re.fullmatch(r"reg(\d+)\((.+)\)", placeholder)
    if match:
        base = parse_placeholder(match.group(2))
        if isinstance(base, (RegOp, TmpOp)):
            return RegViewOp(base=base, view_bits=int(match.group(1)))
        raise ValueError(f"invalid register view base: {placeholder!r}")
    match = re.fullmatch(r"(zext|sext)(\d+)\((.+)\)", placeholder)
    if match:
        return ExtOp(
            kind=match.group(1),
            bits=int(match.group(2)),
            value=parse_operand(match.group(3)),
        )
    match = re.fullmatch(r"lo(\d+)\((.+)\)", placeholder)
    if match:
        return BitSliceOp(base=parse_operand(match.group(2)), bits=int(match.group(1)))
    match = re.fullmatch(r"(ptr\d+)_reg(\d+)", placeholder)
    if match:
        prefix = match.group(1)
        return RegOp(prefix=prefix, bits=int(prefix[3:]), id=int(match.group(2)))
    match = re.fullmatch(r"(i\d+)_reg(\d+)", placeholder)
    if match:
        return RegOp(
            prefix=match.group(1),
            bits=int(match.group(1)[1:]),
            id=int(match.group(2)),
        )
    match = re.fullmatch(r"(sp|fp)(\d+)", placeholder)
    if match:
        return RegOp(prefix=match.group(1), bits=int(match.group(2)), id=0)
    match = re.fullmatch(r"(i\d+|f\d+|v\d+)_tmp(\d+)", placeholder)
    if match:
        prefix = match.group(1)
        return TmpOp(prefix=prefix, bits=int(prefix[1:]), id=int(match.group(2)))
    raise ValueError(f"unknown placeholder format: {placeholder!r}")


def parse_instruction_sequence(
    lines: tuple[str, ...], *, arch: str | None = None
) -> tuple[Instruction, ...]:
    result: list[Instruction] = []
    pending_meta: list[MetaOp] = []
    for line in lines:
        parsed = parse_instruction(line, arch=arch)
        mnemonic = parsed.mnemonic.lower()
        if mnemonic == "save":
            pending_meta.append(MetaOp("save", parsed.operands))
            continue
        if mnemonic == "restore":
            if pending_meta:
                raise ValueError("restore cannot appear before pending save target")
            if not result:
                raise ValueError("restore requires a preceding instruction")
            previous = result[-1]
            result[-1] = Instruction(
                mnemonic=previous.mnemonic,
                operands=previous.operands,
                meta=previous.meta,
                post_meta=previous.post_meta + (MetaOp("restore", parsed.operands),),
            )
            continue
        result.append(
            Instruction(
                mnemonic=parsed.mnemonic,
                operands=parsed.operands,
                meta=tuple(pending_meta),
                post_meta=parsed.post_meta,
            )
        )
        pending_meta.clear()
    if pending_meta:
        raise ValueError("save requires a following instruction")
    return tuple(result)


def _memory_syntax_for_arch(arch: str | None) -> str | None:
    if arch is None:
        return None
    from angr_rule_learning.arch.rule_memory import rule_memory_syntax

    return rule_memory_syntax(arch)


def _parse_memory_operand(
    text: str, *, syntax_hint: str | None = None
) -> MemoryOperand | None:
    from angr_rule_learning.arch.rule_memory import parse_rule_memory

    bracket_text = text[:-1] if text.endswith("]!") else text
    syntax = syntax_hint
    if syntax is None and bracket_text.startswith("[") and bracket_text.endswith("]"):
        syntax = "aarch64" if "," in bracket_text else "x86-64"
    if syntax is None and _X86_MEMORY_RE.fullmatch(text) is not None:
        syntax = "x86-64"
    if syntax is None:
        return None
    return parse_rule_memory(text, syntax, parse_operand, split_operands)
