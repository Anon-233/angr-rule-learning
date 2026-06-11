from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class SourceLocation:
    file: str
    line: int
    column: int = 0

    def key(self) -> tuple[str, int]:
        return (self.file, self.line)

    def label(self) -> str:
        return f"{Path(self.file).name}:{self.line}"


@dataclass(frozen=True)
class ExtractedInstruction:
    arch: str
    address: int
    size: int
    code_bytes: bytes
    mnemonic: str
    op_str: str
    function: str
    source: SourceLocation | None
    read_registers: tuple[str, ...] = field(default_factory=tuple)
    write_registers: tuple[str, ...] = field(default_factory=tuple)
    groups: tuple[str, ...] = field(default_factory=tuple)

    @property
    def end_address(self) -> int:
        return self.address + self.size


@dataclass(frozen=True)
class ExtractedFunction:
    arch: str
    name: str
    address: int
    size: int
    instructions: tuple[ExtractedInstruction, ...]


@dataclass(frozen=True)
class BasicBlock:
    block_id: str
    arch: str
    function: str
    instructions: tuple[ExtractedInstruction, ...]

    @property
    def source_key(self) -> tuple[str, tuple[int, ...]] | None:
        locations = [
            inst.source for inst in self.instructions if inst.source is not None
        ]
        if not locations:
            return None
        files = {loc.file for loc in locations}
        if len(files) != 1:
            return None
        return (
            locations[0].file,
            tuple(sorted({loc.line for loc in locations})),
        )


@dataclass(frozen=True)
class AlignmentRegion:
    region_id: str
    function: str
    source_file: str
    source_lines: tuple[int, ...]
    guest_instructions: tuple[ExtractedInstruction, ...]
    host_instructions: tuple[ExtractedInstruction, ...]


@dataclass(frozen=True)
class InstructionWindow:
    region_id: str
    side: str
    instructions: tuple[ExtractedInstruction, ...]

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def code_hex(self) -> str:
        return b"".join(inst.code_bytes for inst in self.instructions).hex()

    @property
    def address(self) -> int:
        return self.instructions[0].address

    @property
    def source_span(self) -> str:
        locations = [
            inst.source for inst in self.instructions if inst.source is not None
        ]
        if not locations:
            return "unknown"
        lines = sorted({loc.line for loc in locations})
        if len(lines) == 1:
            return f"{locations[0].label()}"
        return f"{Path(locations[0].file).name}:{lines[0]}-{lines[-1]}"


@dataclass(frozen=True)
class WindowPair:
    region_id: str
    stage: tuple[int, int]
    guest: InstructionWindow
    host: InstructionWindow
