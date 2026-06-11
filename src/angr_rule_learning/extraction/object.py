from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile

from angr_rule_learning.extraction.models import (
    ExtractedFunction,
    ExtractedInstruction,
    SourceLocation,
)


@dataclass(frozen=True)
class RawFunction:
    name: str
    address: int
    size: int
    code_bytes: bytes


@dataclass(frozen=True)
class RawInstruction:
    address: int
    size: int
    code_bytes: bytes
    mnemonic: str
    op_str: str
    read_registers: tuple[str, ...]
    write_registers: tuple[str, ...]
    groups: tuple[str, ...]


class ObjectExtractor:
    def extract(self, path: Path, arch: str) -> tuple[ExtractedFunction, ...]:
        raw_functions = self._read_functions(path, arch)
        if not raw_functions:
            raise ValueError(f"{path}: no functions found")
        line_map = self._read_line_map(path)
        functions: list[ExtractedFunction] = []
        for raw_function in raw_functions:
            raw_instructions = self._disassemble_function(arch, raw_function)
            instructions = tuple(
                ExtractedInstruction(
                    arch=arch,
                    address=raw.address,
                    size=raw.size,
                    code_bytes=raw.code_bytes,
                    mnemonic=raw.mnemonic,
                    op_str=raw.op_str,
                    function=raw_function.name,
                    source=line_map.get(raw.address),
                    read_registers=raw.read_registers,
                    write_registers=raw.write_registers,
                    groups=raw.groups,
                )
                for raw in raw_instructions
            )
            functions.append(
                ExtractedFunction(
                    arch=arch,
                    name=raw_function.name,
                    address=raw_function.address,
                    size=raw_function.size,
                    instructions=instructions,
                )
            )
        return tuple(functions)

    def _read_functions(self, path: Path, arch: str) -> tuple[RawFunction, ...]:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            text = elf.get_section_by_name(".text")
            if text is None:
                return ()
            text_data = text.data()
            text_base = text["sh_addr"]
            symbol_table = elf.get_section_by_name(".symtab")
            if symbol_table is None:
                return ()
            functions: list[RawFunction] = []
            for symbol in symbol_table.iter_symbols():
                if symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                size = int(symbol["st_size"])
                if size <= 0:
                    continue
                address = int(symbol["st_value"])
                offset = address - text_base
                if offset < 0 or offset + size > len(text_data):
                    continue
                functions.append(
                    RawFunction(
                        name=symbol.name,
                        address=address,
                        size=size,
                        code_bytes=text_data[offset : offset + size],
                    )
                )
        return tuple(
            sorted(functions, key=lambda function: (function.address, function.name))
        )

    def _read_line_map(self, path: Path) -> dict[int, SourceLocation]:
        result: dict[int, SourceLocation] = {}
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            if not elf.has_dwarf_info():
                return result
            dwarf = elf.get_dwarf_info()
            for compile_unit in dwarf.iter_CUs():
                line_program = dwarf.line_program_for_CU(compile_unit)
                if line_program is None:
                    continue
                file_entries = line_program["file_entry"]
                include_dirs = [
                    entry.decode("utf-8", errors="replace")
                    for entry in line_program["include_directory"]
                ]
                for entry in line_program.get_entries():
                    state = entry.state
                    if state is None or state.end_sequence or state.file == 0:
                        continue
                    file_entry = file_entries[state.file - 1]
                    file_name = file_entry.name.decode("utf-8", errors="replace")
                    if file_entry.dir_index:
                        directory = include_dirs[file_entry.dir_index - 1]
                        file_name = f"{directory}/{file_name}"
                    result[int(state.address)] = SourceLocation(
                        file=file_name,
                        line=int(state.line),
                        column=int(state.column or 0),
                    )
        return result

    def _disassemble_function(
        self,
        arch: str,
        raw_function: RawFunction,
    ) -> tuple[RawInstruction, ...]:
        disassembler = _capstone_for_arch(arch)
        result: list[RawInstruction] = []
        for insn in disassembler.disasm(raw_function.code_bytes, raw_function.address):
            try:
                reads, writes = insn.regs_access()
            except capstone.CsError:
                reads, writes = ([], [])
            result.append(
                RawInstruction(
                    address=int(insn.address),
                    size=int(insn.size),
                    code_bytes=bytes(insn.bytes),
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    read_registers=tuple(disassembler.reg_name(reg) for reg in reads),
                    write_registers=tuple(disassembler.reg_name(reg) for reg in writes),
                    groups=tuple(
                        disassembler.group_name(group) for group in insn.groups
                    ),
                )
            )
        return tuple(result)


def _capstone_for_arch(arch: str) -> capstone.Cs:
    normalized = arch.strip().lower()
    if normalized == "aarch64":
        disassembler = capstone.Cs(
            capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN
        )
    elif normalized == "x86-64":
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        raise ValueError(f"unsupported extraction architecture: {arch}")
    disassembler.detail = True
    return disassembler
