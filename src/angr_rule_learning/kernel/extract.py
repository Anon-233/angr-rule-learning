from __future__ import annotations

from angr_rule_learning.extraction.models import ExtractedInstruction
from angr_rule_learning.extraction.object import ObjectExtractor
from angr_rule_learning.kernel.models import (
    CompiledKernel,
    CompiledKernelPair,
    KernelConfig,
    Snippet,
    SnippetPair,
)


_DROPPED_MNEMONICS = frozenset({"ret", "nop", "endbr64"})


class SnippetExtractor:
    def __init__(self, object_extractor: ObjectExtractor | None = None) -> None:
        self._object_extractor = object_extractor or ObjectExtractor()

    def extract_pair(
        self, compiled: CompiledKernelPair, config: KernelConfig
    ) -> SnippetPair:
        return SnippetPair(
            guest=self.extract(compiled.guest, config.guest_arch),
            host=self.extract(compiled.host, config.host_arch),
        )

    def extract(self, compiled: CompiledKernel, arch: str) -> Snippet:
        functions = self._object_extractor.extract(compiled.object_path, arch)
        function = next(
            (fn for fn in functions if fn.name == compiled.function_name),
            None,
        )
        if function is None:
            available = ", ".join(fn.name for fn in functions) or "<none>"
            raise ValueError(
                f"{compiled.object_path}: function {compiled.function_name!r} "
                f"not found; available: {available}"
            )
        instructions = tuple(
            inst for inst in function.instructions if not _drop_instruction(inst)
        )
        return Snippet(
            kernel=compiled.kernel,
            arch=arch,
            function_name=function.name,
            instructions=instructions,
        )


def _drop_instruction(instruction: ExtractedInstruction) -> bool:
    mnemonic = instruction.mnemonic.strip().lower()
    return mnemonic in _DROPPED_MNEMONICS
