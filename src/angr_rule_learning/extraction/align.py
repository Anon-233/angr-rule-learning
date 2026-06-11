from __future__ import annotations

from collections import defaultdict

from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.models import AlignmentRegion, BasicBlock


class AlignmentRegionBuilder:
    def __init__(self, diagnostics: MiningDiagnostics) -> None:
        self._diagnostics = diagnostics

    def build(
        self,
        guest_blocks: tuple[BasicBlock, ...],
        host_blocks: tuple[BasicBlock, ...],
    ) -> tuple[AlignmentRegion, ...]:
        guest_groups = _group_blocks(guest_blocks)
        host_groups = _group_blocks(host_blocks)
        regions: list[AlignmentRegion] = []
        for key in sorted(set(guest_groups) | set(host_groups)):
            guest_group = guest_groups.get(key, ())
            host_group = host_groups.get(key, ())
            if len(guest_group) != 1 or len(host_group) != 1:
                self._diagnostics.record_region_skipped("ambiguous_alignment_region")
                continue
            function, file_name, lines = key
            ordinal = len([region for region in regions if region.function == function])
            region_id = f"{function}:{file_name}:{_line_label(lines)}:{ordinal}"
            region = AlignmentRegion(
                region_id=region_id,
                function=function,
                source_file=file_name,
                source_lines=lines,
                guest_instructions=guest_group[0].instructions,
                host_instructions=host_group[0].instructions,
            )
            self._diagnostics.record_region()
            regions.append(region)
        return tuple(regions)


def _group_blocks(
    blocks: tuple[BasicBlock, ...],
) -> dict[tuple[str, str, tuple[int, ...]], tuple[BasicBlock, ...]]:
    groups: dict[tuple[str, str, tuple[int, ...]], list[BasicBlock]] = defaultdict(list)
    for block in blocks:
        source_key = block.source_key
        if source_key is None:
            continue
        file_name, lines = source_key
        groups[(block.function, file_name, lines)].append(block)
    return {key: tuple(value) for key, value in groups.items()}


def _line_label(lines: tuple[int, ...]) -> str:
    if len(lines) == 1:
        return str(lines[0])
    return f"{lines[0]}-{lines[-1]}"
