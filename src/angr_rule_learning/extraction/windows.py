from __future__ import annotations

from dataclasses import dataclass, field

from angr_rule_learning.extraction.config import WindowLimits
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics
from angr_rule_learning.extraction.models import (
    AlignmentRegion,
    InstructionWindow,
    WindowPair,
)


@dataclass
class VerifiedWindowSet:
    _windows_by_region: dict[str, list[WindowPair]] = field(default_factory=dict)

    def add(self, window: WindowPair) -> None:
        self._windows_by_region.setdefault(window.region_id, []).append(window)

    def covers(self, window: WindowPair) -> bool:
        smaller = [
            existing
            for existing in self._windows_by_region.get(window.region_id, [])
            if _window_area(existing) < _window_area(window)
        ]
        guest_target = _address_span(window.guest)
        host_target = _address_span(window.host)
        guest_spans = sorted(_address_span(existing.guest) for existing in smaller)
        host_spans = sorted(_address_span(existing.host) for existing in smaller)
        return _covers_span(guest_target, guest_spans) and _covers_span(
            host_target, host_spans
        )


class WindowMiner:
    def __init__(self, limits: WindowLimits, diagnostics: MiningDiagnostics) -> None:
        self._limits = limits
        self._diagnostics = diagnostics

    def enumerate_region(self, region: AlignmentRegion) -> tuple[WindowPair, ...]:
        result: list[WindowPair] = []
        for stage in self._limits.stage_order():
            guest_size, host_size = stage
            for guest_start in range(
                0, len(region.guest_instructions) - guest_size + 1
            ):
                for host_start in range(
                    0, len(region.host_instructions) - host_size + 1
                ):
                    self._diagnostics.record_window_enumerated(guest_size, host_size)
                    result.append(
                        WindowPair(
                            region_id=region.region_id,
                            stage=stage,
                            guest=InstructionWindow(
                                region_id=region.region_id,
                                side="guest",
                                instructions=region.guest_instructions[
                                    guest_start : guest_start + guest_size
                                ],
                            ),
                            host=InstructionWindow(
                                region_id=region.region_id,
                                side="host",
                                instructions=region.host_instructions[
                                    host_start : host_start + host_size
                                ],
                            ),
                        )
                    )
        return tuple(result)

    def prune_composites(
        self,
        windows: tuple[WindowPair, ...],
        verified: VerifiedWindowSet,
    ) -> tuple[WindowPair, ...]:
        result: list[WindowPair] = []
        for window in windows:
            if verified.covers(window):
                self._diagnostics.record_window_skipped("subsumed_by_smaller_window")
                continue
            result.append(window)
        return tuple(result)


def _window_area(window: WindowPair) -> int:
    return window.guest.instruction_count + window.host.instruction_count


def _address_span(window: InstructionWindow) -> tuple[int, int]:
    return (window.instructions[0].address, window.instructions[-1].end_address)


def _covers_span(target: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    cursor = target[0]
    for start, end in spans:
        if end <= cursor:
            continue
        if start != cursor:
            continue
        cursor = end
        if cursor == target[1]:
            return True
    return False
