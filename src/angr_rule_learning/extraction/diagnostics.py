from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from statistics import mean


def _p95(values: list[int]) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * 0.95))
    return ordered[index]


@dataclass
class MiningDiagnostics:
    functions: int = 0
    regions: int = 0
    regions_skipped: int = 0
    windows_enumerated: int = 0
    windows_emitted: int = 0
    windows_verified: int = 0
    windows_verified_pass: int = 0
    skip_reasons: Counter[str] = field(default_factory=Counter)
    skip_details: dict[str, Counter[str]] = field(default_factory=dict)
    surface_kinds: Counter[str] = field(default_factory=Counter)
    _guest_sizes: list[int] = field(default_factory=list)
    _host_sizes: list[int] = field(default_factory=list)

    def record_function(self) -> None:
        self.functions += 1

    def record_region(self) -> None:
        self.regions += 1

    def record_region_skipped(self, reason: str) -> None:
        self.regions_skipped += 1
        self.skip_reasons[reason] += 1

    def record_window_enumerated(self, guest_size: int, host_size: int) -> None:
        self.windows_enumerated += 1
        self._guest_sizes.append(guest_size)
        self._host_sizes.append(host_size)

    def record_window_emitted(
        self,
        guest_size: int,
        host_size: int,
        surface_kinds: tuple[str, ...],
    ) -> None:
        self.windows_emitted += 1
        for kind in surface_kinds:
            self.surface_kinds[kind] += 1

    def record_window_verified(self, status: str) -> None:
        self.windows_verified += 1
        if status == "pass":
            self.windows_verified_pass += 1

    def record_window_skipped(self, reason: str, detail: str | None = None) -> None:
        self.skip_reasons[reason] += 1
        if detail is not None:
            self.skip_details.setdefault(reason, Counter())[detail] += 1

    def to_json(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "functions": self.functions,
            "regions": self.regions,
            "regions_skipped": self.regions_skipped,
            "windows_enumerated": self.windows_enumerated,
            "windows_emitted": self.windows_emitted,
            "windows_verified": self.windows_verified,
            "windows_verified_pass": self.windows_verified_pass,
            "mean_guest_window_size": (
                mean(self._guest_sizes) if self._guest_sizes else 0
            ),
            "mean_host_window_size": (
                mean(self._host_sizes) if self._host_sizes else 0
            ),
            "p95_guest_window_size": _p95(self._guest_sizes),
            "p95_host_window_size": _p95(self._host_sizes),
            "max_guest_window_size": max(self._guest_sizes, default=0),
            "max_host_window_size": max(self._host_sizes, default=0),
            "skip_reasons": dict(sorted(self.skip_reasons.items())),
            "surface_kinds": dict(sorted(self.surface_kinds.items())),
        }
        if self.skip_details:
            skip_details = {
                reason: dict(sorted(counter.items()))
                for reason, counter in sorted(self.skip_details.items())
                if counter
            }
            if skip_details:
                payload["skip_details"] = skip_details
        return payload
