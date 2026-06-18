from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import subprocess

from angr_rule_learning.arch.registry import clang_target
from angr_rule_learning.extraction.config import ExtractionConfig


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class BuildArtifacts:
    guest_object: Path
    host_object: Path
    commands: tuple[tuple[str, ...], ...]


def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


class ClangBuildDriver:
    def __init__(self, runner: Runner = _run_command) -> None:
        self._runner = runner

    def build(self, config: ExtractionConfig) -> BuildArtifacts:
        config.work_dir.mkdir(parents=True, exist_ok=True)
        guest_object = config.work_dir / f"guest-{config.guest_arch}.o"
        host_object = config.work_dir / f"host-{config.host_arch}.o"
        commands = (
            self._command(config, "guest", config.guest_arch, guest_object),
            self._command(config, "host", config.host_arch, host_object),
        )
        for command in commands:
            result = self._runner(command)
            if result.returncode != 0:
                detail = (
                    result.stderr.strip() or result.stdout.strip() or "clang failed"
                )
                raise RuntimeError(detail)
        return BuildArtifacts(
            guest_object=guest_object,
            host_object=host_object,
            commands=tuple(tuple(command) for command in commands),
        )

    def _command(
        self,
        config: ExtractionConfig,
        side: str,
        arch: str,
        output: Path,
    ) -> list[str]:
        target = clang_target(arch)
        return [
            config.compile_options.clang,
            "-target",
            target,
            *config.compile_options.command_flags_for_side(side),
            "-c",
            str(config.source),
            "-o",
            str(output),
        ]
