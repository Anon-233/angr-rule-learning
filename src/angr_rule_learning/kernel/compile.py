from __future__ import annotations

from collections.abc import Callable
import subprocess

from angr_rule_learning.arch.registry import clang_target
from angr_rule_learning.kernel.models import (
    CompiledKernel,
    CompiledKernelPair,
    IRKernel,
    KernelConfig,
)


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


class KernelCompiler:
    def __init__(self, runner: Runner = _run_command) -> None:
        self._runner = runner

    def compile_pair(
        self, kernel: IRKernel, config: KernelConfig
    ) -> CompiledKernelPair:
        return CompiledKernelPair(
            guest=self.compile(kernel, config, config.guest_arch, "guest"),
            host=self.compile(kernel, config, config.host_arch, "host"),
        )

    def compile(
        self,
        kernel: IRKernel,
        config: KernelConfig,
        arch: str,
        side: str,
    ) -> CompiledKernel:
        kernel_dir = config.work_dir / kernel.id / side
        kernel_dir.mkdir(parents=True, exist_ok=True)
        ir_path = kernel_dir / f"{kernel.name}.ll"
        object_path = kernel_dir / f"{kernel.name}.o"
        ir_path.write_text(kernel.llvm_ir, encoding="utf-8")
        command = [
            config.clang,
            "-target",
            clang_target(arch),
            "-x",
            "ir",
            f"-O{config.optimization}",
            "-c",
            str(ir_path),
            "-o",
            str(object_path),
        ]
        result = self._runner(command)
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "clang failed"
            raise RuntimeError(detail)
        compile_log = "\n".join(
            part for part in (result.stdout.strip(), result.stderr.strip()) if part
        )
        return CompiledKernel(
            kernel=kernel,
            arch=arch,
            ir_path=ir_path,
            object_path=object_path,
            function_name=kernel.name,
            command=tuple(command),
            compile_log=compile_log,
        )
