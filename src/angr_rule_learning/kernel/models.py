from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from angr_rule_learning.arch.registry import canonical_arch_name
from angr_rule_learning.extraction.models import ExtractedInstruction
from angr_rule_learning.rules.generalize import GeneratedRule, RuleDiagnostics
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport


_INTEGER_TYPES = {
    "i8": 8,
    "i16": 16,
    "i32": 32,
    "i64": 64,
}


@dataclass(frozen=True)
class KernelValue:
    name: str
    type: str

    def __post_init__(self) -> None:
        name = self.name.strip()
        value_type = self.type.strip().lower()
        if not name:
            raise ValueError("kernel value name must not be empty")
        if value_type not in _INTEGER_TYPES:
            raise ValueError(f"unsupported kernel value type: {self.type}")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "type", value_type)

    @property
    def bit_width(self) -> int:
        return _INTEGER_TYPES[self.type]


@dataclass(frozen=True)
class KernelSignature:
    inputs: tuple[KernelValue, ...] = field(default_factory=tuple)
    outputs: tuple[KernelValue, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "inputs", tuple(self.inputs))
        object.__setattr__(self, "outputs", tuple(self.outputs))


@dataclass(frozen=True)
class KernelMetadata:
    op_kind: str
    bit_width: int
    has_memory: bool = False
    has_branch: bool = False
    has_immediate: bool = False
    notes: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "op_kind", self.op_kind.strip().lower())
        if self.bit_width < 1:
            raise ValueError("kernel bit width must be positive")


@dataclass(frozen=True)
class IRKernel:
    id: str
    name: str
    llvm_ir: str
    signature: KernelSignature
    metadata: KernelMetadata

    def __post_init__(self) -> None:
        kernel_id = self.id.strip()
        name = self.name.strip()
        llvm_ir = self.llvm_ir.strip()
        if not kernel_id:
            raise ValueError("kernel id must not be empty")
        if not name:
            raise ValueError("kernel name must not be empty")
        if not llvm_ir:
            raise ValueError("kernel llvm_ir must not be empty")
        object.__setattr__(self, "id", kernel_id)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "llvm_ir", llvm_ir + "\n")


@dataclass(frozen=True)
class KernelConfig:
    work_dir: Path
    guest_arch: str = "aarch64"
    host_arch: str = "x86-64"
    clang: str = "clang"
    optimization: str = "1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "guest_arch", canonical_arch_name(self.guest_arch))
        object.__setattr__(self, "host_arch", canonical_arch_name(self.host_arch))
        object.__setattr__(self, "clang", self.clang.strip() or "clang")
        object.__setattr__(
            self, "optimization", self.optimization.strip().removeprefix("O")
        )


@dataclass(frozen=True)
class CompiledKernel:
    kernel: IRKernel
    arch: str
    ir_path: Path
    object_path: Path
    function_name: str
    command: tuple[str, ...]
    compile_log: str = ""


@dataclass(frozen=True)
class CompiledKernelPair:
    guest: CompiledKernel
    host: CompiledKernel


@dataclass(frozen=True)
class Snippet:
    kernel: IRKernel
    arch: str
    function_name: str
    instructions: tuple[ExtractedInstruction, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "arch", canonical_arch_name(self.arch))
        object.__setattr__(self, "instructions", tuple(self.instructions))
        if not self.instructions:
            raise ValueError("snippet must contain at least one instruction")


@dataclass(frozen=True)
class SnippetPair:
    guest: Snippet
    host: Snippet


@dataclass(frozen=True)
class BindingSpec:
    inputs: tuple[tuple[str, str, str], ...] = field(default_factory=tuple)
    outputs: tuple[tuple[str, str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "inputs", tuple(self.inputs))
        object.__setattr__(self, "outputs", tuple(self.outputs))

    @property
    def input_registers(self) -> tuple[tuple[str, str], ...]:
        return tuple((guest, host) for _name, guest, host in self.inputs)

    @property
    def output_registers(self) -> tuple[tuple[str, str], ...]:
        return tuple((guest, host) for _name, guest, host in self.outputs)


@dataclass(frozen=True)
class KernelRunRecord:
    kernel_id: str
    kernel_name: str
    status: str
    candidate_id: str | None = None
    rule_id: int | None = None
    reason: str | None = None

    def to_json(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "kernel_id": self.kernel_id,
            "kernel_name": self.kernel_name,
            "status": self.status,
        }
        if self.candidate_id is not None:
            payload["candidate_id"] = self.candidate_id
        if self.rule_id is not None:
            payload["rule_id"] = self.rule_id
        if self.reason is not None:
            payload["reason"] = self.reason
        return payload


@dataclass(frozen=True)
class KernelPipelineResult:
    candidates: tuple[VerificationCandidate, ...]
    reports: tuple[VerificationReport, ...]
    rules: tuple[GeneratedRule, ...]
    rule_diagnostics: RuleDiagnostics
    records: tuple[KernelRunRecord, ...]

    @property
    def diagnostics(self) -> dict[str, object]:
        verified_pass = sum(1 for report in self.reports if report.status == "pass")
        return {
            "kernels_total": len(self.records),
            "candidates_total": len(self.candidates),
            "reports_total": len(self.reports),
            "verified_pass": verified_pass,
            "rules_emitted": len(self.rules),
            "records": [record.to_json() for record in self.records],
            "rule_diagnostics": self.rule_diagnostics.to_json(),
        }
