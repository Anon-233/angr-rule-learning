from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

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

_PTR_TYPES = {"ptr": 64}


@dataclass(frozen=True)
class KernelValue:
    name: str
    type: str

    def __post_init__(self) -> None:
        name = self.name.strip()
        value_type = self.type.strip().lower()
        if not name:
            raise ValueError("kernel value name must not be empty")
        if value_type not in _INTEGER_TYPES and value_type not in _PTR_TYPES:
            raise ValueError(f"unsupported kernel value type: {self.type}")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "type", value_type)

    @property
    def bit_width(self) -> int:
        if self.type in _INTEGER_TYPES:
            return _INTEGER_TYPES[self.type]
        return _PTR_TYPES[self.type]

    @property
    def is_ptr(self) -> bool:
        return self.type in _PTR_TYPES


@dataclass(frozen=True)
class KernelAddressSpec:
    """Describes a base+index address expression in kernel semantics.

    *base* is a kernel-level name (e.g. ``"p"``).
    *index* is a kernel-level name (e.g. ``"idx"``) or ``None``.
    *scale* is the byte scale (e.g. ``4`` for ``i32``, ``8`` for ``i64``).
    *displacement* is a constant byte offset (default ``0``).
    """

    base: str
    index: str | None = None
    scale: int = 1
    displacement: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "base", self.base.strip())
        if self.index is not None:
            object.__setattr__(self, "index", self.index.strip())
        if self.scale not in {1, 2, 4, 8}:
            raise ValueError("kernel address scale must be 1, 2, 4, or 8")
        if self.index is None and self.displacement != 0:
            raise ValueError("kernel address displacement requires index")


@dataclass(frozen=True)
class KernelMemoryObjectSpec:
    """Describes a single memory object that a kernel reads or writes.

    *name* is the object identifier (e.g. ``"slot0"``).
    *base* is the kernel-level pointer name (e.g. ``"p"``).
    *element_bits* is the access element width in bits (e.g. 32 for i32).
    *alias_class* is an optional grouping hint (default ``"slot0"``).
    """

    name: str
    base: str
    element_bits: int
    alias_class: str = "slot0"

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "base", self.base.strip())
        object.__setattr__(self, "alias_class", self.alias_class.strip())
        if not self.name:
            raise ValueError("memory object name must not be empty")
        if not self.base:
            raise ValueError("memory object base must not be empty")
        if self.element_bits <= 0:
            raise ValueError("memory object element width must be positive")


@dataclass(frozen=True)
class KernelMemoryAccessSpec:
    """Describes a single memory access in a kernel.

    *kind* is ``"load"`` or ``"store"``.
    *object* references a ``KernelMemoryObjectSpec.name``.
    *width_bits* is the access width in bits.
    *address* is a ``KernelAddressSpec``.
    *result* is a kernel output name (for loads).
    *value* is a kernel input name (for stores).
    """

    kind: Literal["load", "store"]
    object: str
    width_bits: int
    address: KernelAddressSpec
    result: str | None = None
    value: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", self.kind.strip().lower())
        object.__setattr__(self, "object", self.object.strip())
        if self.kind not in {"load", "store"}:
            raise ValueError("memory access kind must be 'load' or 'store'")
        if self.kind == "load" and self.result is None:
            raise ValueError("load must specify a result")
        if self.kind == "store" and self.value is None:
            raise ValueError("store must specify a value")
        if self.width_bits <= 0:
            raise ValueError("memory access width must be positive")


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
    memory_objects: tuple[KernelMemoryObjectSpec, ...] = field(default_factory=tuple)
    memory_accesses: tuple[KernelMemoryAccessSpec, ...] = field(default_factory=tuple)

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
        object.__setattr__(self, "memory_objects", tuple(self.memory_objects))
        object.__setattr__(self, "memory_accesses", tuple(self.memory_accesses))

    @property
    def has_memory(self) -> bool:
        return bool(self.memory_objects) or bool(self.memory_accesses)


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
