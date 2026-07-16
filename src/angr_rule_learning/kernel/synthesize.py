from __future__ import annotations

from angr_rule_learning.kernel.catalog import generate_scalar_schema_kernels
from angr_rule_learning.kernel.models import (
    IRKernel,
    KernelAddressSpec,
    KernelMemoryObjectSpec,
    KernelMetadata,
    KernelSuite,
    KernelSignature,
    KernelValue,
)
from angr_rule_learning.kernel.schema import (
    KernelCastInstruction,
    KernelIcmpInstruction,
    KernelInstruction,
    KernelLoadInstruction,
    KernelSchema,
    KernelSelectInstruction,
    KernelStoreInstruction,
    KernelValueRef,
    materialize_kernel,
)


class KernelGenerator:
    def generate(self, suite: KernelSuite = "stable") -> tuple[IRKernel, ...]:
        if suite == "stable":
            return tuple(_stable_kernels())
        if suite == "probe":
            return tuple(_probe_kernels())
        if suite == "all":
            return tuple((*_stable_kernels(), *_probe_kernels()))
        raise ValueError(f"unsupported kernel suite: {suite}")


class HardcodedKernelSynthesizer:
    def __init__(self, generator: KernelGenerator | None = None) -> None:
        self._generator = generator or KernelGenerator()

    def generate(self, suite: KernelSuite = "stable") -> tuple[IRKernel, ...]:
        return self._generator.generate(suite)


def _stable_kernels() -> list[IRKernel]:
    kernels: list[IRKernel] = []
    for bits in (32, 64):
        kernels.extend(generate_scalar_schema_kernels(bits, "core"))
        kernels.extend(_memory_kernels(bits))
        kernels.extend(generate_scalar_schema_kernels(bits, "post_memory"))
        kernels.extend(_icmp_integer_kernel(pred, bits) for pred in ("eq", "slt"))
        kernels.append(_select_eq_kernel(bits))
        kernels.extend(generate_scalar_schema_kernels(bits, "composite"))
        kernels.append(_select_add_kernel(bits))
    return kernels


def _probe_kernels() -> list[IRKernel]:
    kernels: list[IRKernel] = []
    for bits in (8, 16):
        kernels.append(_probe_partial_add_kernel(bits))
    kernels.extend(
        (
            _probe_trunc_kernel(),
            _probe_zext_kernel(),
            _probe_sext_kernel(),
            _probe_multi_access_memory_kernel(),
        )
    )
    return kernels


def _icmp_integer_kernel(pred: str, bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_icmp_{pred}_{value_type}"
    return materialize_kernel(
        KernelSchema(
            id=name,
            name=name,
            signature=KernelSignature(
                inputs=(KernelValue("a", value_type), KernelValue("b", value_type)),
                outputs=(KernelValue("r", value_type),),
            ),
            instructions=(
                KernelIcmpInstruction(
                    result=KernelValue("cmp", "i1"),
                    predicate=pred,
                    operands=(KernelValueRef("a"), KernelValueRef("b")),
                ),
                KernelCastInstruction(
                    result=KernelValue("r", value_type),
                    opcode="zext",
                    operand=KernelValueRef("cmp"),
                ),
            ),
            return_value="r",
            metadata=KernelMetadata(op_kind=f"icmp_{pred}", bit_width=bits),
        )
    )


def _select_eq_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_select_eq_{value_type}"
    return materialize_kernel(
        KernelSchema(
            id=name,
            name=name,
            signature=KernelSignature(
                inputs=(KernelValue("a", value_type), KernelValue("b", value_type)),
                outputs=(KernelValue("r", value_type),),
            ),
            instructions=(
                KernelIcmpInstruction(
                    result=KernelValue("cmp", "i1"),
                    predicate="eq",
                    operands=(KernelValueRef("a"), KernelValueRef("b")),
                ),
                KernelSelectInstruction(
                    result=KernelValue("r", value_type),
                    condition=KernelValueRef("cmp"),
                    values=(KernelValueRef("a"), KernelValueRef("b")),
                ),
            ),
            return_value="r",
            metadata=KernelMetadata(op_kind="select_eq", bit_width=bits),
        )
    )


def _select_add_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_select_add_{value_type}"
    return materialize_kernel(
        KernelSchema(
            id=name,
            name=name,
            signature=KernelSignature(
                inputs=(
                    KernelValue("a", value_type),
                    KernelValue("b", value_type),
                    KernelValue("c", value_type),
                ),
                outputs=(KernelValue("r", value_type),),
            ),
            instructions=(
                KernelIcmpInstruction(
                    result=KernelValue("cmp", "i1"),
                    predicate="eq",
                    operands=(KernelValueRef("a"), KernelValueRef("b")),
                ),
                KernelInstruction(
                    result=KernelValue("sum", value_type),
                    opcode="add",
                    operands=(KernelValueRef("a"), KernelValueRef("c")),
                ),
                KernelSelectInstruction(
                    result=KernelValue("r", value_type),
                    condition=KernelValueRef("cmp"),
                    values=(KernelValueRef("sum"), KernelValueRef("b")),
                ),
            ),
            return_value="r",
            metadata=KernelMetadata(op_kind="select_add", bit_width=bits),
        )
    )


def _memory_kernels(bits: int) -> list[IRKernel]:
    """Return load and store kernels for *bits*-wide element access."""
    value_type = f"i{bits}"
    scale = bits // 8

    def _addr(mode: str) -> KernelAddressSpec:
        match mode:
            case "base":
                return KernelAddressSpec(base="p")
            case "idx":
                return KernelAddressSpec(base="p", index="idx", scale=scale)
            case "disp":
                return KernelAddressSpec(base="p", displacement=scale)
            case "prev":
                return KernelAddressSpec(base="p", displacement=-scale)
            case "idx_disp":
                return KernelAddressSpec(
                    base="p",
                    index="idx",
                    scale=scale,
                    displacement=scale,
                )
        raise ValueError(f"unknown memory kernel address mode: {mode}")

    def _suffix(mode: str) -> str:
        return f"_{value_type}" + ("" if mode == "base" else f"_{mode}")

    def _index_args(mode: str) -> list[KernelValue]:
        return [KernelValue("idx", "i64")] if "idx" in mode else []

    def _load(mode: str) -> IRKernel:
        name = f"kernel_load{_suffix(mode)}"
        idx_args = _index_args(mode)
        return materialize_kernel(
            KernelSchema(
                id=name,
                name=name,
                signature=KernelSignature(
                    inputs=(KernelValue("p", "ptr"), *idx_args),
                    outputs=(KernelValue("v", value_type),),
                ),
                instructions=(
                    KernelLoadInstruction(
                        result=KernelValue("v", value_type),
                        object="slot0",
                        address=_addr(mode),
                    ),
                ),
                return_value="v",
                metadata=KernelMetadata(
                    op_kind="load",
                    bit_width=bits,
                    has_memory=True,
                ),
                memory_objects=(
                    KernelMemoryObjectSpec(
                        name="slot0",
                        base="p",
                        element_bits=bits,
                    ),
                ),
            )
        )

    def _store(mode: str) -> IRKernel:
        name = f"kernel_store{_suffix(mode)}"
        idx_args = _index_args(mode)
        return materialize_kernel(
            KernelSchema(
                id=name,
                name=name,
                signature=KernelSignature(
                    inputs=(
                        KernelValue("p", "ptr"),
                        *idx_args,
                        KernelValue("v", value_type),
                    ),
                    outputs=(),
                ),
                instructions=(
                    KernelStoreInstruction(
                        value=KernelValueRef("v"),
                        object="slot0",
                        address=_addr(mode),
                    ),
                ),
                return_value=None,
                metadata=KernelMetadata(
                    op_kind="store",
                    bit_width=bits,
                    has_memory=True,
                ),
                memory_objects=(
                    KernelMemoryObjectSpec(
                        name="slot0",
                        base="p",
                        element_bits=bits,
                    ),
                ),
            )
        )

    modes = ("base", "idx", "disp", "prev", "idx_disp")
    return [kernel for mode in modes for kernel in (_load(mode), _store(mode))]


def _probe_partial_add_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"probe_add_{value_type}"
    return materialize_kernel(
        KernelSchema(
            id=name,
            name=name,
            signature=KernelSignature(
                inputs=(KernelValue("a", value_type), KernelValue("b", value_type)),
                outputs=(KernelValue("r", value_type),),
            ),
            instructions=(
                KernelInstruction(
                    result=KernelValue("r", value_type),
                    opcode="add",
                    operands=(KernelValueRef("a"), KernelValueRef("b")),
                ),
            ),
            return_value="r",
            metadata=KernelMetadata(
                op_kind="add",
                bit_width=bits,
                suite="probe",
                expected_status="unsupported",
                expected_reason="unsupported ABI argument width",
                tags=("integer", "partial-register"),
            ),
        )
    )


def _probe_trunc_kernel() -> IRKernel:
    name = "probe_trunc_i64_to_i16"
    return materialize_kernel(
        _cast_schema(
            name=name,
            opcode="trunc",
            source_type="i64",
            result_type="i16",
            metadata=KernelMetadata(
                op_kind="trunc",
                bit_width=16,
                suite="probe",
                expected_status="unsupported",
                tags=("cast", "partial-register"),
            ),
        )
    )


def _probe_zext_kernel() -> IRKernel:
    name = "probe_zext_i16_to_i64"
    return materialize_kernel(
        _cast_schema(
            name=name,
            opcode="zext",
            source_type="i16",
            result_type="i64",
            metadata=KernelMetadata(
                op_kind="zext",
                bit_width=64,
                suite="probe",
                expected_status="unsupported",
                tags=("cast", "partial-register"),
            ),
        )
    )


def _probe_sext_kernel() -> IRKernel:
    name = "probe_sext_i16_to_i64"
    return materialize_kernel(
        _cast_schema(
            name=name,
            opcode="sext",
            source_type="i16",
            result_type="i64",
            metadata=KernelMetadata(
                op_kind="sext",
                bit_width=64,
                suite="probe",
                expected_status="unsupported",
                tags=("cast", "partial-register"),
            ),
        )
    )


def _cast_schema(
    *,
    name: str,
    opcode: str,
    source_type: str,
    result_type: str,
    metadata: KernelMetadata,
) -> KernelSchema:
    return KernelSchema(
        id=name,
        name=name,
        signature=KernelSignature(
            inputs=(KernelValue("a", source_type),),
            outputs=(KernelValue("r", result_type),),
        ),
        instructions=(
            KernelCastInstruction(
                result=KernelValue("r", result_type),
                opcode=opcode,
                operand=KernelValueRef("a"),
            ),
        ),
        return_value="r",
        metadata=metadata,
    )


def _probe_multi_access_memory_kernel() -> IRKernel:
    name = "probe_load_store_i32"
    address = KernelAddressSpec(base="p")
    return materialize_kernel(
        KernelSchema(
            id=name,
            name=name,
            signature=KernelSignature(
                inputs=(KernelValue("p", "ptr"), KernelValue("v", "i32")),
                outputs=(),
            ),
            instructions=(
                KernelLoadInstruction(
                    result=KernelValue("old", "i32"),
                    object="slot0",
                    address=address,
                ),
                KernelInstruction(
                    result=KernelValue("r", "i32"),
                    opcode="add",
                    operands=(KernelValueRef("old"), KernelValueRef("v")),
                ),
                KernelStoreInstruction(
                    value=KernelValueRef("r"),
                    object="slot0",
                    address=address,
                ),
            ),
            return_value=None,
            metadata=KernelMetadata(
                op_kind="load_store",
                bit_width=32,
                has_memory=True,
                suite="probe",
                expected_status="unsupported",
                expected_reason="exactly one memory access",
                tags=("memory", "multi-access"),
            ),
            memory_objects=(
                KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32),
            ),
        )
    )
