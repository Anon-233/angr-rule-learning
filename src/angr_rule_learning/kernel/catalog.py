from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from angr_rule_learning.kernel.models import (
    IRKernel,
    KernelMetadata,
    KernelSignature,
    KernelValue,
)
from angr_rule_learning.kernel.schema import (
    KernelInstruction,
    KernelIntConstant,
    KernelSchema,
    KernelValueRef,
    materialize_kernel,
)


ScalarCatalogSection = Literal["core", "post_memory", "composite"]


@dataclass(frozen=True)
class WidthConstant:
    i32: int
    i64: int

    def resolve(self, bits: int) -> int:
        if bits == 32:
            return self.i32
        if bits == 64:
            return self.i64
        raise ValueError(f"unsupported scalar catalog width: {bits}")


TemplateOperand = str | int | WidthConstant


@dataclass(frozen=True)
class ScalarStepSpec:
    result: str
    opcode: str
    operands: tuple[TemplateOperand, TemplateOperand]


@dataclass(frozen=True)
class ScalarKernelSpec:
    stem: str
    inputs: tuple[str, ...]
    steps: tuple[ScalarStepSpec, ...]
    section: ScalarCatalogSection
    op_kind: str | None = None
    has_immediate: bool = False
    notes: str | None = None

    def instantiate(self, bits: int) -> KernelSchema:
        if bits not in {32, 64}:
            raise ValueError(f"unsupported scalar catalog width: {bits}")
        value_type = f"i{bits}"
        name = f"kernel_{self.stem}_{value_type}"
        instructions = tuple(
            KernelInstruction(
                result=KernelValue(step.result, value_type),
                opcode=step.opcode,
                operands=tuple(
                    _instantiate_operand(operand, bits) for operand in step.operands
                ),
            )
            for step in self.steps
        )
        return KernelSchema(
            id=name,
            name=name,
            signature=KernelSignature(
                inputs=tuple(
                    KernelValue(input_name, value_type) for input_name in self.inputs
                ),
                outputs=(KernelValue("r", value_type),),
            ),
            instructions=instructions,
            return_value="r",
            metadata=KernelMetadata(
                op_kind=self.op_kind or self.stem,
                bit_width=bits,
                has_immediate=self.has_immediate,
                notes=self.notes,
            ),
        )


_WIDTH_MASK = WidthConstant(31, 63)
_ADD_CONSTANT = WidthConstant(7, 13)
_AND_CONSTANT = WidthConstant(0xFF, 0xFFFF)
_OR_CONSTANT = WidthConstant(0x10, 0x100)
_XOR_CONSTANT = WidthConstant(0xFF, 0xFFFF)
_MUL_CONSTANT = WidthConstant(3, 5)

_DIVREM_NOTES = (
    "first-stage div/rem kernels use a constant divisor to avoid "
    "symbolic division cost in the verifier"
)
_SHIFT_NOTES = "shift count is masked to avoid LLVM poison for oversized counts"


def _binary(stem: str) -> ScalarKernelSpec:
    return ScalarKernelSpec(
        stem=stem,
        inputs=("a", "b"),
        steps=(ScalarStepSpec("r", stem, ("a", "b")),),
        section="core",
    )


def _constant(
    stem: str,
    opcode: str,
    value: int | WidthConstant,
    *,
    op_kind: str | None = None,
    notes: str | None = None,
) -> ScalarKernelSpec:
    return ScalarKernelSpec(
        stem=stem,
        inputs=("a",),
        steps=(ScalarStepSpec("r", opcode, ("a", value)),),
        section="post_memory",
        op_kind=op_kind,
        has_immediate=True,
        notes=notes,
    )


SCALAR_KERNEL_SPECS: tuple[ScalarKernelSpec, ...] = (
    *(_binary(opcode) for opcode in ("add", "sub", "and", "or", "xor", "mul")),
    *(
        ScalarKernelSpec(
            stem=opcode,
            inputs=("a",),
            steps=(ScalarStepSpec("r", opcode, ("a", 3)),),
            section="core",
            has_immediate=True,
            notes=_DIVREM_NOTES,
        )
        for opcode in ("udiv", "sdiv", "urem", "srem")
    ),
    *(
        ScalarKernelSpec(
            stem=opcode,
            inputs=("a", "b"),
            steps=(
                ScalarStepSpec("count", "and", ("b", _WIDTH_MASK)),
                ScalarStepSpec("r", opcode, ("a", "count")),
            ),
            section="core",
            has_immediate=True,
            notes=_SHIFT_NOTES,
        )
        for opcode in ("shl", "lshr", "ashr")
    ),
    _constant("add_const", "add", _ADD_CONSTANT),
    ScalarKernelSpec(
        stem="neg",
        inputs=("a",),
        steps=(ScalarStepSpec("r", "sub", (0, "a")),),
        section="post_memory",
        has_immediate=True,
    ),
    _constant("sub_const", "sub", _ADD_CONSTANT),
    _constant("and_const", "and", _AND_CONSTANT),
    _constant("or_const", "or", _OR_CONSTANT),
    _constant("xor_const", "xor", _XOR_CONSTANT),
    _constant("mul_const", "mul", _MUL_CONSTANT),
    _constant("shl_const", "shl", 3),
    _constant("lshr_const", "lshr", 3),
    _constant("ashr_const", "ashr", 3),
    _constant("xor_not", "xor", -1),
    ScalarKernelSpec(
        stem="mul_add",
        inputs=("a", "b", "c"),
        steps=(
            ScalarStepSpec("m", "mul", ("a", "b")),
            ScalarStepSpec("r", "add", ("m", "c")),
        ),
        section="composite",
    ),
    ScalarKernelSpec(
        stem="add_xor",
        inputs=("a", "b", "c"),
        steps=(
            ScalarStepSpec("s", "add", ("a", "b")),
            ScalarStepSpec("r", "xor", ("s", "c")),
        ),
        section="composite",
    ),
    ScalarKernelSpec(
        stem="and_or",
        inputs=("a", "b", "c"),
        steps=(
            ScalarStepSpec("m", "and", ("a", "b")),
            ScalarStepSpec("r", "or", ("m", "c")),
        ),
        section="composite",
    ),
    ScalarKernelSpec(
        stem="shift_add",
        inputs=("a", "b", "c"),
        steps=(
            ScalarStepSpec("count", "and", ("c", _WIDTH_MASK)),
            ScalarStepSpec("shifted", "shl", ("a", "count")),
            ScalarStepSpec("r", "add", ("shifted", "b")),
        ),
        section="composite",
        has_immediate=True,
        notes=_SHIFT_NOTES,
    ),
)


def generate_scalar_schemas(
    bits: int, section: ScalarCatalogSection | None = None
) -> tuple[KernelSchema, ...]:
    return tuple(
        spec.instantiate(bits)
        for spec in SCALAR_KERNEL_SPECS
        if section is None or spec.section == section
    )


def generate_scalar_schema_kernels(
    bits: int, section: ScalarCatalogSection | None = None
) -> tuple[IRKernel, ...]:
    return tuple(
        materialize_kernel(schema) for schema in generate_scalar_schemas(bits, section)
    )


def _instantiate_operand(operand: TemplateOperand, bits: int):
    if isinstance(operand, str):
        return KernelValueRef(operand)
    if isinstance(operand, WidthConstant):
        return KernelIntConstant(operand.resolve(bits))
    return KernelIntConstant(operand)
