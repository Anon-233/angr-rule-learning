import pytest

from angr_rule_learning.kernel.catalog import (
    generate_scalar_schema_kernels,
    generate_scalar_schemas,
)
from angr_rule_learning.kernel.models import (
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


def test_materializes_typed_multi_instruction_schema() -> None:
    value_type = "i32"
    schema = KernelSchema(
        id="kernel_add_xor_i32",
        name="kernel_add_xor_i32",
        signature=KernelSignature(
            inputs=(
                KernelValue("a", value_type),
                KernelValue("b", value_type),
                KernelValue("c", value_type),
            ),
            outputs=(KernelValue("r", value_type),),
        ),
        instructions=(
            KernelInstruction(
                result=KernelValue("sum", value_type),
                opcode="add",
                operands=(KernelValueRef("a"), KernelValueRef("b")),
            ),
            KernelInstruction(
                result=KernelValue("r", value_type),
                opcode="xor",
                operands=(KernelValueRef("sum"), KernelValueRef("c")),
            ),
        ),
        return_value="r",
        metadata=KernelMetadata(op_kind="add_xor", bit_width=32),
    )

    kernel = materialize_kernel(schema)

    assert kernel.signature == schema.signature
    assert "define i32 @kernel_add_xor_i32(i32 %a, i32 %b, i32 %c)" in kernel.llvm_ir
    assert "  %sum = add i32 %a, %b" in kernel.llvm_ir
    assert "  %r = xor i32 %sum, %c" in kernel.llvm_ir
    assert "  ret i32 %r" in kernel.llvm_ir


def test_schema_rejects_forward_value_reference() -> None:
    with pytest.raises(ValueError, match="unknown or forward value reference: later"):
        KernelSchema(
            id="bad",
            name="bad",
            signature=KernelSignature(
                inputs=(KernelValue("a", "i32"),),
                outputs=(KernelValue("r", "i32"),),
            ),
            instructions=(
                KernelInstruction(
                    result=KernelValue("r", "i32"),
                    opcode="add",
                    operands=(KernelValueRef("a"), KernelValueRef("later")),
                ),
            ),
            return_value="r",
            metadata=KernelMetadata(op_kind="bad", bit_width=32),
        )


def test_schema_rejects_operand_type_mismatch() -> None:
    with pytest.raises(ValueError, match="operand type mismatch"):
        KernelSchema(
            id="bad_width",
            name="bad_width",
            signature=KernelSignature(
                inputs=(KernelValue("a", "i32"), KernelValue("b", "i64")),
                outputs=(KernelValue("r", "i32"),),
            ),
            instructions=(
                KernelInstruction(
                    result=KernelValue("r", "i32"),
                    opcode="add",
                    operands=(KernelValueRef("a"), KernelValueRef("b")),
                ),
            ),
            return_value="r",
            metadata=KernelMetadata(op_kind="bad", bit_width=32),
        )


def test_schema_rejects_input_outside_return_dependency_graph() -> None:
    with pytest.raises(ValueError, match="kernel schema contains unused inputs: b"):
        KernelSchema(
            id="unused_input",
            name="unused_input",
            signature=KernelSignature(
                inputs=(KernelValue("a", "i32"), KernelValue("b", "i32")),
                outputs=(KernelValue("r", "i32"),),
            ),
            instructions=(
                KernelInstruction(
                    result=KernelValue("r", "i32"),
                    opcode="add",
                    operands=(KernelValueRef("a"), KernelIntConstant(1)),
                ),
            ),
            return_value="r",
            metadata=KernelMetadata(op_kind="unused_input", bit_width=32),
        )


def test_schema_rejects_unsupported_opcode() -> None:
    with pytest.raises(ValueError, match="unsupported scalar schema opcode: fadd"):
        KernelInstruction(
            result=KernelValue("r", "i32"),
            opcode="fadd",
            operands=(KernelValueRef("a"), KernelIntConstant(1)),
        )


def test_scalar_catalog_generates_existing_kernel_families_in_order() -> None:
    schemas = generate_scalar_schemas(32)
    kernels = generate_scalar_schema_kernels(32)

    assert len(schemas) == len(kernels)
    assert all(isinstance(schema, KernelSchema) for schema in schemas)
    assert [schema.id for schema in schemas] == [kernel.id for kernel in kernels]
    assert len(kernels) == 28
    assert [kernel.name for kernel in kernels[:6]] == [
        "kernel_add_i32",
        "kernel_sub_i32",
        "kernel_and_i32",
        "kernel_or_i32",
        "kernel_xor_i32",
        "kernel_mul_i32",
    ]
    assert {kernel.name for kernel in kernels} >= {
        "kernel_shl_i32",
        "kernel_udiv_i32",
        "kernel_add_const_i32",
        "kernel_xor_not_i32",
        "kernel_mul_add_i32",
        "kernel_shift_add_i32",
    }


def test_scalar_catalog_materializes_width_dependent_constants() -> None:
    kernels = {kernel.name: kernel for kernel in generate_scalar_schema_kernels(64)}

    assert "  %count = and i64 %b, 63" in kernels["kernel_shl_i64"].llvm_ir
    assert "  %r = add i64 %a, 13" in kernels["kernel_add_const_i64"].llvm_ir
    assert "  %r = and i64 %a, 65535" in kernels["kernel_and_const_i64"].llvm_ir
    assert "  %r = xor i64 %a, -1" in kernels["kernel_xor_not_i64"].llvm_ir
