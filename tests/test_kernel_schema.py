import pytest

from angr_rule_learning.kernel.catalog import (
    generate_scalar_schema_kernels,
    generate_scalar_schemas,
)
from angr_rule_learning.kernel.models import (
    KernelAddressSpec,
    KernelMemoryObjectSpec,
    KernelMetadata,
    KernelSignature,
    KernelValue,
)
from angr_rule_learning.kernel.schema import (
    KernelCastInstruction,
    KernelIcmpInstruction,
    KernelInstruction,
    KernelIntConstant,
    KernelLoadInstruction,
    KernelSchema,
    KernelSelectInstruction,
    KernelStoreInstruction,
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


def test_materializes_compare_cast_and_select_operations() -> None:
    schema = KernelSchema(
        id="kernel_compare_select_i32",
        name="kernel_compare_select_i32",
        signature=KernelSignature(
            inputs=(KernelValue("a", "i32"), KernelValue("b", "i32")),
            outputs=(KernelValue("r", "i64"),),
        ),
        instructions=(
            KernelIcmpInstruction(
                result=KernelValue("cmp", "i1"),
                predicate="eq",
                operands=(KernelValueRef("a"), KernelValueRef("b")),
            ),
            KernelSelectInstruction(
                result=KernelValue("selected", "i32"),
                condition=KernelValueRef("cmp"),
                values=(KernelValueRef("a"), KernelValueRef("b")),
            ),
            KernelCastInstruction(
                result=KernelValue("r", "i64"),
                opcode="zext",
                operand=KernelValueRef("selected"),
            ),
        ),
        return_value="r",
        metadata=KernelMetadata(op_kind="compare_select", bit_width=64),
    )

    kernel = materialize_kernel(schema)

    assert "%cmp = icmp eq i32 %a, %b" in kernel.llvm_ir
    assert "%selected = select i1 %cmp, i32 %a, i32 %b" in kernel.llvm_ir
    assert "%r = zext i32 %selected to i64" in kernel.llvm_ir


def test_schema_rejects_invalid_cast_direction() -> None:
    with pytest.raises(ValueError, match="zext requires a wider result type"):
        KernelSchema(
            id="bad_zext",
            name="bad_zext",
            signature=KernelSignature(
                inputs=(KernelValue("a", "i64"),),
                outputs=(KernelValue("r", "i32"),),
            ),
            instructions=(
                KernelCastInstruction(
                    result=KernelValue("r", "i32"),
                    opcode="zext",
                    operand=KernelValueRef("a"),
                ),
            ),
            return_value="r",
            metadata=KernelMetadata(op_kind="bad", bit_width=32),
        )


def test_materializes_indexed_load_and_derives_memory_access() -> None:
    schema = KernelSchema(
        id="kernel_load_i32_idx",
        name="kernel_load_i32_idx",
        signature=KernelSignature(
            inputs=(KernelValue("p", "ptr"), KernelValue("idx", "i64")),
            outputs=(KernelValue("v", "i32"),),
        ),
        instructions=(
            KernelLoadInstruction(
                result=KernelValue("v", "i32"),
                object="slot0",
                address=KernelAddressSpec(base="p", index="idx", scale=4),
            ),
        ),
        return_value="v",
        metadata=KernelMetadata(op_kind="load", bit_width=32, has_memory=True),
        memory_objects=(
            KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32),
        ),
    )

    kernel = materialize_kernel(schema)

    assert "%q = getelementptr i32, ptr %p, i64 %idx" in kernel.llvm_ir
    assert "%v = load i32, ptr %q" in kernel.llvm_ir
    assert len(kernel.memory_accesses) == 1
    access = kernel.memory_accesses[0]
    assert access.kind == "load"
    assert access.address == KernelAddressSpec(base="p", index="idx", scale=4)
    assert access.result == "v"


def test_materializes_void_store_and_keeps_producer_live() -> None:
    schema = KernelSchema(
        id="kernel_store_sum_i32",
        name="kernel_store_sum_i32",
        signature=KernelSignature(
            inputs=(
                KernelValue("p", "ptr"),
                KernelValue("a", "i32"),
                KernelValue("b", "i32"),
            ),
            outputs=(),
        ),
        instructions=(
            KernelInstruction(
                result=KernelValue("sum", "i32"),
                opcode="add",
                operands=(KernelValueRef("a"), KernelValueRef("b")),
            ),
            KernelStoreInstruction(
                value=KernelValueRef("sum"),
                object="slot0",
                address=KernelAddressSpec(base="p"),
            ),
        ),
        return_value=None,
        metadata=KernelMetadata(op_kind="store", bit_width=32, has_memory=True),
        memory_objects=(
            KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32),
        ),
    )

    kernel = materialize_kernel(schema)

    assert "define void @kernel_store_sum_i32(ptr %p, i32 %a, i32 %b)" in kernel.llvm_ir
    assert "%sum = add i32 %a, %b" in kernel.llvm_ir
    assert "store i32 %sum, ptr %p" in kernel.llvm_ir
    assert kernel.llvm_ir.endswith("  ret void\n}\n")
    assert kernel.signature.outputs == ()
    assert kernel.memory_accesses[0].value == "sum"


def test_schema_rejects_memory_width_mismatch() -> None:
    with pytest.raises(ValueError, match="memory object width does not match load"):
        KernelSchema(
            id="bad_load",
            name="bad_load",
            signature=KernelSignature(
                inputs=(KernelValue("p", "ptr"),),
                outputs=(KernelValue("v", "i64"),),
            ),
            instructions=(
                KernelLoadInstruction(
                    result=KernelValue("v", "i64"),
                    object="slot0",
                    address=KernelAddressSpec(base="p"),
                ),
            ),
            return_value="v",
            metadata=KernelMetadata(op_kind="load", bit_width=64, has_memory=True),
            memory_objects=(
                KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32),
            ),
        )


def test_schema_rejects_memory_metadata_mismatch() -> None:
    with pytest.raises(ValueError, match="has_memory must match"):
        KernelSchema(
            id="bad_memory_metadata",
            name="bad_memory_metadata",
            signature=KernelSignature(
                inputs=(KernelValue("p", "ptr"),),
                outputs=(KernelValue("v", "i32"),),
            ),
            instructions=(
                KernelLoadInstruction(
                    result=KernelValue("v", "i32"),
                    object="slot0",
                    address=KernelAddressSpec(base="p"),
                ),
            ),
            return_value="v",
            metadata=KernelMetadata(op_kind="load", bit_width=32),
            memory_objects=(
                KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32),
            ),
        )


def test_schema_rejects_pointer_store_value() -> None:
    with pytest.raises(ValueError, match="store value must be an integer"):
        KernelSchema(
            id="bad_pointer_store",
            name="bad_pointer_store",
            signature=KernelSignature(
                inputs=(KernelValue("p", "ptr"), KernelValue("q", "ptr")),
                outputs=(),
            ),
            instructions=(
                KernelStoreInstruction(
                    value=KernelValueRef("q"),
                    object="slot0",
                    address=KernelAddressSpec(base="p"),
                ),
            ),
            return_value=None,
            metadata=KernelMetadata(op_kind="store", bit_width=64, has_memory=True),
            memory_objects=(
                KernelMemoryObjectSpec(name="slot0", base="p", element_bits=64),
            ),
        )
