from pathlib import Path

import pytest

from angr_rule_learning.kernel.models import (
    BindingSpec,
    KernelAddressSpec,
    KernelConfig,
    KernelMemoryAccessSpec,
    KernelMemoryObjectSpec,
    KernelSignature,
    KernelValue,
)


def test_kernel_value_accepts_scalar_integer_types() -> None:
    value = KernelValue("a", "i32")

    assert value.name == "a"
    assert value.bit_width == 32
    assert not value.is_ptr


def test_kernel_value_accepts_ptr_type() -> None:
    value = KernelValue("p", "ptr")

    assert value.name == "p"
    assert value.bit_width == 64
    assert value.is_ptr


def test_kernel_value_rejects_unknown_types() -> None:
    with pytest.raises(ValueError, match="unsupported kernel value type"):
        KernelValue("a", "f32")


def test_kernel_config_canonicalizes_architectures(tmp_path: Path) -> None:
    config = KernelConfig(work_dir=tmp_path, guest_arch="arm64", host_arch="amd64")

    assert config.guest_arch == "aarch64"
    assert config.host_arch == "x86-64"


def test_signature_allows_void_output() -> None:
    signature = KernelSignature(inputs=(KernelValue("a", "i32"),), outputs=())

    assert signature.inputs == (KernelValue("a", "i32"),)
    assert signature.outputs == ()


def test_binding_spec_allows_no_register_outputs() -> None:
    spec = BindingSpec(inputs=(("a", "w0", "edi"),), outputs=())

    assert spec.input_registers == (("w0", "edi"),)
    assert spec.output_registers == ()


# ── Memory spec model tests ─────────────────────────────────────────────


def test_kernel_address_spec_accepts_base_only() -> None:
    spec = KernelAddressSpec(base="p")
    assert spec.base == "p"
    assert spec.index is None
    assert spec.scale == 1
    assert spec.displacement == 0


def test_kernel_address_spec_accepts_indexed_address() -> None:
    spec = KernelAddressSpec(base="p", index="idx", scale=4)
    assert spec.base == "p"
    assert spec.index == "idx"
    assert spec.scale == 4
    assert spec.displacement == 0


def test_kernel_memory_object_spec_requires_base() -> None:
    spec = KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32)
    assert spec.name == "slot0"
    assert spec.base == "p"
    assert spec.element_bits == 32


def test_kernel_memory_object_spec_rejects_empty_name() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        KernelMemoryObjectSpec(name="", base="p", element_bits=32)


def test_kernel_memory_access_spec_validates_load_result() -> None:
    addr = KernelAddressSpec(base="p")
    spec = KernelMemoryAccessSpec(
        kind="load", object="slot0", width_bits=32, address=addr, result="v"
    )
    assert spec.kind == "load"
    assert spec.result == "v"
    assert spec.value is None


def test_kernel_memory_access_spec_validates_store_value() -> None:
    addr = KernelAddressSpec(base="p")
    spec = KernelMemoryAccessSpec(
        kind="store", object="slot0", width_bits=32, address=addr, value="v"
    )
    assert spec.kind == "store"
    assert spec.value == "v"
    assert spec.result is None


def test_kernel_memory_access_spec_rejects_load_without_result() -> None:
    addr = KernelAddressSpec(base="p")
    with pytest.raises(ValueError, match="load must specify a result"):
        KernelMemoryAccessSpec(kind="load", object="slot0", width_bits=32, address=addr)


def test_kernel_memory_access_spec_rejects_store_without_value() -> None:
    addr = KernelAddressSpec(base="p")
    with pytest.raises(ValueError, match="store must specify a value"):
        KernelMemoryAccessSpec(
            kind="store", object="slot0", width_bits=32, address=addr
        )


def test_irkernel_reports_has_memory() -> None:
    from angr_rule_learning.kernel.models import (
        IRKernel,
        KernelMetadata,
        KernelSignature,
    )

    no_mem = IRKernel(
        id="no_mem",
        name="no_mem",
        llvm_ir="define void @f() { ret void }",
        signature=KernelSignature(),
        metadata=KernelMetadata(op_kind="test", bit_width=32),
    )
    assert not no_mem.has_memory

    with_mem = IRKernel(
        id="with_mem",
        name="with_mem",
        llvm_ir="define void @f() { ret void }",
        signature=KernelSignature(),
        metadata=KernelMetadata(op_kind="test", bit_width=32, has_memory=True),
        memory_objects=(
            KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32),
        ),
        memory_accesses=(
            KernelMemoryAccessSpec(
                kind="store",
                object="slot0",
                width_bits=32,
                address=KernelAddressSpec(base="p"),
                value="v",
            ),
        ),
    )
    assert with_mem.has_memory
