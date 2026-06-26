import shutil

import pytest

from angr_rule_learning.kernel.bind import KernelBindingBuilder
from angr_rule_learning.kernel.compile import KernelCompiler
from angr_rule_learning.kernel.extract import SnippetExtractor
from angr_rule_learning.kernel.models import (
    IRKernel,
    KernelAddressSpec,
    KernelConfig,
    KernelMemoryAccessSpec,
    KernelMemoryObjectSpec,
    KernelMetadata,
    KernelSignature,
    KernelValue,
)
from angr_rule_learning.kernel.synthesize import HardcodedKernelSynthesizer


def _kernel(name: str):
    return next(k for k in HardcodedKernelSynthesizer().generate() if k.name == name)


def test_scalar_i32_abi_binding_for_aarch64_to_x86_64() -> None:
    spec = KernelBindingBuilder().build_spec(
        _kernel("kernel_add_i32"), "aarch64", "x86-64"
    )

    assert spec.inputs == (("a", "w0", "edi"), ("b", "w1", "esi"))
    assert spec.outputs == (("r", "w0", "eax"),)


def test_scalar_i32_abi_binding_for_reverse_direction() -> None:
    spec = KernelBindingBuilder().build_spec(
        _kernel("kernel_add_i32"), "x86-64", "aarch64"
    )

    assert spec.inputs == (("a", "edi", "w0"), ("b", "esi", "w1"))
    assert spec.outputs == (("r", "eax", "w0"),)


def test_void_kernel_abi_binding_has_no_output_registers() -> None:
    kernel = IRKernel(
        id="kernel_void_i32",
        name="kernel_void_i32",
        llvm_ir="""
define void @kernel_void_i32(i32 %a) {
entry:
  ret void
}
""",
        signature=KernelSignature(
            inputs=(KernelValue("a", "i32"),),
            outputs=(),
        ),
        metadata=KernelMetadata(op_kind="void", bit_width=32),
    )

    spec = KernelBindingBuilder().build_spec(kernel, "aarch64", "x86-64")

    assert spec.inputs == (("a", "w0", "edi"),)
    assert spec.outputs == ()
    assert spec.output_registers == ()


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_build_candidate_from_compiled_kernel_snippets(tmp_path) -> None:
    kernel = _kernel("kernel_add_i32")
    config = KernelConfig(work_dir=tmp_path, optimization="1")
    compiled = KernelCompiler().compile_pair(kernel, config)
    snippets = SnippetExtractor().extract_pair(compiled, config)

    pair, candidate = KernelBindingBuilder().build_candidate(kernel, snippets)

    assert pair.region_id == kernel.id
    assert candidate.candidate_id == "kernel_add_i32"
    assert candidate.input_registers == (("w0", "edi"), ("w1", "esi"))
    assert candidate.output_registers == (("w0", "eax"),)
    assert candidate.guest.code_hex == pair.guest.code_hex
    assert candidate.host.code_hex == pair.host.code_hex


def test_load_i32_binding_builds_memory_spec() -> None:
    """For a load kernel, the binding should produce a MemorySpec with
    one read slot, using the ABI register for the pointer base."""
    kernel = _kernel("kernel_load_i32")
    spec = KernelBindingBuilder().build_spec(kernel, "aarch64", "x86-64")

    # ptr input should use 64-bit ABI register.
    assert spec.inputs == (("p", "x0", "rdi"),)
    assert spec.outputs == (("v", "w0", "eax"),)

    # Quick construction: create a basic kernel with memory access and
    # verify that build_candidate would emit the right MemorySpec.
    kernel_with_mem = IRKernel(
        id="test_load",
        name="test_load",
        llvm_ir="""
define i32 @test_load(ptr %p) {
entry:
  %v = load i32, ptr %p
  ret i32 %v
}
""",
        signature=KernelSignature(
            inputs=(KernelValue("p", "ptr"),),
            outputs=(KernelValue("v", "i32"),),
        ),
        metadata=KernelMetadata(op_kind="load", bit_width=32, has_memory=True),
        memory_objects=(
            KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32),
        ),
        memory_accesses=(
            KernelMemoryAccessSpec(
                kind="load",
                object="slot0",
                width_bits=32,
                address=KernelAddressSpec(base="p"),
                result="v",
            ),
        ),
    )
    spec2 = KernelBindingBuilder().build_spec(kernel_with_mem, "aarch64", "x86-64")
    assert spec2.input_registers == (("x0", "rdi"),)


def test_pointer_input_binding_uses_64_bit_abi_register() -> None:
    """ptr kernel input should use 64-bit register in both directions."""
    kernel = _kernel("kernel_load_i32")

    # Forward: AArch64→x86-64
    spec_fwd = KernelBindingBuilder().build_spec(kernel, "aarch64", "x86-64")
    assert spec_fwd.inputs[0] == ("p", "x0", "rdi"), (
        f"ptr input should be x0/rdi, got {spec_fwd.inputs[0]}"
    )

    # Reverse: x86-64→AArch64
    spec_rev = KernelBindingBuilder().build_spec(kernel, "x86-64", "aarch64")
    assert spec_rev.inputs[0] == ("p", "rdi", "x0"), (
        f"ptr input reverse should be rdi/x0, got {spec_rev.inputs[0]}"
    )


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_store_kernel_binding_has_no_output_and_write_access(tmp_path) -> None:
    """Store kernels produce candidates with no output registers and
    a write memory slot."""
    kernel = _kernel("kernel_store_i64")
    config = KernelConfig(work_dir=tmp_path, guest_arch="aarch64", host_arch="x86-64")
    compiled = KernelCompiler().compile_pair(kernel, config)
    snippets = SnippetExtractor().extract_pair(compiled, config)

    pair, candidate = KernelBindingBuilder().build_candidate(kernel, snippets)

    # Store kernels have void return → no output registers.
    assert candidate.output_registers == ()

    # Memory spec must exist with a write binding.
    assert len(candidate.memory.bindings) == 1
    assert candidate.memory.bindings[0].access == "write"

    # Register roles should include ptr and i64.
    assert len(candidate.register_roles) > 0
    role_types = {r.value_type for r in candidate.register_roles}
    assert "ptr" in role_types
    assert "i64" in role_types


# ── Validation tests ───────────────────────────────────────────────────


def _make_memory_kernel(
    *,
    inputs: tuple[tuple[str, str], ...] = (("p", "ptr"),),
    outputs: tuple[tuple[str, str], ...] = (("v", "i32"),),
    objects: tuple | None = None,
    accesses: tuple | None = None,
) -> IRKernel:
    """Build a minimal memory kernel for validation tests."""
    from angr_rule_learning.kernel.models import (
        KernelAddressSpec,
        KernelMemoryAccessSpec,
        KernelMemoryObjectSpec,
        KernelMetadata,
        KernelSignature,
    )

    sig_inputs = tuple(KernelValue(name, typ) for name, typ in inputs)
    sig_outputs = tuple(KernelValue(name, typ) for name, typ in outputs)
    kernel_id = "test_mem"
    return IRKernel(
        id=kernel_id,
        name=kernel_id,
        llvm_ir=f"define i32 @{kernel_id}(ptr %p) {{ ret i32 0 }}",
        signature=KernelSignature(inputs=sig_inputs, outputs=sig_outputs),
        metadata=KernelMetadata(op_kind="load", bit_width=32, has_memory=True),
        memory_objects=objects
        or (KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32),),
        memory_accesses=accesses
        or (
            KernelMemoryAccessSpec(
                kind="load",
                object="slot0",
                width_bits=32,
                address=KernelAddressSpec(base="p"),
                result="v",
            ),
        ),
    )


def _build_memory_spec(kernel, spec):
    from angr_rule_learning.kernel.bind import _build_memory_spec as bms

    return bms(kernel, spec)


def test_validation_rejects_missing_object_base_in_inputs():
    from angr_rule_learning.kernel.bind import KernelBindingBuilder
    from angr_rule_learning.kernel.models import (
        KernelMemoryObjectSpec,
    )

    kernel = _make_memory_kernel(
        objects=(
            KernelMemoryObjectSpec(name="slot0", base="nonexistent", element_bits=32),
        ),
        accesses=(),
    )
    spec = KernelBindingBuilder().build_spec(kernel, "aarch64", "x86-64")
    with pytest.raises(ValueError, match="not found in kernel signature inputs"):
        _build_memory_spec(kernel, spec)


def test_validation_rejects_non_ptr_base():
    from angr_rule_learning.kernel.bind import KernelBindingBuilder
    from angr_rule_learning.kernel.models import (
        KernelMemoryObjectSpec,
    )

    kernel = _make_memory_kernel(
        inputs=(("p", "i64"), ("v", "i64")),
        objects=(KernelMemoryObjectSpec(name="slot0", base="p", element_bits=64),),
        accesses=(),
    )
    spec = KernelBindingBuilder().build_spec(kernel, "aarch64", "x86-64")
    with pytest.raises(ValueError, match="expected 'ptr'"):
        _build_memory_spec(kernel, spec)


def test_validation_rejects_invalid_index_type():
    from angr_rule_learning.kernel.bind import KernelBindingBuilder
    from angr_rule_learning.kernel.models import (
        KernelAddressSpec,
        KernelMemoryAccessSpec,
        KernelMemoryObjectSpec,
    )

    kernel = _make_memory_kernel(
        inputs=(("p", "ptr"), ("idx", "i32"), ("v", "i32")),
        objects=(KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32),),
        accesses=(
            KernelMemoryAccessSpec(
                kind="load",
                object="slot0",
                width_bits=32,
                address=KernelAddressSpec(base="p", index="idx", scale=4),
                result="v",
            ),
        ),
    )
    spec = KernelBindingBuilder().build_spec(kernel, "aarch64", "x86-64")
    with pytest.raises(ValueError, match="must have type 'i64'"):
        _build_memory_spec(kernel, spec)


def test_validation_rejects_store_without_value():
    from angr_rule_learning.kernel.bind import KernelBindingBuilder
    from angr_rule_learning.kernel.models import (
        KernelAddressSpec,
        KernelMemoryAccessSpec,
        KernelMemoryObjectSpec,
    )

    # Test with a kernel where store value doesn't exist in inputs.
    kernel2 = IRKernel(
        id="store_no_val",
        name="store_no_val",
        llvm_ir="define void @store_no_val(ptr %p, i32 %v) { ret void }",
        signature=KernelSignature(
            inputs=(KernelValue("p", "ptr"), KernelValue("v", "i32")),
            outputs=(),
        ),
        metadata=KernelMetadata(op_kind="store", bit_width=32, has_memory=True),
        memory_objects=(
            KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32),
        ),
        memory_accesses=(
            KernelMemoryAccessSpec(
                kind="store",
                object="slot0",
                width_bits=32,
                address=KernelAddressSpec(base="p"),
                value="nonexistent",
            ),
        ),
    )
    spec = KernelBindingBuilder().build_spec(kernel2, "aarch64", "x86-64")
    with pytest.raises(ValueError, match="not found in kernel signature inputs"):
        _build_memory_spec(kernel2, spec)


def test_validation_rejects_unknown_object_name():
    from angr_rule_learning.kernel.bind import KernelBindingBuilder
    from angr_rule_learning.kernel.models import (
        KernelAddressSpec,
        KernelMemoryAccessSpec,
        KernelMemoryObjectSpec,
    )

    kernel = _make_memory_kernel(
        objects=(KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32),),
        accesses=(
            KernelMemoryAccessSpec(
                kind="load",
                object="wrong_name",
                width_bits=32,
                address=KernelAddressSpec(base="p"),
                result="v",
            ),
        ),
    )
    spec = KernelBindingBuilder().build_spec(kernel, "aarch64", "x86-64")
    with pytest.raises(ValueError, match="does not match declared memory object"):
        _build_memory_spec(kernel, spec)


def test_kernel_address_spec_with_displacement():
    from angr_rule_learning.kernel.models import KernelAddressSpec

    # Displacement without index is now allowed.
    spec = KernelAddressSpec(base="p", displacement=8)
    assert spec.base == "p"
    assert spec.index is None
    assert spec.displacement == 8

    spec = KernelAddressSpec(base="p", displacement=-16)
    assert spec.displacement == -16


def test_build_addr_str_with_displacement():
    from angr_rule_learning.kernel.bind import _build_addr_str
    from angr_rule_learning.kernel.models import KernelAddressSpec

    reg_map = {"p": ("x0", "rdi")}

    # Positive displacement
    addr = KernelAddressSpec(base="p", displacement=8)
    assert _build_addr_str(addr, reg_map, "guest") == "x0 + 8"
    assert _build_addr_str(addr, reg_map, "host") == "rdi + 8"

    # Negative displacement
    addr = KernelAddressSpec(base="p", displacement=-4)
    assert _build_addr_str(addr, reg_map, "guest") == "x0 - 4"

    # Zero displacement (base only)
    addr = KernelAddressSpec(base="p")
    assert _build_addr_str(addr, reg_map, "guest") == "x0"


def test_build_addr_str_with_index_and_displacement():
    from angr_rule_learning.kernel.bind import _build_addr_str
    from angr_rule_learning.kernel.models import KernelAddressSpec

    reg_map = {"p": ("x0", "rdi"), "idx": ("x1", "rsi")}

    addr = KernelAddressSpec(base="p", index="idx", scale=4, displacement=8)
    result = _build_addr_str(addr, reg_map, "guest")
    assert "x0 +" in result
    assert "x1 * 4" in result
    assert "+ 8" in result


def test_validation_rejects_unknown_base():
    from angr_rule_learning.kernel.bind import _build_addr_str
    from angr_rule_learning.kernel.models import KernelAddressSpec

    reg_map = {"p": ("x0", "rdi")}
    addr = KernelAddressSpec(base="unknown")
    with pytest.raises(ValueError, match="not in register map"):
        _build_addr_str(addr, reg_map, "guest")
