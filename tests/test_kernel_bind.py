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
