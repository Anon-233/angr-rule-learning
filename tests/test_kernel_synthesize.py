from angr_rule_learning.kernel.synthesize import HardcodedKernelSynthesizer


def test_builtin_synthesizer_emits_scalar_integer_kernels() -> None:
    kernels = HardcodedKernelSynthesizer().generate()
    names = {kernel.name for kernel in kernels}

    assert {"kernel_add_i32", "kernel_and_i32", "kernel_xor_i32"} <= names


def test_builtin_kernel_ir_is_single_function() -> None:
    kernel = next(
        k for k in HardcodedKernelSynthesizer().generate() if k.name == "kernel_add_i32"
    )

    assert "define i32 @kernel_add_i32(i32 %a, i32 %b)" in kernel.llvm_ir
    assert "ret i32 %r" in kernel.llvm_ir
    assert [value.name for value in kernel.signature.inputs] == ["a", "b"]
    assert [value.name for value in kernel.signature.outputs] == ["r"]
