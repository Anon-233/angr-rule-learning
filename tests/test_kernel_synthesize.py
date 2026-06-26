from angr_rule_learning.kernel.synthesize import HardcodedKernelSynthesizer


def test_builtin_synthesizer_emits_scalar_integer_kernels() -> None:
    kernels = HardcodedKernelSynthesizer().generate()
    names = {kernel.name for kernel in kernels}

    assert {
        "kernel_add_i32",
        "kernel_add_i64",
        "kernel_and_i32",
        "kernel_and_i64",
        "kernel_mul_i32",
        "kernel_mul_i64",
        "kernel_shl_i32",
        "kernel_lshr_i64",
        "kernel_add_const_i32",
        "kernel_xor_not_i64",
        "kernel_icmp_eq_i32",
        "kernel_icmp_slt_i64",
        "kernel_select_eq_i32",
        "kernel_mul_add_i32",
        "kernel_add_xor_i64",
        "kernel_and_or_i32",
        "kernel_shift_add_i64",
        "kernel_select_add_i32",
        "kernel_xor_i32",
        "kernel_xor_i64",
    } <= names
    assert len(kernels) == 38


def test_builtin_kernel_ir_is_single_function() -> None:
    kernel = next(
        k for k in HardcodedKernelSynthesizer().generate() if k.name == "kernel_add_i32"
    )

    assert "define i32 @kernel_add_i32(i32 %a, i32 %b)" in kernel.llvm_ir
    assert "ret i32 %r" in kernel.llvm_ir
    assert [value.name for value in kernel.signature.inputs] == ["a", "b"]
    assert [value.name for value in kernel.signature.outputs] == ["r"]


def test_builtin_i64_kernel_uses_i64_signature() -> None:
    kernel = next(
        k for k in HardcodedKernelSynthesizer().generate() if k.name == "kernel_mul_i64"
    )

    assert "define i64 @kernel_mul_i64(i64 %a, i64 %b)" in kernel.llvm_ir
    assert "  %r = mul i64 %a, %b" in kernel.llvm_ir
    assert [value.type for value in kernel.signature.inputs] == ["i64", "i64"]
    assert [value.type for value in kernel.signature.outputs] == ["i64"]
    assert kernel.metadata.op_kind == "mul"
    assert kernel.metadata.bit_width == 64


def test_builtin_shift_kernel_masks_count_to_keep_ir_defined() -> None:
    kernel = next(
        k for k in HardcodedKernelSynthesizer().generate() if k.name == "kernel_shl_i32"
    )

    assert "  %count = and i32 %b, 31" in kernel.llvm_ir
    assert "  %r = shl i32 %a, %count" in kernel.llvm_ir
    assert kernel.metadata.op_kind == "shl"
    assert kernel.metadata.has_immediate


def test_builtin_compare_kernel_returns_integer_flag() -> None:
    kernel = next(
        k
        for k in HardcodedKernelSynthesizer().generate()
        if k.name == "kernel_icmp_slt_i64"
    )

    assert "  %cmp = icmp slt i64 %a, %b" in kernel.llvm_ir
    assert "  %r = zext i1 %cmp to i64" in kernel.llvm_ir
    assert [value.type for value in kernel.signature.outputs] == ["i64"]
    assert kernel.metadata.op_kind == "icmp_slt"


def test_builtin_select_kernel_exercises_conditional_value_selection() -> None:
    kernel = next(
        k
        for k in HardcodedKernelSynthesizer().generate()
        if k.name == "kernel_select_eq_i32"
    )

    assert "  %cmp = icmp eq i32 %a, %b" in kernel.llvm_ir
    assert "  %r = select i1 %cmp, i32 %a, i32 %b" in kernel.llvm_ir
    assert kernel.metadata.op_kind == "select_eq"


def test_builtin_mul_add_kernel_exercises_common_combined_arithmetic() -> None:
    kernel = next(
        k
        for k in HardcodedKernelSynthesizer().generate()
        if k.name == "kernel_mul_add_i32"
    )

    assert "  %m = mul i32 %a, %b" in kernel.llvm_ir
    assert "  %r = add i32 %m, %c" in kernel.llvm_ir
    assert [value.name for value in kernel.signature.inputs] == ["a", "b", "c"]
    assert kernel.metadata.op_kind == "mul_add"


def test_builtin_shift_add_kernel_combines_masked_shift_and_add() -> None:
    kernel = next(
        k
        for k in HardcodedKernelSynthesizer().generate()
        if k.name == "kernel_shift_add_i64"
    )

    assert "  %count = and i64 %c, 63" in kernel.llvm_ir
    assert "  %shifted = shl i64 %a, %count" in kernel.llvm_ir
    assert "  %r = add i64 %shifted, %b" in kernel.llvm_ir
    assert kernel.metadata.op_kind == "shift_add"
    assert kernel.metadata.has_immediate
