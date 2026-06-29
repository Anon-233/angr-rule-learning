from angr_rule_learning.kernel.synthesize import (
    HardcodedKernelSynthesizer,
    KernelGenerator,
)


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
    assert len(kernels) == 58


def test_kernel_generator_defaults_to_stable_suite() -> None:
    kernels = KernelGenerator().generate()

    assert kernels
    assert {kernel.metadata.suite for kernel in kernels} == {"stable"}
    assert all(kernel.metadata.expected_status == "rule_emitted" for kernel in kernels)


def test_kernel_generator_can_select_probe_and_all_suites() -> None:
    generator = KernelGenerator()
    stable = generator.generate("stable")
    probe = generator.generate("probe")
    all_kernels = generator.generate("all")

    assert stable
    assert probe
    assert {kernel.metadata.suite for kernel in probe} == {"probe"}
    assert len(all_kernels) == len(stable) + len(probe)
    assert {kernel.metadata.suite for kernel in all_kernels} == {"stable", "probe"}


def test_probe_kernels_have_expected_status_and_tags() -> None:
    kernels = KernelGenerator().generate("probe")

    assert any("partial-register" in kernel.metadata.tags for kernel in kernels)
    assert any("cast" in kernel.metadata.tags for kernel in kernels)
    assert any("memory" in kernel.metadata.tags for kernel in kernels)
    assert all(kernel.metadata.expected_status != "rule_emitted" for kernel in kernels)


def test_memory_kernels_are_present() -> None:
    kernels = HardcodedKernelSynthesizer().generate()
    names = {kernel.name for kernel in kernels}

    assert "kernel_load_i32" in names
    assert "kernel_load_i64" in names
    assert "kernel_store_i32" in names
    assert "kernel_store_i64" in names
    assert "kernel_load_i32_idx" in names
    assert "kernel_load_i64_idx" in names
    assert "kernel_load_i32_disp" in names
    assert "kernel_load_i64_disp" in names
    assert "kernel_load_i32_prev" in names
    assert "kernel_load_i64_prev" in names
    assert "kernel_load_i32_idx_disp" in names
    assert "kernel_load_i64_idx_disp" in names
    assert "kernel_store_i32_idx" in names
    assert "kernel_store_i64_idx" in names
    assert "kernel_store_i32_disp" in names
    assert "kernel_store_i64_disp" in names
    assert "kernel_store_i32_prev" in names
    assert "kernel_store_i64_prev" in names
    assert "kernel_store_i32_idx_disp" in names
    assert "kernel_store_i64_idx_disp" in names


def test_load_kernel_has_memory_and_result() -> None:
    kernel = next(
        k
        for k in HardcodedKernelSynthesizer().generate()
        if k.name == "kernel_load_i32"
    )

    assert kernel.metadata.has_memory
    assert len(kernel.memory_objects) == 1
    assert kernel.memory_objects[0].base == "p"
    assert len(kernel.memory_accesses) == 1
    mem = kernel.memory_accesses[0]
    assert mem.kind == "load"
    assert mem.result == "v"
    assert mem.value is None
    assert mem.address.base == "p"
    assert mem.address.index is None


def test_store_kernel_has_memory_no_outputs() -> None:
    kernel = next(
        k
        for k in HardcodedKernelSynthesizer().generate()
        if k.name == "kernel_store_i64"
    )

    assert kernel.metadata.has_memory
    assert kernel.signature.outputs == ()
    assert kernel.memory_accesses[0].kind == "store"
    assert kernel.memory_accesses[0].value == "v"
    assert kernel.memory_accesses[0].result is None


def test_indexed_load_uses_scale_4_for_i32() -> None:
    kernel = next(
        k
        for k in HardcodedKernelSynthesizer().generate()
        if k.name == "kernel_load_i32_idx"
    )

    assert kernel.memory_accesses[0].address.index == "idx"
    assert kernel.memory_accesses[0].address.scale == 4

    # Verify the input signature has ptr and i64
    types = [v.type for v in kernel.signature.inputs]
    assert "ptr" in types
    assert "i64" in types


def test_indexed_load_uses_scale_8_for_i64() -> None:
    kernel = next(
        k
        for k in HardcodedKernelSynthesizer().generate()
        if k.name == "kernel_load_i64_idx"
    )

    assert kernel.memory_accesses[0].address.scale == 8


def test_displacement_load_uses_element_byte_offset() -> None:
    kernel = next(
        k
        for k in HardcodedKernelSynthesizer().generate()
        if k.name == "kernel_load_i32_disp"
    )

    addr = kernel.memory_accesses[0].address
    assert addr.base == "p"
    assert addr.index is None
    assert addr.displacement == 4
    assert "getelementptr i32, ptr %p, i64 1" in kernel.llvm_ir


def test_previous_element_store_uses_negative_displacement() -> None:
    kernel = next(
        k
        for k in HardcodedKernelSynthesizer().generate()
        if k.name == "kernel_store_i64_prev"
    )

    addr = kernel.memory_accesses[0].address
    assert addr.base == "p"
    assert addr.index is None
    assert addr.displacement == -8
    assert "getelementptr i64, ptr %p, i64 -1" in kernel.llvm_ir


def test_indexed_displacement_load_keeps_index_and_byte_offset() -> None:
    kernel = next(
        k
        for k in HardcodedKernelSynthesizer().generate()
        if k.name == "kernel_load_i64_idx_disp"
    )

    addr = kernel.memory_accesses[0].address
    assert addr.base == "p"
    assert addr.index == "idx"
    assert addr.scale == 8
    assert addr.displacement == 8
    assert "%idx_plus = add i64 %idx, 1" in kernel.llvm_ir


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
