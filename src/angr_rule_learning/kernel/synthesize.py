from __future__ import annotations

from angr_rule_learning.kernel.models import (
    IRKernel,
    KernelAddressSpec,
    KernelMemoryAccessSpec,
    KernelMemoryObjectSpec,
    KernelMetadata,
    KernelSignature,
    KernelValue,
)


class HardcodedKernelSynthesizer:
    def generate(self) -> tuple[IRKernel, ...]:
        kernels: list[IRKernel] = []
        for bits in (32, 64):
            kernels.extend(
                _binary_integer_kernel(op, bits)
                for op in ("add", "sub", "and", "or", "xor", "mul")
            )
            kernels.extend(
                _shift_integer_kernel(op, bits) for op in ("shl", "lshr", "ashr")
            )
            kernels.extend(_memory_kernels(bits))
            kernels.append(_add_const_kernel(bits))
            kernels.append(_xor_not_kernel(bits))
            kernels.extend(_icmp_integer_kernel(pred, bits) for pred in ("eq", "slt"))
            kernels.append(_select_eq_kernel(bits))
            kernels.extend(
                factory(bits)
                for factory in (
                    _mul_add_kernel,
                    _add_xor_kernel,
                    _and_or_kernel,
                    _shift_add_kernel,
                    _select_add_kernel,
                )
            )
        return tuple(kernels)


def _binary_integer_kernel(op: str, bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_{op}_{value_type}"
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a, {value_type} %b) {{
entry:
  %r = {op} {value_type} %a, %b
  ret {value_type} %r
}}
"""
    return IRKernel(
        id=name,
        name=name,
        llvm_ir=llvm_ir,
        signature=KernelSignature(
            inputs=(KernelValue("a", value_type), KernelValue("b", value_type)),
            outputs=(KernelValue("r", value_type),),
        ),
        metadata=KernelMetadata(op_kind=op, bit_width=bits),
    )


def _shift_integer_kernel(op: str, bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_{op}_{value_type}"
    mask = bits - 1
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a, {value_type} %b) {{
entry:
  %count = and {value_type} %b, {mask}
  %r = {op} {value_type} %a, %count
  ret {value_type} %r
}}
"""
    return IRKernel(
        id=name,
        name=name,
        llvm_ir=llvm_ir,
        signature=KernelSignature(
            inputs=(KernelValue("a", value_type), KernelValue("b", value_type)),
            outputs=(KernelValue("r", value_type),),
        ),
        metadata=KernelMetadata(
            op_kind=op,
            bit_width=bits,
            has_immediate=True,
            notes="shift count is masked to avoid LLVM poison for oversized counts",
        ),
    )


def _add_const_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_add_const_{value_type}"
    constant = 7 if bits == 32 else 13
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a) {{
entry:
  %r = add {value_type} %a, {constant}
  ret {value_type} %r
}}
"""
    return IRKernel(
        id=name,
        name=name,
        llvm_ir=llvm_ir,
        signature=KernelSignature(
            inputs=(KernelValue("a", value_type),),
            outputs=(KernelValue("r", value_type),),
        ),
        metadata=KernelMetadata(
            op_kind="add_const",
            bit_width=bits,
            has_immediate=True,
        ),
    )


def _xor_not_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_xor_not_{value_type}"
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a) {{
entry:
  %r = xor {value_type} %a, -1
  ret {value_type} %r
}}
"""
    return IRKernel(
        id=name,
        name=name,
        llvm_ir=llvm_ir,
        signature=KernelSignature(
            inputs=(KernelValue("a", value_type),),
            outputs=(KernelValue("r", value_type),),
        ),
        metadata=KernelMetadata(
            op_kind="xor_not",
            bit_width=bits,
            has_immediate=True,
        ),
    )


def _icmp_integer_kernel(pred: str, bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_icmp_{pred}_{value_type}"
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a, {value_type} %b) {{
entry:
  %cmp = icmp {pred} {value_type} %a, %b
  %r = zext i1 %cmp to {value_type}
  ret {value_type} %r
}}
"""
    return IRKernel(
        id=name,
        name=name,
        llvm_ir=llvm_ir,
        signature=KernelSignature(
            inputs=(KernelValue("a", value_type), KernelValue("b", value_type)),
            outputs=(KernelValue("r", value_type),),
        ),
        metadata=KernelMetadata(op_kind=f"icmp_{pred}", bit_width=bits),
    )


def _select_eq_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_select_eq_{value_type}"
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a, {value_type} %b) {{
entry:
  %cmp = icmp eq {value_type} %a, %b
  %r = select i1 %cmp, {value_type} %a, {value_type} %b
  ret {value_type} %r
}}
"""
    return IRKernel(
        id=name,
        name=name,
        llvm_ir=llvm_ir,
        signature=KernelSignature(
            inputs=(KernelValue("a", value_type), KernelValue("b", value_type)),
            outputs=(KernelValue("r", value_type),),
        ),
        metadata=KernelMetadata(op_kind="select_eq", bit_width=bits),
    )


def _mul_add_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_mul_add_{value_type}"
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a, {value_type} %b, {value_type} %c) {{
entry:
  %m = mul {value_type} %a, %b
  %r = add {value_type} %m, %c
  ret {value_type} %r
}}
"""
    return _three_input_kernel(name, llvm_ir, "mul_add", bits)


def _add_xor_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_add_xor_{value_type}"
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a, {value_type} %b, {value_type} %c) {{
entry:
  %s = add {value_type} %a, %b
  %r = xor {value_type} %s, %c
  ret {value_type} %r
}}
"""
    return _three_input_kernel(name, llvm_ir, "add_xor", bits)


def _and_or_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_and_or_{value_type}"
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a, {value_type} %b, {value_type} %c) {{
entry:
  %m = and {value_type} %a, %b
  %r = or {value_type} %m, %c
  ret {value_type} %r
}}
"""
    return _three_input_kernel(name, llvm_ir, "and_or", bits)


def _shift_add_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_shift_add_{value_type}"
    mask = bits - 1
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a, {value_type} %b, {value_type} %c) {{
entry:
  %count = and {value_type} %c, {mask}
  %shifted = shl {value_type} %a, %count
  %r = add {value_type} %shifted, %b
  ret {value_type} %r
}}
"""
    return _three_input_kernel(
        name,
        llvm_ir,
        "shift_add",
        bits,
        has_immediate=True,
        notes="shift count is masked to avoid LLVM poison for oversized counts",
    )


def _select_add_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_select_add_{value_type}"
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a, {value_type} %b, {value_type} %c) {{
entry:
  %cmp = icmp eq {value_type} %a, %b
  %sum = add {value_type} %a, %c
  %r = select i1 %cmp, {value_type} %sum, {value_type} %b
  ret {value_type} %r
}}
"""
    return _three_input_kernel(name, llvm_ir, "select_add", bits)


def _memory_kernels(bits: int) -> list[IRKernel]:
    """Return load and store kernels for *bits*-wide element access."""
    value_type = f"i{bits}"
    scale = bits // 8

    def _load(has_idx: bool) -> IRKernel:
        suffix = f"_{value_type}" + ("_idx" if has_idx else "")
        name = f"kernel_load{suffix}"
        idx_param = ", i64 %idx" if has_idx else ""
        idx_gep = (
            f"  %q = getelementptr {value_type}, ptr %p, i64 %idx\n" if has_idx else ""
        )
        idx_args = [KernelValue("idx", "i64")] if has_idx else []
        idx_addr = (
            KernelAddressSpec(base="p", index="idx", scale=scale)
            if has_idx
            else KernelAddressSpec(base="p")
        )
        llvm_ir = (
            f"""
define {value_type} @{name}(ptr %p{idx_param}) {{
entry:
{idx_gep}  %v = load {value_type}, ptr %q
  ret {value_type} %v
}}
"""
            if has_idx
            else f"""
define {value_type} @{name}(ptr %p) {{
entry:
  %v = load {value_type}, ptr %p
  ret {value_type} %v
}}
"""
        )
        return IRKernel(
            id=name,
            name=name,
            llvm_ir=llvm_ir,
            signature=KernelSignature(
                inputs=(KernelValue("p", "ptr"), *idx_args),
                outputs=(KernelValue("v", value_type),),
            ),
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
            memory_accesses=(
                KernelMemoryAccessSpec(
                    kind="load",
                    object="slot0",
                    width_bits=bits,
                    address=idx_addr,
                    result="v",
                ),
            ),
        )

    def _store(has_idx: bool) -> IRKernel:
        suffix = f"_{value_type}" + ("_idx" if has_idx else "")
        name = f"kernel_store{suffix}"
        idx_param = ", i64 %idx" if has_idx else ""
        idx_gep = (
            f"  %q = getelementptr {value_type}, ptr %p, i64 %idx\n" if has_idx else ""
        )
        idx_args = [KernelValue("idx", "i64")] if has_idx else []
        idx_addr = (
            KernelAddressSpec(base="p", index="idx", scale=scale)
            if has_idx
            else KernelAddressSpec(base="p")
        )
        llvm_ir = (
            f"""
define void @{name}(ptr %p{idx_param}, {value_type} %v) {{
entry:
{idx_gep}  store {value_type} %v, ptr %q
  ret void
}}
"""
            if has_idx
            else f"""
define void @{name}(ptr %p, {value_type} %v) {{
entry:
  store {value_type} %v, ptr %p
  ret void
}}
"""
        )
        return IRKernel(
            id=name,
            name=name,
            llvm_ir=llvm_ir,
            signature=KernelSignature(
                inputs=(
                    KernelValue("p", "ptr"),
                    *idx_args,
                    KernelValue("v", value_type),
                ),
                outputs=(),
            ),
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
            memory_accesses=(
                KernelMemoryAccessSpec(
                    kind="store",
                    object="slot0",
                    width_bits=bits,
                    address=idx_addr,
                    value="v",
                ),
            ),
        )

    return [_load(False), _load(True), _store(False), _store(True)]


def _three_input_kernel(
    name: str,
    llvm_ir: str,
    op_kind: str,
    bits: int,
    *,
    has_immediate: bool = False,
    notes: str | None = None,
) -> IRKernel:
    value_type = f"i{bits}"
    return IRKernel(
        id=name,
        name=name,
        llvm_ir=llvm_ir,
        signature=KernelSignature(
            inputs=(
                KernelValue("a", value_type),
                KernelValue("b", value_type),
                KernelValue("c", value_type),
            ),
            outputs=(KernelValue("r", value_type),),
        ),
        metadata=KernelMetadata(
            op_kind=op_kind,
            bit_width=bits,
            has_immediate=has_immediate,
            notes=notes,
        ),
    )
