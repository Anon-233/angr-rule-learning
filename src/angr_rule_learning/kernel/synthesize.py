from __future__ import annotations

from angr_rule_learning.kernel.models import (
    IRKernel,
    KernelAddressSpec,
    KernelMemoryAccessSpec,
    KernelMemoryObjectSpec,
    KernelMetadata,
    KernelSuite,
    KernelSignature,
    KernelValue,
)


class KernelGenerator:
    def generate(self, suite: KernelSuite = "stable") -> tuple[IRKernel, ...]:
        if suite == "stable":
            return tuple(_stable_kernels())
        if suite == "probe":
            return tuple(_probe_kernels())
        if suite == "all":
            return tuple((*_stable_kernels(), *_probe_kernels()))
        raise ValueError(f"unsupported kernel suite: {suite}")


class HardcodedKernelSynthesizer:
    def __init__(self, generator: KernelGenerator | None = None) -> None:
        self._generator = generator or KernelGenerator()

    def generate(self, suite: KernelSuite = "stable") -> tuple[IRKernel, ...]:
        return self._generator.generate(suite)


def _stable_kernels() -> list[IRKernel]:
    kernels: list[IRKernel] = []
    for bits in (32, 64):
        kernels.extend(
            _binary_integer_kernel(op, bits)
            for op in (
                "add",
                "sub",
                "and",
                "or",
                "xor",
                "mul",
            )
        )
        kernels.extend(
            _divrem_const_kernel(op, bits) for op in ("udiv", "sdiv", "urem", "srem")
        )
        kernels.extend(
            _shift_integer_kernel(op, bits) for op in ("shl", "lshr", "ashr")
        )
        kernels.extend(_memory_kernels(bits))
        kernels.append(_add_const_kernel(bits))
        kernels.append(_neg_kernel(bits))
        kernels.extend(
            _const_integer_kernel(op, bits) for op in ("sub", "and", "or", "xor", "mul")
        )
        kernels.extend(_shift_const_kernel(op, bits) for op in ("shl", "lshr", "ashr"))
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
    return kernels


def _probe_kernels() -> list[IRKernel]:
    kernels: list[IRKernel] = []
    for bits in (8, 16):
        kernels.append(_probe_partial_add_kernel(bits))
    kernels.extend(
        (
            _probe_trunc_kernel(),
            _probe_zext_kernel(),
            _probe_sext_kernel(),
            _probe_multi_access_memory_kernel(),
        )
    )
    return kernels


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


def _divrem_const_kernel(op: str, bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_{op}_{value_type}"
    constant = 3
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a) {{
entry:
  %r = {op} {value_type} %a, {constant}
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
            op_kind=op,
            bit_width=bits,
            has_immediate=True,
            notes=(
                "first-stage div/rem kernels use a constant divisor to avoid "
                "symbolic division cost in the verifier"
            ),
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

    def _addr(mode: str) -> KernelAddressSpec:
        match mode:
            case "base":
                return KernelAddressSpec(base="p")
            case "idx":
                return KernelAddressSpec(base="p", index="idx", scale=scale)
            case "disp":
                return KernelAddressSpec(base="p", displacement=scale)
            case "prev":
                return KernelAddressSpec(base="p", displacement=-scale)
            case "idx_disp":
                return KernelAddressSpec(
                    base="p",
                    index="idx",
                    scale=scale,
                    displacement=scale,
                )
        raise ValueError(f"unknown memory kernel address mode: {mode}")

    def _suffix(mode: str) -> str:
        return f"_{value_type}" + ("" if mode == "base" else f"_{mode}")

    def _index_args(mode: str) -> list[KernelValue]:
        return [KernelValue("idx", "i64")] if "idx" in mode else []

    def _llvm_address_setup(mode: str) -> tuple[str, str, str]:
        match mode:
            case "base":
                return "", "", "%p"
            case "idx":
                return (
                    ", i64 %idx",
                    (f"  %q = getelementptr {value_type}, ptr %p, i64 %idx\n"),
                    "%q",
                )
            case "disp":
                return "", (f"  %q = getelementptr {value_type}, ptr %p, i64 1\n"), "%q"
            case "prev":
                return (
                    "",
                    (f"  %q = getelementptr {value_type}, ptr %p, i64 -1\n"),
                    "%q",
                )
            case "idx_disp":
                return (
                    ", i64 %idx",
                    (
                        "  %idx_plus = add i64 %idx, 1\n"
                        f"  %q = getelementptr {value_type}, ptr %p, i64 %idx_plus\n"
                    ),
                    "%q",
                )
        raise ValueError(f"unknown memory kernel address mode: {mode}")

    def _load(mode: str) -> IRKernel:
        name = f"kernel_load{_suffix(mode)}"
        idx_param, addr_setup, addr_value = _llvm_address_setup(mode)
        idx_args = _index_args(mode)
        idx_addr = _addr(mode)
        llvm_ir = f"""
define {value_type} @{name}(ptr %p{idx_param}) {{
entry:
{addr_setup}  %v = load {value_type}, ptr {addr_value}
  ret {value_type} %v
}}
"""
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

    def _store(mode: str) -> IRKernel:
        name = f"kernel_store{_suffix(mode)}"
        idx_param, addr_setup, addr_value = _llvm_address_setup(mode)
        idx_args = _index_args(mode)
        idx_addr = _addr(mode)
        llvm_ir = f"""
define void @{name}(ptr %p{idx_param}, {value_type} %v) {{
entry:
{addr_setup}  store {value_type} %v, ptr {addr_value}
  ret void
}}
"""
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

    modes = ("base", "idx", "disp", "prev", "idx_disp")
    return [kernel for mode in modes for kernel in (_load(mode), _store(mode))]


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


def _neg_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_neg_{value_type}"
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a) {{
entry:
  %r = sub {value_type} 0, %a
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
            op_kind="neg",
            bit_width=bits,
            has_immediate=True,
        ),
    )


def _const_integer_kernel(op: str, bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_{op}_const_{value_type}"
    constant = _constant_for(op, bits)
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a) {{
entry:
  %r = {op} {value_type} %a, {constant}
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
            op_kind=f"{op}_const",
            bit_width=bits,
            has_immediate=True,
        ),
    )


def _shift_const_kernel(op: str, bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"kernel_{op}_const_{value_type}"
    constant = 3
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a) {{
entry:
  %r = {op} {value_type} %a, {constant}
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
            op_kind=f"{op}_const",
            bit_width=bits,
            has_immediate=True,
        ),
    )


def _constant_for(op: str, bits: int) -> int:
    constants = {
        32: {
            "sub": 7,
            "and": 0xFF,
            "or": 0x10,
            "xor": 0xFF,
            "mul": 3,
        },
        64: {
            "sub": 13,
            "and": 0xFFFF,
            "or": 0x100,
            "xor": 0xFFFF,
            "mul": 5,
        },
    }
    try:
        return constants[bits][op]
    except KeyError as exc:
        raise ValueError(f"unsupported const kernel: {op} i{bits}") from exc


def _probe_partial_add_kernel(bits: int) -> IRKernel:
    value_type = f"i{bits}"
    name = f"probe_add_{value_type}"
    llvm_ir = f"""
define {value_type} @{name}({value_type} %a, {value_type} %b) {{
entry:
  %r = add {value_type} %a, %b
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
            op_kind="add",
            bit_width=bits,
            suite="probe",
            expected_status="unsupported",
            expected_reason="unsupported ABI argument width",
            tags=("integer", "partial-register"),
        ),
    )


def _probe_trunc_kernel() -> IRKernel:
    name = "probe_trunc_i64_to_i16"
    llvm_ir = f"""
define i16 @{name}(i64 %a) {{
entry:
  %r = trunc i64 %a to i16
  ret i16 %r
}}
"""
    return IRKernel(
        id=name,
        name=name,
        llvm_ir=llvm_ir,
        signature=KernelSignature(
            inputs=(KernelValue("a", "i64"),),
            outputs=(KernelValue("r", "i16"),),
        ),
        metadata=KernelMetadata(
            op_kind="trunc",
            bit_width=16,
            suite="probe",
            expected_status="unsupported",
            tags=("cast", "partial-register"),
        ),
    )


def _probe_zext_kernel() -> IRKernel:
    name = "probe_zext_i16_to_i64"
    llvm_ir = f"""
define i64 @{name}(i16 %a) {{
entry:
  %r = zext i16 %a to i64
  ret i64 %r
}}
"""
    return IRKernel(
        id=name,
        name=name,
        llvm_ir=llvm_ir,
        signature=KernelSignature(
            inputs=(KernelValue("a", "i16"),),
            outputs=(KernelValue("r", "i64"),),
        ),
        metadata=KernelMetadata(
            op_kind="zext",
            bit_width=64,
            suite="probe",
            expected_status="unsupported",
            tags=("cast", "partial-register"),
        ),
    )


def _probe_sext_kernel() -> IRKernel:
    name = "probe_sext_i16_to_i64"
    llvm_ir = f"""
define i64 @{name}(i16 %a) {{
entry:
  %r = sext i16 %a to i64
  ret i64 %r
}}
"""
    return IRKernel(
        id=name,
        name=name,
        llvm_ir=llvm_ir,
        signature=KernelSignature(
            inputs=(KernelValue("a", "i16"),),
            outputs=(KernelValue("r", "i64"),),
        ),
        metadata=KernelMetadata(
            op_kind="sext",
            bit_width=64,
            suite="probe",
            expected_status="unsupported",
            tags=("cast", "partial-register"),
        ),
    )


def _probe_multi_access_memory_kernel() -> IRKernel:
    name = "probe_load_store_i32"
    llvm_ir = f"""
define void @{name}(ptr %p, i32 %v) {{
entry:
  %old = load i32, ptr %p
  %r = add i32 %old, %v
  store i32 %r, ptr %p
  ret void
}}
"""
    return IRKernel(
        id=name,
        name=name,
        llvm_ir=llvm_ir,
        signature=KernelSignature(
            inputs=(KernelValue("p", "ptr"), KernelValue("v", "i32")),
            outputs=(),
        ),
        metadata=KernelMetadata(
            op_kind="load_store",
            bit_width=32,
            has_memory=True,
            suite="probe",
            expected_status="unsupported",
            expected_reason="exactly one memory access",
            tags=("memory", "multi-access"),
        ),
        memory_objects=(
            KernelMemoryObjectSpec(name="slot0", base="p", element_bits=32),
        ),
        memory_accesses=(
            KernelMemoryAccessSpec(
                kind="load",
                object="slot0",
                width_bits=32,
                address=KernelAddressSpec(base="p"),
                result="old",
            ),
            KernelMemoryAccessSpec(
                kind="store",
                object="slot0",
                width_bits=32,
                address=KernelAddressSpec(base="p"),
                value="v",
            ),
        ),
    )
