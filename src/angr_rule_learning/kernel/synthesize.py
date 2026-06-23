from __future__ import annotations

from angr_rule_learning.kernel.models import (
    IRKernel,
    KernelMetadata,
    KernelSignature,
    KernelValue,
)


class HardcodedKernelSynthesizer:
    def generate(self) -> tuple[IRKernel, ...]:
        return tuple(
            _binary_i32_kernel(op) for op in ("add", "sub", "and", "or", "xor")
        )


def _binary_i32_kernel(op: str) -> IRKernel:
    name = f"kernel_{op}_i32"
    llvm_ir = f"""
define i32 @{name}(i32 %a, i32 %b) {{
entry:
  %r = {op} i32 %a, %b
  ret i32 %r
}}
"""
    return IRKernel(
        id=name,
        name=name,
        llvm_ir=llvm_ir,
        signature=KernelSignature(
            inputs=(KernelValue("a", "i32"), KernelValue("b", "i32")),
            outputs=(KernelValue("r", "i32"),),
        ),
        metadata=KernelMetadata(op_kind=op, bit_width=32),
    )
