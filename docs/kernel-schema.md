# Kernel Schema

`KernelSchema` is the architecture-independent semantic boundary between
kernel generation and LLVM materialization. Builtin generators describe typed
operations rather than constructing LLVM IR strings directly.

## Operation Model

The schema currently supports:

```text
KernelInstruction        same-type integer binary operation
KernelIcmpInstruction    integer comparison producing i1
KernelCastInstruction    trunc, zext, or sext
KernelSelectInstruction  i1 condition and two same-type values
KernelLoadInstruction    typed load from a declared memory object
KernelStoreInstruction   typed store to a declared memory object
```

Operands are either `KernelValueRef` values or integer constants. Instruction
results form a straight-line SSA graph: each reference must name a signature
input or an earlier result.

## Returns And Effects

A scalar-returning schema has one signature output and names that SSA value in
`return_value`. A void schema has no outputs and uses `return_value=None`.
Stores are effect roots, so their address/value dependencies remain live even
without a register return. Pure results that reach neither the return value nor
a store are rejected as dead.

Current schemas support at most one register result. Multiple memory effects
can be represented, although the first-stage `KernelBindingBuilder` still
rejects kernels with more than one memory access.

## Memory Semantics

Loads and stores reference a `KernelMemoryObjectSpec` and carry one
`KernelAddressSpec`:

```text
base + index * scale + displacement
```

The base must be a `ptr` value, an index must be `i64`, scale must match the
memory object's element size, and displacement must be element-aligned.
Materialization uses this address to emit any required `getelementptr` and also
derives `KernelMemoryAccessSpec`. This prevents the LLVM body and verifier
declaration from disagreeing about kind, width, address, or stored value.

## Validation Boundary

Construction rejects:

```text
unknown or forward references
duplicate inputs, results, or memory objects
operand type mismatches
invalid icmp predicates or non-i1 conditions
invalid cast direction
unknown or unused memory objects
mis-typed base/index values
memory width, scale, or displacement mismatches
dead results and unused inputs
return/signature mismatches
```

Once materialized, an `IRKernel` follows the existing compilation, snippet
extraction, ABI binding, semantic verification, and rule generalization path.
