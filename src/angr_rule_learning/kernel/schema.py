from __future__ import annotations

from dataclasses import dataclass

from angr_rule_learning.kernel.models import (
    IRKernel,
    KernelMetadata,
    KernelSignature,
    KernelValue,
)


_SCALAR_BINARY_OPCODES = frozenset(
    {
        "add",
        "sub",
        "mul",
        "udiv",
        "sdiv",
        "urem",
        "srem",
        "shl",
        "lshr",
        "ashr",
        "and",
        "or",
        "xor",
    }
)


@dataclass(frozen=True)
class KernelValueRef:
    name: str

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("kernel value reference must not be empty")
        object.__setattr__(self, "name", name)


@dataclass(frozen=True)
class KernelIntConstant:
    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise TypeError("kernel integer constant must be an int")


KernelOperand = KernelValueRef | KernelIntConstant


@dataclass(frozen=True)
class KernelInstruction:
    """One same-type scalar binary instruction in a kernel SSA graph."""

    result: KernelValue
    opcode: str
    operands: tuple[KernelOperand, KernelOperand]

    def __post_init__(self) -> None:
        opcode = self.opcode.strip().lower()
        if opcode not in _SCALAR_BINARY_OPCODES:
            raise ValueError(f"unsupported scalar schema opcode: {self.opcode}")
        operands = tuple(self.operands)
        if len(operands) != 2:
            raise ValueError("scalar schema instructions require exactly two operands")
        if not self.result.type.startswith("i"):
            raise ValueError("scalar schema instruction results must be integer values")
        object.__setattr__(self, "opcode", opcode)
        object.__setattr__(self, "operands", operands)


@dataclass(frozen=True)
class KernelSchema:
    """Typed, straight-line scalar SSA semantics before LLVM materialization."""

    id: str
    name: str
    signature: KernelSignature
    instructions: tuple[KernelInstruction, ...]
    return_value: str
    metadata: KernelMetadata

    def __post_init__(self) -> None:
        kernel_id = self.id.strip()
        name = self.name.strip()
        return_value = self.return_value.strip()
        instructions = tuple(self.instructions)
        if not kernel_id:
            raise ValueError("kernel schema id must not be empty")
        if not name:
            raise ValueError("kernel schema name must not be empty")
        if not return_value:
            raise ValueError("kernel schema return value must not be empty")
        if not instructions:
            raise ValueError("kernel schema must contain at least one instruction")
        if len(self.signature.outputs) != 1:
            raise ValueError("scalar kernel schema requires exactly one output")

        values: dict[str, KernelValue] = {}
        for value in self.signature.inputs:
            if value.name in values:
                raise ValueError(f"duplicate kernel input: {value.name}")
            values[value.name] = value

        dependencies: dict[str, set[str]] = {}
        for instruction in instructions:
            result = instruction.result
            if result.name in values:
                raise ValueError(f"duplicate kernel SSA value: {result.name}")
            refs: set[str] = set()
            for operand in instruction.operands:
                if not isinstance(operand, KernelValueRef):
                    continue
                source = values.get(operand.name)
                if source is None:
                    raise ValueError(
                        f"unknown or forward value reference: {operand.name}"
                    )
                if source.type != result.type:
                    raise ValueError(
                        "operand type mismatch: "
                        f"{operand.name} is {source.type}, result is {result.type}"
                    )
                refs.add(operand.name)
            dependencies[result.name] = refs
            values[result.name] = result

        returned = values.get(return_value)
        if returned is None:
            raise ValueError(f"unknown kernel return value: {return_value}")
        output = self.signature.outputs[0]
        if output.name != return_value or output.type != returned.type:
            raise ValueError("kernel output must match the returned SSA value")

        live_values = _transitive_dependencies(return_value, dependencies)
        dead_results = [
            instruction.result.name
            for instruction in instructions
            if instruction.result.name not in live_values
        ]
        if dead_results:
            raise ValueError(
                "kernel schema contains dead instruction results: "
                + ", ".join(dead_results)
            )
        unused_inputs = [
            value.name
            for value in self.signature.inputs
            if value.name not in live_values
        ]
        if unused_inputs:
            raise ValueError(
                "kernel schema contains unused inputs: " + ", ".join(unused_inputs)
            )

        object.__setattr__(self, "id", kernel_id)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "instructions", instructions)
        object.__setattr__(self, "return_value", return_value)


def materialize_kernel(schema: KernelSchema) -> IRKernel:
    arguments = ", ".join(
        f"{value.type} %{value.name}" for value in schema.signature.inputs
    )
    lines = [
        f"define {schema.signature.outputs[0].type} @{schema.name}({arguments}) {{",
        "entry:",
    ]
    for instruction in schema.instructions:
        operand_text = ", ".join(
            _format_operand(operand) for operand in instruction.operands
        )
        lines.append(
            f"  %{instruction.result.name} = {instruction.opcode} "
            f"{instruction.result.type} {operand_text}"
        )
    returned = schema.signature.outputs[0]
    lines.extend((f"  ret {returned.type} %{schema.return_value}", "}"))
    return IRKernel(
        id=schema.id,
        name=schema.name,
        llvm_ir="\n".join(lines),
        signature=schema.signature,
        metadata=schema.metadata,
    )


def _format_operand(operand: KernelOperand) -> str:
    if isinstance(operand, KernelValueRef):
        return f"%{operand.name}"
    return str(operand.value)


def _transitive_dependencies(root: str, dependencies: dict[str, set[str]]) -> set[str]:
    live = {root}
    pending = [root]
    while pending:
        current = pending.pop()
        for dependency in dependencies.get(current, ()):
            if dependency in live:
                continue
            live.add(dependency)
            pending.append(dependency)
    return live
