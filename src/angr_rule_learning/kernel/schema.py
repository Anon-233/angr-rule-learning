from __future__ import annotations

from dataclasses import dataclass, field

from angr_rule_learning.kernel.models import (
    IRKernel,
    KernelAddressSpec,
    KernelMemoryAccessSpec,
    KernelMemoryObjectSpec,
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
_ICMP_PREDICATES = frozenset(
    {"eq", "ne", "ugt", "uge", "ult", "ule", "sgt", "sge", "slt", "sle"}
)
_CAST_OPCODES = frozenset({"trunc", "zext", "sext"})


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
        if not _is_integer(self.result):
            raise ValueError("scalar schema instruction results must be integer values")
        object.__setattr__(self, "opcode", opcode)
        object.__setattr__(self, "operands", operands)


@dataclass(frozen=True)
class KernelIcmpInstruction:
    result: KernelValue
    predicate: str
    operands: tuple[KernelOperand, KernelOperand]

    def __post_init__(self) -> None:
        predicate = self.predicate.strip().lower()
        if predicate not in _ICMP_PREDICATES:
            raise ValueError(f"unsupported icmp predicate: {self.predicate}")
        if self.result.type != "i1":
            raise ValueError("icmp result must have type i1")
        operands = tuple(self.operands)
        if len(operands) != 2:
            raise ValueError("icmp instructions require exactly two operands")
        object.__setattr__(self, "predicate", predicate)
        object.__setattr__(self, "operands", operands)


@dataclass(frozen=True)
class KernelCastInstruction:
    result: KernelValue
    opcode: str
    operand: KernelValueRef

    def __post_init__(self) -> None:
        opcode = self.opcode.strip().lower()
        if opcode not in _CAST_OPCODES:
            raise ValueError(f"unsupported cast opcode: {self.opcode}")
        if not _is_integer(self.result):
            raise ValueError("cast result must be an integer value")
        object.__setattr__(self, "opcode", opcode)


@dataclass(frozen=True)
class KernelSelectInstruction:
    result: KernelValue
    condition: KernelValueRef
    values: tuple[KernelOperand, KernelOperand]

    def __post_init__(self) -> None:
        if not _is_integer(self.result):
            raise ValueError("select result must be an integer value")
        values = tuple(self.values)
        if len(values) != 2:
            raise ValueError("select instructions require exactly two values")
        object.__setattr__(self, "values", values)


@dataclass(frozen=True)
class KernelLoadInstruction:
    result: KernelValue
    object: str
    address: KernelAddressSpec

    def __post_init__(self) -> None:
        object_name = self.object.strip()
        if not object_name:
            raise ValueError("load memory object must not be empty")
        if not _is_integer(self.result):
            raise ValueError("load result must be an integer value")
        object.__setattr__(self, "object", object_name)


@dataclass(frozen=True)
class KernelStoreInstruction:
    value: KernelValueRef
    object: str
    address: KernelAddressSpec

    def __post_init__(self) -> None:
        object_name = self.object.strip()
        if not object_name:
            raise ValueError("store memory object must not be empty")
        object.__setattr__(self, "object", object_name)


KernelOperation = (
    KernelInstruction
    | KernelIcmpInstruction
    | KernelCastInstruction
    | KernelSelectInstruction
    | KernelLoadInstruction
    | KernelStoreInstruction
)


@dataclass(frozen=True)
class KernelSchema:
    """Typed straight-line kernel semantics before LLVM materialization."""

    id: str
    name: str
    signature: KernelSignature
    instructions: tuple[KernelOperation, ...]
    return_value: str | None
    metadata: KernelMetadata
    memory_objects: tuple[KernelMemoryObjectSpec, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        kernel_id = self.id.strip()
        name = self.name.strip()
        return_value = (
            self.return_value.strip() if self.return_value is not None else None
        )
        instructions = tuple(self.instructions)
        memory_objects = tuple(self.memory_objects)
        if not kernel_id:
            raise ValueError("kernel schema id must not be empty")
        if not name:
            raise ValueError("kernel schema name must not be empty")
        if not instructions:
            raise ValueError("kernel schema must contain at least one instruction")
        if len(self.signature.outputs) > 1:
            raise ValueError("kernel schema supports at most one output")
        if self.signature.outputs and not return_value:
            raise ValueError("non-void kernel schema requires a return value")
        if not self.signature.outputs and return_value is not None:
            raise ValueError("void kernel schema must not have a return value")
        has_memory_operations = any(
            isinstance(operation, (KernelLoadInstruction, KernelStoreInstruction))
            for operation in instructions
        )
        if self.metadata.has_memory != has_memory_operations:
            raise ValueError(
                "kernel metadata has_memory must match schema memory operations"
            )

        values = _input_values(self.signature)
        dependencies: dict[str, set[str]] = {}
        effect_roots: set[str] = set()
        objects = _memory_object_map(memory_objects)
        used_objects: set[str] = set()

        for operation in instructions:
            refs = _operation_refs(operation)
            for reference in refs:
                if reference not in values:
                    raise ValueError(f"unknown or forward value reference: {reference}")
            _validate_operation(operation, values, objects)
            result = _operation_result(operation)
            if result is None:
                effect_roots.update(refs)
            else:
                if result.name in values:
                    raise ValueError(f"duplicate kernel SSA value: {result.name}")
                dependencies[result.name] = set(refs)
                values[result.name] = result
            if isinstance(operation, (KernelLoadInstruction, KernelStoreInstruction)):
                used_objects.add(operation.object)

        unused_objects = sorted(set(objects) - used_objects)
        if unused_objects:
            raise ValueError(
                "kernel schema contains unused memory objects: "
                + ", ".join(unused_objects)
            )

        live_roots = set(effect_roots)
        if return_value is not None:
            returned = values.get(return_value)
            if returned is None:
                raise ValueError(f"unknown kernel return value: {return_value}")
            output = self.signature.outputs[0]
            if output.name != return_value or output.type != returned.type:
                raise ValueError("kernel output must match the returned SSA value")
            live_roots.add(return_value)

        live_values = _transitive_dependencies(live_roots, dependencies)
        dead_results = [
            result.name
            for operation in instructions
            if (result := _operation_result(operation)) is not None
            and result.name not in live_values
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
        object.__setattr__(self, "memory_objects", memory_objects)


def materialize_kernel(schema: KernelSchema) -> IRKernel:
    arguments = ", ".join(
        f"{value.type} %{value.name}" for value in schema.signature.inputs
    )
    return_type = (
        schema.signature.outputs[0].type if schema.signature.outputs else "void"
    )
    lines = [f"define {return_type} @{schema.name}({arguments}) {{", "entry:"]
    values = _all_values(schema)
    objects = _memory_object_map(schema.memory_objects)
    memory_accesses: list[KernelMemoryAccessSpec] = []
    memory_index = 0

    for operation in schema.instructions:
        if isinstance(operation, KernelInstruction):
            operand_text = ", ".join(
                _format_operand(operand) for operand in operation.operands
            )
            lines.append(
                f"  %{operation.result.name} = {operation.opcode} "
                f"{operation.result.type} {operand_text}"
            )
        elif isinstance(operation, KernelIcmpInstruction):
            operand_type = _referenced_operand_type(operation.operands, values)
            operand_text = ", ".join(
                _format_operand(operand) for operand in operation.operands
            )
            lines.append(
                f"  %{operation.result.name} = icmp {operation.predicate} "
                f"{operand_type} {operand_text}"
            )
        elif isinstance(operation, KernelCastInstruction):
            source = values[operation.operand.name]
            lines.append(
                f"  %{operation.result.name} = {operation.opcode} "
                f"{source.type} %{source.name} to {operation.result.type}"
            )
        elif isinstance(operation, KernelSelectInstruction):
            value_text = ", ".join(
                f"{operation.result.type} {_format_operand(value)}"
                for value in operation.values
            )
            lines.append(
                f"  %{operation.result.name} = select i1 "
                f"%{operation.condition.name}, {value_text}"
            )
        elif isinstance(operation, (KernelLoadInstruction, KernelStoreInstruction)):
            memory_index += 1
            memory_lines, address_value = _materialize_address(
                operation.address,
                objects[operation.object],
                memory_index,
            )
            lines.extend(memory_lines)
            memory_accesses.append(
                _materialize_memory_operation(operation, values, address_value, lines)
            )

    if schema.return_value is None:
        lines.append("  ret void")
    else:
        returned = values[schema.return_value]
        lines.append(f"  ret {returned.type} %{returned.name}")
    lines.append("}")
    return IRKernel(
        id=schema.id,
        name=schema.name,
        llvm_ir="\n".join(lines),
        signature=schema.signature,
        metadata=schema.metadata,
        memory_objects=schema.memory_objects,
        memory_accesses=tuple(memory_accesses),
    )


def _input_values(signature: KernelSignature) -> dict[str, KernelValue]:
    values: dict[str, KernelValue] = {}
    for value in signature.inputs:
        if value.name in values:
            raise ValueError(f"duplicate kernel input: {value.name}")
        values[value.name] = value
    return values


def _memory_object_map(
    memory_objects: tuple[KernelMemoryObjectSpec, ...],
) -> dict[str, KernelMemoryObjectSpec]:
    objects: dict[str, KernelMemoryObjectSpec] = {}
    for memory_object in memory_objects:
        if memory_object.name in objects:
            raise ValueError(f"duplicate kernel memory object: {memory_object.name}")
        objects[memory_object.name] = memory_object
    return objects


def _operation_result(operation: KernelOperation) -> KernelValue | None:
    if isinstance(operation, KernelStoreInstruction):
        return None
    return operation.result


def _operation_refs(operation: KernelOperation) -> tuple[str, ...]:
    if isinstance(operation, KernelInstruction):
        return _operand_refs(operation.operands)
    if isinstance(operation, KernelIcmpInstruction):
        return _operand_refs(operation.operands)
    if isinstance(operation, KernelCastInstruction):
        return (operation.operand.name,)
    if isinstance(operation, KernelSelectInstruction):
        return (operation.condition.name, *_operand_refs(operation.values))
    address_refs = (operation.address.base,) + (
        (operation.address.index,) if operation.address.index is not None else ()
    )
    if isinstance(operation, KernelLoadInstruction):
        return address_refs
    return (operation.value.name, *address_refs)


def _operand_refs(operands: tuple[KernelOperand, ...]) -> tuple[str, ...]:
    return tuple(
        operand.name for operand in operands if isinstance(operand, KernelValueRef)
    )


def _validate_operation(
    operation: KernelOperation,
    values: dict[str, KernelValue],
    objects: dict[str, KernelMemoryObjectSpec],
) -> None:
    if isinstance(operation, KernelInstruction):
        _validate_operands(operation.operands, operation.result.type, values)
        return
    if isinstance(operation, KernelIcmpInstruction):
        operand_type = _referenced_operand_type(operation.operands, values)
        if not operand_type.startswith("i"):
            raise ValueError("icmp operands must be integer values")
        _validate_operands(operation.operands, operand_type, values)
        return
    if isinstance(operation, KernelCastInstruction):
        source = values[operation.operand.name]
        _validate_cast(operation, source)
        return
    if isinstance(operation, KernelSelectInstruction):
        condition = values[operation.condition.name]
        if condition.type != "i1":
            raise ValueError("select condition must have type i1")
        _validate_operands(operation.values, operation.result.type, values)
        return
    memory_object = objects.get(operation.object)
    if memory_object is None:
        raise ValueError(f"unknown kernel memory object: {operation.object}")
    _validate_address(operation.address, memory_object, values)
    if isinstance(operation, KernelLoadInstruction):
        if operation.result.bit_width != memory_object.element_bits:
            raise ValueError("memory object width does not match load result width")
        return
    stored = values[operation.value.name]
    if not _is_integer(stored):
        raise ValueError("store value must be an integer value")
    if stored.bit_width != memory_object.element_bits:
        raise ValueError("memory object width does not match store value width")


def _validate_operands(
    operands: tuple[KernelOperand, ...],
    expected_type: str,
    values: dict[str, KernelValue],
) -> None:
    for operand in operands:
        if not isinstance(operand, KernelValueRef):
            continue
        source = values[operand.name]
        if source.type != expected_type:
            raise ValueError(
                "operand type mismatch: "
                f"{operand.name} is {source.type}, expected {expected_type}"
            )


def _referenced_operand_type(
    operands: tuple[KernelOperand, ...], values: dict[str, KernelValue]
) -> str:
    for operand in operands:
        if isinstance(operand, KernelValueRef):
            return values[operand.name].type
    raise ValueError("operation requires at least one value reference")


def _validate_cast(operation: KernelCastInstruction, source: KernelValue) -> None:
    if not _is_integer(source):
        raise ValueError("cast source must be an integer value")
    if operation.opcode == "trunc":
        if operation.result.bit_width >= source.bit_width:
            raise ValueError("trunc requires a narrower result type")
        return
    if operation.result.bit_width <= source.bit_width:
        raise ValueError(f"{operation.opcode} requires a wider result type")


def _validate_address(
    address: KernelAddressSpec,
    memory_object: KernelMemoryObjectSpec,
    values: dict[str, KernelValue],
) -> None:
    if address.base != memory_object.base:
        raise ValueError("memory address base does not match memory object base")
    base = values[address.base]
    if base.type != "ptr":
        raise ValueError("memory address base must have type ptr")
    element_bytes = memory_object.element_bits // 8
    if memory_object.element_bits % 8 != 0:
        raise ValueError("memory object width must be divisible by 8")
    if address.index is not None:
        index = values[address.index]
        if index.type != "i64":
            raise ValueError("memory address index must have type i64")
        if address.scale != element_bytes:
            raise ValueError("memory address scale must match element width")
    if address.displacement % element_bytes != 0:
        raise ValueError("memory displacement must align to element width")


def _all_values(schema: KernelSchema) -> dict[str, KernelValue]:
    values = {value.name: value for value in schema.signature.inputs}
    for operation in schema.instructions:
        result = _operation_result(operation)
        if result is not None:
            values[result.name] = result
    return values


def _materialize_address(
    address: KernelAddressSpec,
    memory_object: KernelMemoryObjectSpec,
    index: int,
) -> tuple[list[str], str]:
    if address.index is None and address.displacement == 0:
        return [], f"%{address.base}"
    element_type = f"i{memory_object.element_bits}"
    element_bytes = memory_object.element_bits // 8
    lines: list[str] = []
    if address.index is None:
        llvm_index = str(address.displacement // element_bytes)
    else:
        llvm_index = f"%{address.index}"
        if address.displacement:
            adjusted = "idx_plus" if index == 1 else f"idx_plus{index}"
            offset = address.displacement // element_bytes
            lines.append(f"  %{adjusted} = add i64 %{address.index}, {offset}")
            llvm_index = f"%{adjusted}"
    address_name = "q" if index == 1 else f"q{index}"
    lines.append(
        f"  %{address_name} = getelementptr {element_type}, "
        f"ptr %{address.base}, i64 {llvm_index}"
    )
    return lines, f"%{address_name}"


def _materialize_memory_operation(
    operation: KernelLoadInstruction | KernelStoreInstruction,
    values: dict[str, KernelValue],
    address_value: str,
    lines: list[str],
) -> KernelMemoryAccessSpec:
    if isinstance(operation, KernelLoadInstruction):
        lines.append(
            f"  %{operation.result.name} = load {operation.result.type}, "
            f"ptr {address_value}"
        )
        return KernelMemoryAccessSpec(
            kind="load",
            object=operation.object,
            width_bits=operation.result.bit_width,
            address=operation.address,
            result=operation.result.name,
        )
    stored = values[operation.value.name]
    lines.append(f"  store {stored.type} %{stored.name}, ptr {address_value}")
    return KernelMemoryAccessSpec(
        kind="store",
        object=operation.object,
        width_bits=stored.bit_width,
        address=operation.address,
        value=stored.name,
    )


def _format_operand(operand: KernelOperand) -> str:
    if isinstance(operand, KernelValueRef):
        return f"%{operand.name}"
    return str(operand.value)


def _transitive_dependencies(
    roots: set[str], dependencies: dict[str, set[str]]
) -> set[str]:
    live = set(roots)
    pending = list(roots)
    while pending:
        current = pending.pop()
        for dependency in dependencies.get(current, ()):
            if dependency in live:
                continue
            live.add(dependency)
            pending.append(dependency)
    return live


def _is_integer(value: KernelValue) -> bool:
    return value.type.startswith("i")
