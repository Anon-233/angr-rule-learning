from __future__ import annotations

from dataclasses import dataclass, field

from angr_rule_learning.verification.addressing import parse_address_binding


def _canonicalize_binding(expression: str) -> str:
    """Canonicalize a supported address expression; keep unsupported forms.

    Supported expressions are normalized through parse_address_binding so
    whitespace and case are canonical.  Expressions the parser does not yet
    support are left as lowercased strings so the verifier can report
    ``unsupported_address_expression`` at the right stage.
    """
    try:
        return parse_address_binding(expression).canonical()
    except ValueError:
        return expression


def normalize_register(reg: str) -> str:
    return reg.strip().lower()


def normalize_hex(code_hex: str) -> str:
    parts = code_hex.replace(",", " ").replace("_", " ").split()
    normalized = []
    for part in parts:
        if part.startswith(("0x", "0X")):
            part = part[2:]
        normalized.append(part)
    return "".join(normalized).lower()


@dataclass(frozen=True)
class CodeFragment:
    arch: str
    address: int
    code_hex: str
    instruction_count: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "arch", self.arch.strip().lower())
        code_hex = normalize_hex(self.code_hex)
        if not code_hex:
            raise ValueError("code_hex must contain at least one byte")
        try:
            bytes.fromhex(code_hex)
        except ValueError as exc:
            raise ValueError("code_hex must contain valid hexadecimal bytes") from exc
        object.__setattr__(self, "code_hex", code_hex)
        if self.instruction_count < 1:
            raise ValueError("instruction_count must be positive")

    @property
    def code_bytes(self) -> bytes:
        return bytes.fromhex(self.code_hex)


@dataclass(frozen=True)
class MemorySlot:
    name: str
    size: int
    initial: str = "symbolic"

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "initial", self.initial.strip().lower())
        if not self.name:
            raise ValueError("memory slot name must not be empty")
        if self.size < 1:
            raise ValueError("memory slot size must be positive")
        if self.initial != "symbolic":
            raise ValueError("only symbolic memory slots are supported")


@dataclass(frozen=True)
class MemoryBinding:
    slot: str
    guest_addr: str
    host_addr: str
    access: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "slot", self.slot.strip())
        object.__setattr__(self, "access", self.access.strip().lower())
        if not self.slot:
            raise ValueError("memory binding slot must not be empty")
        if self.access not in {"read", "write", "read_write"}:
            raise ValueError("unsupported memory binding access")

        guest_addr = self.guest_addr.strip().lower()
        if not guest_addr:
            raise ValueError("guest memory address expression must not be empty")
        guest_addr = _canonicalize_binding(guest_addr)
        object.__setattr__(self, "guest_addr", guest_addr)

        host_addr = self.host_addr.strip().lower()
        if not host_addr:
            raise ValueError("host memory address expression must not be empty")
        host_addr = _canonicalize_binding(host_addr)
        object.__setattr__(self, "host_addr", host_addr)


@dataclass(frozen=True)
class MemoryAccessExpectation:
    slot: str
    kind: str
    width: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "slot", self.slot.strip())
        object.__setattr__(self, "kind", self.kind.strip().lower())
        if not self.slot:
            raise ValueError("memory access slot must not be empty")
        if self.kind not in {"read", "write"}:
            raise ValueError("unsupported memory access kind")
        if self.width < 1:
            raise ValueError("memory access width must be positive")


@dataclass(frozen=True)
class AliasDeclaration:
    slots: tuple[str, ...]
    relation: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "slots", tuple(slot.strip() for slot in self.slots))
        object.__setattr__(self, "relation", self.relation.strip().lower())
        if any(not slot for slot in self.slots):
            raise ValueError("alias slot must not be empty")
        if len(self.slots) < 2:
            raise ValueError("alias declaration must include at least two slots")
        if self.relation not in {"disjoint", "must_alias", "may_alias"}:
            raise ValueError("unsupported alias relation")


@dataclass(frozen=True)
class MemorySpec:
    slots: tuple[MemorySlot, ...] = field(default_factory=tuple)
    bindings: tuple[MemoryBinding, ...] = field(default_factory=tuple)
    accesses: tuple[MemoryAccessExpectation, ...] = field(default_factory=tuple)
    alias: tuple[AliasDeclaration, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "slots", tuple(self.slots))
        object.__setattr__(self, "bindings", tuple(self.bindings))
        object.__setattr__(self, "accesses", tuple(self.accesses))
        object.__setattr__(self, "alias", tuple(self.alias))

        known_slots: set[str] = set()
        for slot in self.slots:
            if slot.name in known_slots:
                raise ValueError(f"duplicate memory slot: {slot.name}")
            known_slots.add(slot.name)

        for binding in self.bindings:
            if binding.slot not in known_slots:
                raise ValueError(f"unknown memory slot: {binding.slot}")

        for access in self.accesses:
            if access.slot not in known_slots:
                raise ValueError(f"unknown memory slot: {access.slot}")

        for alias in self.alias:
            for slot in alias.slots:
                if slot not in known_slots:
                    raise ValueError(f"unknown memory slot: {slot}")


@dataclass(frozen=True)
class Clobbers:
    guest: tuple[str, ...] = field(default_factory=tuple)
    host: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "guest", tuple(normalize_register(reg) for reg in self.guest)
        )
        object.__setattr__(
            self, "host", tuple(normalize_register(reg) for reg in self.host)
        )


@dataclass(frozen=True)
class RegisterBindingRole:
    """Semantic role hint for a register pair in a ``VerificationCandidate``.

    Preserves the kernel-level type (``"i32"``, ``"i64"``, ``"ptr"``) so
    that rule generalization can emit type-specific placeholders.
    """

    guest: str
    host: str
    value_name: str
    value_type: str  # "i32", "i64", "ptr"

    def __post_init__(self) -> None:
        from angr_rule_learning.verification.candidate import normalize_register

        object.__setattr__(self, "guest", normalize_register(self.guest))
        object.__setattr__(self, "host", normalize_register(self.host))
        object.__setattr__(self, "value_name", self.value_name.strip())
        object.__setattr__(self, "value_type", self.value_type.strip().lower())
        if not self.value_name:
            raise ValueError("register role value_name must not be empty")
        if self.value_type not in {"i8", "i16", "i32", "i64", "ptr"}:
            raise ValueError(f"unsupported register value_type: {self.value_type}")


@dataclass(frozen=True)
class VerificationCandidate:
    candidate_id: str
    guest: CodeFragment
    host: CodeFragment
    input_registers: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    output_registers: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    output_flags: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    memory: MemorySpec = field(default_factory=MemorySpec)
    preconditions: tuple[str, ...] = field(default_factory=tuple)
    clobbers: Clobbers = field(default_factory=Clobbers)
    register_roles: tuple[RegisterBindingRole, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_id", self.candidate_id.strip())
        if not self.candidate_id:
            raise ValueError("candidate_id must not be empty")
        object.__setattr__(
            self,
            "input_registers",
            tuple(
                (normalize_register(guest), normalize_register(host))
                for guest, host in self.input_registers
            ),
        )
        object.__setattr__(
            self,
            "output_registers",
            tuple(
                (normalize_register(guest), normalize_register(host))
                for guest, host in self.output_registers
            ),
        )
        object.__setattr__(
            self,
            "output_flags",
            tuple(
                (normalize_register(guest), normalize_register(host))
                for guest, host in self.output_flags
            ),
        )
        object.__setattr__(self, "preconditions", tuple(self.preconditions))
