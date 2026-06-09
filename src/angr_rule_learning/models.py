from __future__ import annotations

from dataclasses import dataclass, field


def _normalize_reg(reg: str) -> str:
    return reg.strip().lower()


def _normalize_hex(code_hex: str) -> str:
    parts = code_hex.replace(",", " ").replace("_", " ").split()
    normalized = []
    for part in parts:
        if part.startswith(("0x", "0X")):
            part = part[2:]
        normalized.append(part)
    return "".join(normalized)


@dataclass(frozen=True)
class CodeFragment:
    arch: str
    address: int
    code_hex: str
    instruction_count: int
    def_regs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "arch", self.arch.strip().lower())
        object.__setattr__(self, "code_hex", _normalize_hex(self.code_hex))
        object.__setattr__(
            self, "def_regs", tuple(_normalize_reg(reg) for reg in self.def_regs)
        )
        if self.instruction_count < 1:
            raise ValueError("instruction_count must be positive")

    @property
    def code_bytes(self) -> bytes:
        return bytes.fromhex(self.code_hex)


@dataclass(frozen=True)
class VerificationRequest:
    guest: CodeFragment
    host: CodeFragment
    init_map: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "init_map",
            tuple(
                (_normalize_reg(guest), _normalize_reg(host))
                for guest, host in self.init_map
            ),
        )
        if len(self.guest.def_regs) != len(self.host.def_regs):
            raise ValueError("guest and host def_regs must have the same length")


@dataclass(frozen=True)
class RegisterCheck:
    guest_reg: str
    host_reg: str
    status: str


@dataclass(frozen=True)
class VerificationResult:
    register_checks: tuple[RegisterCheck, ...]
    counterexample: dict[str, int] = field(default_factory=dict)

    @property
    def equivalent(self) -> bool:
        return all(check.status == "pass" for check in self.register_checks)
