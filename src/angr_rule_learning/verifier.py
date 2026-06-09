from __future__ import annotations

# ruff: noqa: E402

from dataclasses import dataclass
import logging

logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

import angr
import claripy

from angr_rule_learning.models import RegisterCheck, VerificationRequest, VerificationResult


ARCH_ALIASES = {
    "arm": "ARMEL",
    "armel": "ARMEL",
    "x86": "X86",
    "i386": "X86",
    "amd64": "AMD64",
    "x86_64": "AMD64",
    "x86-64": "AMD64",
    "aarch64": "AARCH64",
    "arm64": "AARCH64",
}


@dataclass(frozen=True)
class ExecutedFragment:
    state: angr.SimState


class AngrSemanticVerifier:
    def verify(self, request: VerificationRequest) -> VerificationResult:
        guest_state = self._make_state(request.guest.arch, request.guest.code_bytes, request.guest.address)
        host_state = self._make_state(request.host.arch, request.host.code_bytes, request.host.address)

        symbols: dict[str, claripy.ast.BV] = {}
        for guest_reg, host_reg in request.init_map:
            width = max(self._reg_width(guest_state, guest_reg), self._reg_width(host_state, host_reg))
            symbol = claripy.BVS(f"init_{guest_reg}_{host_reg}", width)
            symbols[guest_reg] = symbol
            symbols[host_reg] = symbol
            self._write_reg(guest_state, guest_reg, symbol)
            self._write_reg(host_state, host_reg, symbol)

        guest_final = self._execute(
            request.guest.arch,
            request.guest.code_bytes,
            request.guest.address,
            request.guest.instruction_count,
            guest_state,
        )
        host_final = self._execute(
            request.host.arch,
            request.host.code_bytes,
            request.host.address,
            request.host.instruction_count,
            host_state,
        )

        register_checks = []
        for guest_reg, host_reg in zip(request.guest.def_regs, request.host.def_regs, strict=True):
            guest_value = self._read_reg(guest_final.state, guest_reg)
            host_value = self._read_reg(host_final.state, host_reg)
            guest_value, host_value = self._align_widths(guest_value, host_value)
            diff = guest_value != host_value
            solver = self._solver_for(guest_final.state, host_final.state)
            if solver.satisfiable(extra_constraints=[diff]):
                counterexample = self._counterexample(guest_final.state, host_final.state, diff, symbols)
                register_checks.append(RegisterCheck(guest_reg, host_reg, "fail"))
                return VerificationResult(tuple(register_checks), counterexample)
            register_checks.append(RegisterCheck(guest_reg, host_reg, "pass"))

        return VerificationResult(tuple(register_checks))

    def _make_state(self, arch: str, code: bytes, address: int) -> angr.SimState:
        project = angr.load_shellcode(code, arch=self._angr_arch(arch), load_address=address)
        return project.factory.blank_state(addr=address)

    def _execute(
        self,
        arch: str,
        code: bytes,
        address: int,
        instruction_count: int,
        state: angr.SimState,
    ) -> ExecutedFragment:
        project = angr.load_shellcode(code, arch=self._angr_arch(arch), load_address=address)
        successors = project.factory.successors(state, num_inst=instruction_count).successors
        if len(successors) != 1:
            raise ValueError(f"expected exactly one successor, got {len(successors)}")
        return ExecutedFragment(successors[0])

    def _angr_arch(self, arch: str) -> str:
        try:
            return ARCH_ALIASES[arch]
        except KeyError as exc:
            raise ValueError(f"unsupported architecture: {arch}") from exc

    def _read_reg(self, state: angr.SimState, reg: str) -> claripy.ast.BV:
        return getattr(state.regs, reg)

    def _write_reg(self, state: angr.SimState, reg: str, value: claripy.ast.BV) -> None:
        setattr(state.regs, reg, self._fit_width(value, self._reg_width(state, reg)))

    def _reg_width(self, state: angr.SimState, reg: str) -> int:
        try:
            _, size = state.arch.registers[reg]
        except KeyError as exc:
            raise ValueError(f"unknown register for {state.arch.name}: {reg}") from exc
        return size * state.arch.byte_width

    def _fit_width(self, value: claripy.ast.BV, width: int) -> claripy.ast.BV:
        if value.size() == width:
            return value
        if value.size() < width:
            return value.zero_extend(width - value.size())
        return value[width - 1 : 0]

    def _align_widths(
        self,
        left: claripy.ast.BV,
        right: claripy.ast.BV,
    ) -> tuple[claripy.ast.BV, claripy.ast.BV]:
        width = max(left.size(), right.size())
        return self._fit_width(left, width), self._fit_width(right, width)

    def _solver_for(self, guest_state: angr.SimState, host_state: angr.SimState) -> claripy.Solver:
        solver = claripy.Solver()
        if guest_state.solver.constraints:
            solver.add(*guest_state.solver.constraints)
        if host_state.solver.constraints:
            solver.add(*host_state.solver.constraints)
        return solver

    def _counterexample(
        self,
        guest_state: angr.SimState,
        host_state: angr.SimState,
        diff: claripy.ast.Bool,
        symbols: dict[str, claripy.ast.BV],
    ) -> dict[str, int]:
        solver = self._solver_for(guest_state, host_state)
        solver.add(diff)
        return {reg: solver.eval(symbol, 1)[0] for reg, symbol in symbols.items()}
