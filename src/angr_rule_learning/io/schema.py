from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from angr_rule_learning.verification.candidate import (
    AliasDeclaration,
    Clobbers,
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)
from angr_rule_learning.verification.report import VerificationReport


TOP_LEVEL_FIELDS = {
    "candidate_id",
    "guest",
    "host",
    "inputs",
    "outputs",
    "memory",
    "preconditions",
    "clobbers",
}
REQUIRED_TOP_LEVEL_FIELDS = (
    "candidate_id",
    "guest",
    "host",
    "inputs",
    "outputs",
    "memory",
    "preconditions",
    "clobbers",
)
FRAGMENT_FIELDS = {"arch", "address", "code_hex", "instruction_count"}
INPUT_FIELDS = {"registers"}
OUTPUT_FIELDS = {"registers", "flags"}
CLOBBER_FIELDS = {"guest", "host"}
MEMORY_FIELDS = {"slots", "bindings", "accesses", "alias"}
MEMORY_SLOT_FIELDS = {"name", "size", "initial"}
MEMORY_BINDING_FIELDS = {"slot", "guest_addr", "host_addr", "access"}
MEMORY_ACCESS_FIELDS = {"slot", "kind", "width"}
MEMORY_ALIAS_FIELDS = {"slots", "relation"}


def candidate_from_json(payload: dict[str, Any]) -> VerificationCandidate:
    _reject_unknown_fields(payload, TOP_LEVEL_FIELDS, "top-level")
    for field in REQUIRED_TOP_LEVEL_FIELDS:
        if field not in payload:
            raise ValueError(f"missing top-level field: {field}")

    inputs = _dict(payload["inputs"], "inputs")
    _reject_unknown_fields(inputs, INPUT_FIELDS, "inputs")
    outputs = _dict(payload["outputs"], "outputs")
    _reject_unknown_fields(outputs, OUTPUT_FIELDS, "outputs")
    memory = _dict(payload["memory"], "memory")
    _reject_unknown_fields(memory, MEMORY_FIELDS, "memory")
    clobbers = _dict(payload["clobbers"], "clobbers")
    _reject_unknown_fields(clobbers, CLOBBER_FIELDS, "clobbers")

    return VerificationCandidate(
        candidate_id=_string(payload["candidate_id"], "candidate_id"),
        guest=_fragment_from_json(_dict(payload["guest"], "guest"), "guest"),
        host=_fragment_from_json(_dict(payload["host"], "host"), "host"),
        input_registers=_pairs(
            _required(inputs, "registers", "inputs"), "inputs.registers"
        ),
        output_registers=_pairs(
            _required(outputs, "registers", "outputs"), "outputs.registers"
        ),
        output_flags=_pairs(_required(outputs, "flags", "outputs"), "outputs.flags"),
        memory=_memory_from_json(memory),
        preconditions=tuple(
            _string(item, "preconditions entries")
            for item in _list(payload["preconditions"], "preconditions")
        ),
        clobbers=Clobbers(
            guest=tuple(
                _string(reg, "clobbers.guest entries")
                for reg in _list(
                    _required(clobbers, "guest", "clobbers"), "clobbers.guest"
                )
            ),
            host=tuple(
                _string(reg, "clobbers.host entries")
                for reg in _list(
                    _required(clobbers, "host", "clobbers"), "clobbers.host"
                )
            ),
        ),
    )


def report_to_json(report: VerificationReport) -> dict[str, Any]:
    result = {
        "candidate_id": report.candidate_id,
        "equivalent": report.equivalent,
        "status": report.status,
        "checks": [
            {
                "kind": check.kind,
                "status": check.status,
                "guest": check.guest,
                "host": check.host,
                "reason": check.reason,
                "counterexample": _json_value(
                    check.counterexample, f"checks[{index}].counterexample"
                ),
            }
            for index, check in enumerate(report.checks)
        ],
        "unsupported_features": list(report.unsupported_features),
        "events": _json_value(report.events, "events"),
        "failure_reasons": _json_value(report.failure_reasons, "failure_reasons"),
    }
    return _dict(_json_value(result, ""), "report")


def _fragment_from_json(payload: dict[str, Any], location: str) -> CodeFragment:
    _reject_unknown_fields(payload, FRAGMENT_FIELDS, location)
    return CodeFragment(
        arch=_string(_required(payload, "arch", location), f"{location}.arch"),
        address=_integer(
            _required(payload, "address", location), f"{location}.address"
        ),
        code_hex=_string(
            _required(payload, "code_hex", location), f"{location}.code_hex"
        ),
        instruction_count=_integer(
            _required(payload, "instruction_count", location),
            f"{location}.instruction_count",
        ),
    )


def _memory_from_json(payload: dict[str, Any]) -> MemorySpec:
    return MemorySpec(
        slots=tuple(
            _memory_slot_from_json(slot, f"memory.slots[{index}]")
            for index, slot in enumerate(
                _list(_required(payload, "slots", "memory"), "memory.slots")
            )
        ),
        bindings=tuple(
            _memory_binding_from_json(binding, f"memory.bindings[{index}]")
            for index, binding in enumerate(
                _list(_required(payload, "bindings", "memory"), "memory.bindings")
            )
        ),
        accesses=tuple(
            _memory_access_from_json(access, f"memory.accesses[{index}]")
            for index, access in enumerate(
                _list(_required(payload, "accesses", "memory"), "memory.accesses")
            )
        ),
        alias=tuple(
            _memory_alias_from_json(alias, f"memory.alias[{index}]")
            for index, alias in enumerate(
                _list(_required(payload, "alias", "memory"), "memory.alias")
            )
        ),
    )


def _memory_slot_from_json(value: object, path: str) -> MemorySlot:
    slot = _dict(value, path)
    _reject_unknown_fields(slot, MEMORY_SLOT_FIELDS, path)
    return MemorySlot(
        name=_string(_required(slot, "name", path), f"{path}.name"),
        size=_integer(_required(slot, "size", path), f"{path}.size"),
        initial=_string(slot.get("initial", "symbolic"), f"{path}.initial"),
    )


def _memory_binding_from_json(value: object, path: str) -> MemoryBinding:
    binding = _dict(value, path)
    _reject_unknown_fields(binding, MEMORY_BINDING_FIELDS, path)
    return MemoryBinding(
        slot=_string(_required(binding, "slot", path), f"{path}.slot"),
        guest_addr=_string(
            _required(binding, "guest_addr", path), f"{path}.guest_addr"
        ),
        host_addr=_string(_required(binding, "host_addr", path), f"{path}.host_addr"),
        access=_string(_required(binding, "access", path), f"{path}.access"),
    )


def _memory_access_from_json(value: object, path: str) -> MemoryAccessExpectation:
    access = _dict(value, path)
    _reject_unknown_fields(access, MEMORY_ACCESS_FIELDS, path)
    return MemoryAccessExpectation(
        slot=_string(_required(access, "slot", path), f"{path}.slot"),
        kind=_string(_required(access, "kind", path), f"{path}.kind"),
        width=_integer(_required(access, "width", path), f"{path}.width"),
    )


def _memory_alias_from_json(value: object, path: str) -> AliasDeclaration:
    alias = _dict(value, path)
    _reject_unknown_fields(alias, MEMORY_ALIAS_FIELDS, path)
    return AliasDeclaration(
        slots=tuple(
            _string(slot, f"{path}.slots entries")
            for slot in _list(_required(alias, "slots", path), f"{path}.slots")
        ),
        relation=_string(_required(alias, "relation", path), f"{path}.relation"),
    )


def _pairs(value: object, path: str) -> tuple[tuple[str, str], ...]:
    value = _list(value, path)
    pairs = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError(f"{path} entries must be two-item lists")
        if not isinstance(item[0], str) or not isinstance(item[1], str):
            raise ValueError(f"{path} entries must contain strings")
        pairs.append((item[0], item[1]))
    return tuple(pairs)


def _dict(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    return value


def _list(value: object, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list")
    return value


def _string(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{path} must be a string")
    return value


def _integer(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{path} must be an integer")
    return value


def _required(payload: dict[str, Any], field: str, location: str) -> Any:
    if field not in payload:
        raise ValueError(f"missing {location} field: {field}")
    return payload[field]


def _reject_unknown_fields(
    payload: dict[str, Any], allowed: set[str], location: str
) -> None:
    for field in payload:
        if field not in allowed:
            raise ValueError(f"unknown {location} field: {field}")


def _json_value(value: object, path: str) -> object:
    if value is None or isinstance(value, str | int | bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"report contains non-JSON value at {path}")
        return value
    if isinstance(value, Mapping):
        result = {}
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError(
                    f"report contains non-JSON value at {_json_path(path, key)}"
                )
            result[key] = _json_value(nested, _json_path(path, key))
        return result
    if isinstance(value, list | tuple):
        return [
            _json_value(nested, f"{path}[{index}]")
            for index, nested in enumerate(value)
        ]
    raise ValueError(f"report contains non-JSON value at {path}")


def _json_path(path: str, key: object) -> str:
    if not path:
        return str(key)
    if isinstance(key, str) and key.isidentifier():
        return f"{path}.{key}"
    return f"{path}[{key!r}]"
