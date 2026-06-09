from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from angr_rule_learning.models import (
    CodeFragment,
    VerificationRequest,
    VerificationResult,
)
from angr_rule_learning.verifier import AngrSemanticVerifier


def run_verify_payload(payload: dict[str, Any]) -> dict[str, Any]:
    request = _request_from_payload(payload)
    result = AngrSemanticVerifier().verify(request)
    return _result_to_payload(result)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="angr-rule-learning")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser(
        "verify", help="verify one candidate mapping JSON file"
    )
    verify_parser.add_argument("request", type=Path)

    args = parser.parse_args(argv)
    if args.command == "verify":
        payload = json.loads(args.request.read_text(encoding="utf-8"))
        json.dump(run_verify_payload(payload), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")


def _request_from_payload(payload: dict[str, Any]) -> VerificationRequest:
    return VerificationRequest(
        guest=_fragment_from_payload(payload["guest"]),
        host=_fragment_from_payload(payload["host"]),
        init_map=tuple(tuple(pair) for pair in payload.get("init_map", ())),
    )


def _fragment_from_payload(payload: dict[str, Any]) -> CodeFragment:
    return CodeFragment(
        arch=payload["arch"],
        address=int(payload["address"]),
        code_hex=payload["code_hex"],
        instruction_count=int(payload["instruction_count"]),
        def_regs=tuple(payload.get("def_regs", ())),
    )


def _result_to_payload(result: VerificationResult) -> dict[str, Any]:
    return {
        "equivalent": result.equivalent,
        "register_checks": [
            {
                "guest_reg": check.guest_reg,
                "host_reg": check.host_reg,
                "status": check.status,
            }
            for check in result.register_checks
        ],
        "counterexample": result.counterexample,
    }
