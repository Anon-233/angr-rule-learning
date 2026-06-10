from __future__ import annotations

import argparse
from pathlib import Path

from angr_rule_learning.io.readers import read_candidates
from angr_rule_learning.io.writers import write_reports_jsonl, write_summary_json
from angr_rule_learning.verification.batch import BatchVerifier


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="angr-rule-learning")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser(
        "verify", help="verify candidate JSON or JSONL inputs"
    )
    verify_parser.add_argument("input", type=Path)
    verify_parser.add_argument("--output", required=True, type=Path)
    verify_parser.add_argument("--summary", required=True, type=Path)

    args = parser.parse_args(argv)
    if args.command == "verify":
        candidates = list(read_candidates(args.input))
        verifier = BatchVerifier()
        reports = verifier.verify_many(candidates)
        write_reports_jsonl(args.output, reports)
        write_summary_json(args.summary, verifier.summarize(reports))
