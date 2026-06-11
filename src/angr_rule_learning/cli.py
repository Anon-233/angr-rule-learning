from __future__ import annotations

import argparse
from pathlib import Path

from angr_rule_learning.extraction.config import (
    CompileOptions,
    ExtractionConfig,
    WindowLimits,
)
from angr_rule_learning.extraction.pipeline import ExtractionPipeline
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

    extract_parser = subparsers.add_parser(
        "extract", help="compile one C source and emit verifier candidates"
    )
    extract_parser.add_argument("source", type=Path)
    extract_parser.add_argument("--work-dir", required=True, type=Path)
    extract_parser.add_argument("--output", required=True, type=Path)
    extract_parser.add_argument("--diagnostics", required=True, type=Path)
    extract_parser.add_argument("--clang", default="clang")
    extract_parser.add_argument("--optimization", default="0")
    extract_parser.add_argument("--guest-max-window", type=int, default=2)
    extract_parser.add_argument("--host-max-window", type=int, default=3)
    extract_parser.add_argument("--verify", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "verify":
        candidates = list(read_candidates(args.input))
        verifier = BatchVerifier()
        reports = verifier.verify_many(candidates)
        write_reports_jsonl(args.output, reports)
        write_summary_json(args.summary, verifier.summarize(reports))
    elif args.command == "extract":
        config = ExtractionConfig(
            source=args.source,
            work_dir=args.work_dir,
            compile_options=CompileOptions(
                clang=args.clang,
                optimization=args.optimization,
            ),
            window_limits=WindowLimits(
                guest_max=args.guest_max_window,
                host_max=args.host_max_window,
            ),
        )
        ExtractionPipeline().run(
            config,
            candidates_output=args.output,
            diagnostics_output=args.diagnostics,
            verify=args.verify,
        )
