# angr-rule-learning

`angr-rule-learning` is a Python prototype for learning and validating binary
translation rules. The current implementation focuses on the semantic verifier:
it accepts paired guest/host machine-code fragments, executes them with angr,
and uses Claripy/SMT checks to decide whether the requested semantic surfaces
are equivalent.

The first supported rule-learning target is AArch64 integer fragments translated
to x86-64 integer fragments. The package is intentionally API-first so future
candidate extraction, rule generalization, rule storage, and coverage evaluation
can reuse the verifier without shelling out to the CLI.

## Current Status

Implemented:

- typed verifier candidate and report models;
- JSON/JSONL candidate input and JSON report/summary output;
- batch verifier API and CLI wrapper;
- AArch64 and x86-64 shellcode execution through angr;
- shared symbolic input register initialization;
- SMT relation checks for register outputs, memory events, explicit flags, and
  terminal conditional branch guards;
- memory slots, address bindings, load/store events, `must_alias`, and
  `may_alias` unsupported reporting;
- four-state diagnostics: `pass`, `fail`, `unsupported`, and `error`.

Not implemented yet:

- compiler/debug-info based candidate extraction;
- rule generalization and rule store;
- coverage evaluation against a reference rule table;
- precondition solving;
- branch target equivalence for direct or indirect branches.

## Quick Start

Install dependencies with uv:

```bash
uv sync
```

Run the test suite:

```bash
uv run pytest
```

Run lint and formatting checks:

```bash
uv run ruff check
uv run ruff format --check
```

Verify the example JSONL batch:

```bash
uv run angr-rule-learning verify examples/aarch64_x86_64_batch.jsonl \
  --output /tmp/angr-rule-learning-report.jsonl \
  --summary /tmp/angr-rule-learning-summary.json
```

Extract verifier candidates from one C source file:

```bash
uv run angr-rule-learning extract samples/sources/smoke_int.c \
  --work-dir /tmp/angr-rule-learning-extract \
  --output /tmp/angr-rule-learning-candidates.jsonl \
  --diagnostics /tmp/angr-rule-learning-diagnostics.json \
  --optimization 0
```

The CLI is a thin wrapper around `BatchVerifier`. Pipeline code should call the
Python API directly.

## Documentation

- [Architecture](docs/architecture.md): current package structure, data flow,
  and extension points.
- [Verifier](docs/verifier.md): semantic verifier behavior, SMT checks, memory
  model, branch scope, and known coverage limits.
- [Candidate Format](docs/candidate-format.md): input candidate JSON, report
  JSON, and batch summary schemas.

## Repository Layout

```text
src/angr_rule_learning/
  arch/          architecture-name and flag helpers
  io/            JSON/JSONL readers, writers, and schema conversion
  smt/           shared bit-vector width utilities
  verification/  verifier models, execution, checks, reports, and batching
tests/           pytest coverage for verifier behavior and CLI output
examples/        small candidate batches for smoke testing
docs/            architecture and format documentation
```
