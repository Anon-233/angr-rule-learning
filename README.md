# angr-rule-learning

`angr-rule-learning` is a Python prototype for learning binary translation
rules. The current main path is IR-kernel based constructive learning: small
LLVM IR kernels are compiled to a Guest ISA and a Host ISA, the resulting
machine-code snippets are verified with angr/Claripy, and passing snippets are
generalized into text rules.

The first target remains scalar integer rules between AArch64 and x86-64. The
verifier and rule generalizer are intentionally reusable: later kernel
synthesizers, memory kernels, branch kernels, coverage tooling, or manual rule
seeds should all feed the same candidate and report boundary.

## Current Status

Implemented:

- builtin scalar integer IR kernels for `add`, `sub`, `and`, `or`, and `xor`;
- clang-based LLVM IR compilation for Guest and Host targets;
- object extraction and conservative snippet filtering;
- ABI-based scalar register binding for AArch64 and x86-64;
- angr/Claripy semantic verification for generated candidates;
- text rule generation with typed placeholders;
- JSON/JSONL verifier utility input and report output;
- architecture capability modules for register families, fixed-role registers,
  flags, and memory operand recognition;
- legacy source/DWARF extraction modules retained for reference and reuse.

Not implemented yet:

- memory and branch IR kernels in the constructive pipeline;
- variable-shift kernels with explicit LLVM shift-domain constraints;
- rule store and coverage evaluation against a reference rule table;
- replacement of the current heuristic immediate derivation module;
- large or feedback-driven kernel corpus synthesis.

## Quick Start

Install dependencies:

```bash
uv sync
```

Run tests and lint checks:

```bash
uv run pytest
uv run ruff check
uv run ruff format --check
```

Generate rules from the builtin IR-kernel corpus:

```bash
uv run angr-rule-learning learn \
  --work-dir /tmp/angr-rule-learning-kernels \
  --rules-output /tmp/angr-rule-learning-rules.txt \
  --diagnostics /tmp/angr-rule-learning-diagnostics.json
```

Write optional candidate and report artifacts:

```bash
uv run angr-rule-learning learn \
  --work-dir /tmp/angr-rule-learning-kernels \
  --rules-output /tmp/angr-rule-learning-rules.txt \
  --diagnostics /tmp/angr-rule-learning-diagnostics.json \
  --candidates-output /tmp/angr-rule-learning-candidates.jsonl \
  --reports-output /tmp/angr-rule-learning-reports.jsonl
```

Reverse the learning direction:

```bash
uv run angr-rule-learning learn \
  --guest-arch x86-64 \
  --host-arch aarch64 \
  --work-dir /tmp/angr-rule-learning-reverse \
  --rules-output /tmp/angr-rule-learning-reverse-rules.txt \
  --diagnostics /tmp/angr-rule-learning-reverse-diagnostics.json
```

Verify an existing candidate JSON/JSONL batch directly:

```bash
uv run angr-rule-learning verify examples/aarch64_x86_64_batch.jsonl \
  --output /tmp/angr-rule-learning-report.jsonl \
  --summary /tmp/angr-rule-learning-summary.json
```

## Documentation

- [Architecture](docs/architecture.md): current package structure, data flow,
  and extension points.
- [Verifier](docs/verifier.md): semantic verifier behavior, SMT checks, memory
  model, branch scope, and known coverage limits.
- [Candidate Format](docs/candidate-format.md): input candidate JSON, report
  JSON, and batch summary schemas.
- [Rule Generalization](docs/rule-generalization.md): text rule format,
  register placeholders, and CLI usage.
- [Rule Format](docs/rule-format.md): detailed placeholder catalogue, semantic
  contract, and supported/unsupported rule patterns.

## Repository Layout

```text
src/angr_rule_learning/
  arch/          architecture identities and per-ISA semantic recognizers
  kernel/        IR-kernel synthesis, compilation, extraction, binding, pipeline
  verification/  verifier models, execution, checks, reports, and batching
  rules/         register classification, rule generalization, text formatting
  io/            JSON/JSONL readers, writers, and schema conversion
  smt/           shared bit-vector width utilities
  extraction/    legacy source/debug-info mining modules retained for reference
tests/           pytest coverage for kernel learning, verifier, rules, and CLI
examples/        small candidate batches for verifier smoke testing
docs/            architecture and format documentation
```
