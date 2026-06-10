# angr-rule-learning

This is a new Python implementation of the binary translation rule learning
pipeline. The old implementation is preserved outside this subproject at:

```text
../legacy_original_20260609
```

The first milestone is an angr-backed semantic verifier for AArch64 integer
rules targeting x86-64. It accepts concrete guest/host machine-code fragments,
injects shared symbolic inputs with Claripy, executes both fragments with
angr, and proves output equivalence by asking whether a difference is
satisfiable.

## Current Scope

Implemented:

- AArch64 and x86-64 shellcode fragments
- register initialization mapping
- register output equivalence checks
- memory slot initialization and load/store event checks
- `must_alias` memory slots and `may_alias` unsupported reporting
- JSON/JSONL request/result boundary for future pipeline integration
- batch CLI wrapper around the Python verifier API

Not implemented yet:

- precondition solving
- branch guard equivalence
- flags / condition code mapping
- candidate extraction from compiler debug information
- rule generalization and rule store

## Usage

Run tests:

```bash
uv run pytest
```

Verify a JSONL batch:

```bash
uv run angr-rule-learning verify examples/aarch64_x86_64_batch.jsonl --output report.jsonl --summary summary.json
```

The CLI is an external wrapper around the Python verifier API. Full pipeline
code should call `SemanticVerifier` or `BatchVerifier` directly instead of
shelling out to the CLI.

## Design Direction

The new system should keep data boundaries explicit:

- compiler/candidate extraction produces structured candidate JSON
- the semantic verifier consumes candidate JSON and emits structured JSON
- rule generalization consumes successful verifier results
- evaluation reports coverage, pass/fail reasons, and rule usefulness
- coverage can be computed against the existing complete AArch64 -> x86-64
  integer rule table

This avoids the old implementation's dependency on parsing fragile textual
logs from the symbolic execution engine.
