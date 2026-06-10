# CLAUDE.md

This file provides stable guidance for AI coding agents working in this
repository. It should describe durable engineering rules, not the current
implementation inventory. Feature status, package maps, and task progress belong
in README files, design docs, plans, or commit history.

## Project Direction

This repository rebuilds a binary translation rule-learning pipeline around an
angr-backed semantic verifier. The verifier compares short guest and host
machine-code fragments by constructing shared symbolic inputs, executing both
fragments, and using SMT queries to check whether observable outputs can differ.

Keep the project API-first:

- Pipeline code should call typed Python APIs directly.
- The CLI is an external convenience wrapper, not the core integration surface.
- JSON/JSONL is an external boundary for tools and batch data exchange.
- Verifier internals should work with typed models, not raw JSON dictionaries.

## Architecture Principles

- Keep schema parsing and report serialization isolated under `io/`.
- Keep execution, memory modeling, SMT checks, and batch aggregation separated by
  responsibility.
- Prefer small, explicit dataclasses and focused functions over broad dynamic
  dictionaries.
- Treat unsupported semantic features explicitly. Return or report
  `unsupported` rather than silently ignoring accepted input fields.
- Do not add legacy schema compatibility unless it is explicitly requested. If a
  legacy importer becomes necessary, implement it as a separate converter that
  emits the current typed model.
- Preserve strict validation at external boundaries. Unknown external fields
  should fail loudly.
- Keep failure reasons stable and machine-readable; downstream rule coverage and
  quality analysis depend on them.

## Verification Discipline

- Use test-driven development for behavior changes and bug fixes: write the
  failing regression test first, confirm it fails for the right reason, then
  implement the minimal fix.
- Run formatting after Python edits:

```bash
uv run ruff format
```

- Run lint and tests before claiming work is complete:

```bash
uv run ruff check
uv run pytest
```

- When changing CLI behavior, run an end-to-end CLI smoke test as well as the
  Python test suite.
- Treat third-party Python deprecation warnings separately from project
  failures, but do not ignore project warnings or stderr noise from normal CLI
  usage.
- If a test passes immediately after being added, verify that it actually
  exercises the intended missing behavior.

## Code Style

- Follow existing project structure and naming before introducing new
  abstractions.
- Keep JSON handling centralized; do not scatter ad hoc JSON parsing or
  serialization across verifier logic.
- Prefer structured APIs and Claripy/angr primitives over string parsing for
  symbolic values, expressions, and machine state.
- Keep changes scoped to the current task. Avoid unrelated refactors in the same
  commit unless they are required to make the task correct.
- Use comments sparingly, only where they clarify non-obvious verifier or SMT
  behavior.
- Do not commit generated files such as `__pycache__`, `.pyc`, coverage output,
  or virtual-environment contents.

## Documentation Rules

- Keep this file stable and policy-oriented.
- Record feature status and examples in README or design documents, not here.
- Update docs when public schemas, CLI usage, or verifier semantics change.
- Do not leave examples that use rejected legacy fields.
- Prefer documenting semantic contracts and invariants over listing every file
  in the current package layout.

## Git Hygiene

- Work on feature branches for implementation work.
- Keep commits focused and use imperative commit messages.
- Do not rewrite or revert unrelated user changes.
- Before committing, check the worktree and review the diff for accidental
  generated files or unrelated edits.
