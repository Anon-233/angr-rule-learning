# Memory MVP Implementation — Design Refinements

Date: 2026-06-10

## Context

Tasks 1-5 of the verifier core memory MVP plan ([plan](../plans/2026-06-09-verifier-core-memory-mvp.md)) are complete. Register verification works through the new typed API. This document captures design refinements for Tasks 6-9 before implementation begins.

## Refinement 1: Split memory checks into a separate file

The original plan puts `check_memory_events()` into `verification/checks.py` alongside `check_register_pair()`. For higher cohesion and clearer file responsibilities:

| File | Responsibility |
|------|---------------|
| `verification/checks.py` | Register equivalence checks only (`check_register_pair`) |
| `verification/memory.py` | Memory initialization, event recording (`MemoryLayout`, `MemoryEvent`, `MemoryInitializer`, `MemoryEventRecorder`) |
| `verification/memory_checks.py` | **New file** — memory equivalence checks (`check_memory_events`) |

Each file has a single domain. SMT queries are kept close to the domain they verify.

## Refinement 2: Verifier integration order

In `SemanticVerifier.verify()`, memory checks run before register checks. This keeps the failure taxonomy clean — a candidate that fails memory validation fails with a memory reason, not a confusing register reason.

New flow:
```
1. reject flag_outputs (existing)
2. reject may_alias (new)
3. make_state × 2 (existing)
4. initialize input registers (existing)
5. MemoryInitializer.initialize() (new)
6. MemoryEventRecorder.install() × 2 (new)
7. execute × 2 (existing)
8. check_memory_events() — short-circuit on fail (new)
9. check_register_pair() × N (existing)
10. return report
```

## Refinement 3: Legacy code cleanup

Remove dead code that predates the refactored package layout:

- `src/angr_rule_learning/models.py` — old `CodeFragment`/`VerificationRequest` using `def_regs`/`init_map`
- `src/angr_rule_learning/verifier.py` — old `AngrSemanticVerifier`
- `tests/test_models.py` — tests the old API

These have no consumers. `__init__.py` and `cli.py` exclusively use the new `verification/` package.

## Git discipline

Each task (6, 7, 8, 9) gets its own commit. Commits follow the existing style:
```
<imperative summary>

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

The Codex stopping point is `f85986b`. All subsequent work is on branch `verifier-core-memory-mvp`.
