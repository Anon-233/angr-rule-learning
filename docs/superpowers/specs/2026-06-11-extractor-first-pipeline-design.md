# Extractor-First Pipeline Design

Date: 2026-06-11

## Context

The project now has a usable semantic verifier for short AArch64-to-x86-64
machine-code fragments. It accepts strict verifier candidate JSON/JSONL,
executes guest and host fragments with angr, and uses Claripy/SMT relation
checks for registers, memory events, explicit flags, and terminal conditional
branch guards.

The next pipeline stage should produce real verifier candidates from source and
compiled artifacts. The goal is not coverage scoring yet. Early coverage numbers
would be too small to guide design. The next useful step is to build a
source-to-candidate extraction path that exposes real debug-line, disassembly,
alignment, and semantic-surface problems.

## Goals

- Accept one simple C source file as the external input.
- Compile the source to guest and host object files through a fixed clang/LLVM
  flow.
- Read DWARF/debug line information and disassembly from the generated objects.
- Build alignment regions from source, function, line, and block information.
- Mine small semantic windows inside alignment regions instead of treating a
  whole source line or whole basic block as one rule candidate.
- Emit verifier candidate JSONL for windows with enough inferred semantic
  surface information.
- Emit diagnostics that quantify region quality, window sizes, skip reasons,
  and verification cost pressure.

## Non-Goals

- Do not implement rule generalization or a rule store in this stage.
- Do not implement coverage evaluation against a reference rule table.
- Do not support multi-file projects, `compile_commands.json`, arbitrary build
  systems, or linked executable extraction in the first version.
- Do not treat source lines or basic blocks as final rule granularity.
- Do not emit verifier candidates with no checks, because empty-check pass
  reports would be false positives.
- Do not solve the full memory surface inference problem before a register-only
  and branch-only extraction loop works.

## High-Level Pipeline

```text
single C source
  -> Build Driver
  -> Object Extractor
  -> Alignment Region Builder
  -> Semantic Window Miner
  -> Surface Inference
  -> Candidate JSONL Emitter
  -> Verifier Feedback
  -> Mining Diagnostics
```

The first target pair remains AArch64 guest to x86-64 host.

## Components

### Build Driver

The build driver owns compilation. First-version input is a single `.c` file and
an output work directory.

It should invoke clang with fixed, reproducible defaults:

- guest target: AArch64 object file;
- host target: x86-64 object file;
- debug information enabled with `-g`;
- low optimization by default, initially `-O0`;
- freestanding source mode with `-ffreestanding` and `-fno-builtin`;
- no linking.

The default command shape is:

```text
clang -target <target-triple> -g -O0 -ffreestanding -fno-builtin -c <source> -o <object>
```

These defaults should live in typed extraction configuration instead of being
scattered through the build driver. The first CLI should expose the clang binary
and optimization level directly. Extra common and per-side compile flags may be
configured through the API and can be exposed in the CLI once concrete use cases
appear.

The exact command should be visible in diagnostics so failed extraction runs can
be reproduced. Later versions may allow user-provided compile flags, but the
first version should keep the external input simple.

### Object Extractor

The object extractor reads each generated object and produces typed internal
records:

- functions with names and address ranges;
- disassembled instructions with address, bytes, mnemonic, operands, and size;
- source locations from DWARF line tables;
- instruction-to-source annotations.

Implementation may use LLVM tools, pyelftools, Capstone, or angr facilities, but
the rest of the pipeline should consume typed project records rather than raw
tool text. This keeps the extractor replaceable if a backend changes.

### Alignment Region Builder

Alignment regions are search spaces, not rules.

Each region should pair a guest instruction range and host instruction range
using conservative keys:

```text
source file
function name
source line or small continuous source span
block ordinal within that source span
```

The builder may use basic blocks to avoid mixing unrelated control-flow paths,
but a basic block is still only an alignment container. It should not become the
default rule candidate.

If guest and host regions cannot be paired unambiguously, the builder should
skip the region and record a reason such as `ambiguous_alignment_region` or
`missing_host_region`.

### Semantic Window Miner

The miner enumerates smaller guest/host instruction windows inside each
alignment region. Window limits are configurable, with conservative defaults:

```text
guest window size: 1..2 instructions
host window size:  1..3 instructions
```

The miner should enumerate in increasing cost order:

```text
1:1
1:2, 2:1
1:3, 2:2
2:3
```

The exact order should be generated from configuration rather than hard-coded
only for the default limits.

The miner must not default to validating whole source-line or whole-block
windows. Large windows are fallback candidates only when smaller windows cannot
explain the same guest/host instruction ranges.

The miner should be driven by a staged controller:

1. enumerate the next lowest-cost window stage;
2. infer semantic surfaces and emit verifier candidates for that stage;
3. run the existing batch verifier or consume its reports;
4. record verified passing windows;
5. use those passing windows to prune pure composite windows in later stages.

A candidate-only mode may emit windows without running the verifier, but that
mode cannot apply verified-window subsumption. It should record the enumeration
stage and window metadata so later tooling can apply the same pruning after
verification.

### Subsumption And Atomicity

The learning goal is to find atomic semantic rules, not composites. A large
window should be skipped as a pure composite only after verifier feedback proves
that both sides can already be fully explained by smaller windows.

Precise rule:

> For a candidate large window, skip it only if its guest instruction interval
> and host instruction interval can both be covered by previously verified
> smaller windows in order, with no overlap and no gaps.

Examples:

```text
G1 <=> H1
G2 <=> H2
G3 <=> H3
```

If those three smaller windows pass, then:

```text
G1 G2 G3 <=> H1 H2 H3
```

is a pure composite and should not be learned as another rule.

But if no smaller windows explain:

```text
G1 G2 <=> H1
```

then the `2:1` window is a real minimal candidate and should be emitted for
verification.

Subsumption should therefore reduce composite rules without preventing `1:N`,
`M:1`, or small `M:N` atomic rules from being learned.

Verified-window coverage should be tracked per alignment region. It should not
cross region boundaries, because source/debug alignment is part of the evidence
that the guest and host windows are related.

### Surface Inference

Surface inference converts a mined window into verifier candidate fields:

- `inputs.registers`;
- `outputs.registers`;
- `outputs.flags`;
- `memory`;
- `preconditions`;
- `clobbers`.

The first implementation should be conservative:

- infer register inputs as registers read before they are written inside the
  window;
- infer register outputs as registers written by the window and still meaningful
  at the window boundary;
- infer explicit flags only when both architectures expose supported flag names;
- preserve terminal conditional branch windows so the verifier can compare
  branch guards;
- skip windows with memory access unless the memory binding and expected access
  can be represented safely in the existing verifier schema.

If no semantic surface can be inferred, the window must be skipped with
`no_verifiable_surface`. It must not be emitted as a verifier candidate.

Memory inference should be developed incrementally after register-only windows
and branch windows are stable. The verifier already supports memory checks, but
extracting correct stack/global/pointer bindings from arbitrary compiled C is a
separate problem.

### Candidate Emitter

The emitter writes verifier-compatible JSONL. Every emitted candidate should be
valid according to `docs/candidate-format.md` and should include enough
semantic surfaces to avoid empty-check pass reports.

Candidate identifiers should be stable and traceable:

```text
<source-stem>:<function>:<source-span>:<region-ordinal>:<guest-window>:<host-window>
```

The exact spelling may change, but it must identify the source, function,
region, and window boundaries.

Candidates should include enough stable metadata in their identifiers or a side
diagnostic map to recover:

- alignment region id;
- enumeration stage;
- guest instruction interval;
- host instruction interval;
- source span.

This metadata is required for verifier-feedback pruning and for diagnosing why
large windows were emitted or skipped.

### Mining Diagnostics

Diagnostics are a first-class output. Each run should write a JSON summary that
helps decide whether the window strategy is cost-effective.

Required metrics:

- number of functions discovered;
- number of aligned regions;
- number of ambiguous or skipped regions;
- windows enumerated;
- windows emitted;
- windows verified;
- windows verified as pass;
- windows skipped by reason;
- mean guest window size;
- mean host window size;
- p95 guest window size;
- p95 host window size;
- max guest window size;
- max host window size;
- verifier candidates produced by semantic surface kind.

Example:

```json
{
  "functions": 12,
  "regions": 128,
  "regions_skipped": 17,
  "windows_enumerated": 940,
  "windows_emitted": 312,
  "windows_verified": 312,
  "windows_verified_pass": 104,
  "mean_guest_window_size": 1.34,
  "mean_host_window_size": 1.71,
  "p95_guest_window_size": 2,
  "p95_host_window_size": 3,
  "max_guest_window_size": 2,
  "max_host_window_size": 3,
  "skip_reasons": {
    "subsumed_by_smaller_window": 420,
    "contains_unsupported_control_flow": 51,
    "ambiguous_alignment_region": 37,
    "no_verifiable_surface": 120
  },
  "surface_kinds": {
    "register": 280,
    "branch": 32,
    "memory": 0
  }
}
```

These metrics are not coverage evaluation. They are extractor/miner health
signals. If average windows stay small, the default enumeration bounds are
probably acceptable. If windows frequently hit the configured maximum or the
enumerated-to-emitted ratio is high, the miner needs stronger pruning. If
verified-pass windows are mostly large, the default window limits or surface
inference strategy should be revisited.

## Error Handling

The pipeline should distinguish:

- build failures;
- object parsing failures;
- missing debug line information;
- ambiguous alignment;
- unsupported control-flow or memory shapes;
- no verifiable semantic surface;
- verifier-incompatible candidate generation bugs.
- verifier feedback ingestion failures.

Build and parser failures should stop the run. Region and window problems should
usually be recorded in diagnostics and skipped so the extractor can still emit
other candidates.

## Testing Strategy

Tests should start with small single-file C fixtures that compile quickly, avoid
external headers or libc calls, and exercise one concept at a time:

- pure register arithmetic;
- one-to-one instruction mappings;
- one-to-many and many-to-one mappings;
- terminal conditional branch;
- source lines that produce multiple blocks;
- ambiguous source/debug mapping;
- windows with memory access that should be skipped in the first version.

The repository should keep `samples/sources/smoke_int.c` as the default manual
smoke fixture. The `samples/sources/` directory is reserved for source inputs
that can later be fed to the learning pipeline, while `examples/` remains
focused on verifier candidate examples. The smoke fixture intentionally includes
several short integer functions, one simple branch function, one memory function
for skip diagnostics, and a small `main` function, while remaining compilable as
an object without linking.

Each component should have focused tests:

- build driver command construction and artifact detection;
- object extractor instruction/source annotation records;
- alignment region pairing and ambiguity diagnostics;
- bounded window enumeration order;
- subsumption behavior for composite windows;
- staged verifier-feedback pruning;
- surface inference skip behavior for no-surface and unsupported-memory windows;
- JSONL candidate emission accepted by existing schema readers.

End-to-end tests should compile a tiny C file, emit candidate JSONL, run the
existing batch verifier, and inspect both reports and mining diagnostics.

## Development Order

1. Add extractor data models and diagnostics schema.
2. Add build driver for fixed single-source clang/LLVM compilation.
3. Add object extraction for functions, instructions, and source locations.
4. Add alignment region builder.
5. Add bounded window miner with configurable limits and statistics.
6. Add conservative surface inference for register and branch windows.
7. Add candidate JSONL and diagnostics emitters.
8. Add staged verifier feedback ingestion and composite-window pruning.
9. Add an end-to-end extractor CLI/API entry point.

This order creates a real source-to-candidate path before rule generalization
and coverage scoring are introduced.
