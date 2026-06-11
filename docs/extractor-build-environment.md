# Extractor Build Environment

Date: 2026-06-11

This document records the first extractor build environment for local
development and Claude handoff work.

## Required Tooling

The extractor MVP uses clang to compile one C source file into two relocatable
object files:

- AArch64 guest object;
- x86-64 host object.

No linker is required for the MVP. The extractor reads `.text`, symbols, and
DWARF line information directly from `.o` files.

The local Apple clang installation already advertises both required backends:

```text
aarch64 - AArch64
x86-64  - 64-bit X86
```

Because the smoke source does not include system headers or call libc, no target
sysroot is needed for object-only compilation.

## Default Compile Shape

The default extractor command shape should be:

```bash
clang -target aarch64-linux-gnu -g -O0 -ffreestanding -fno-builtin -c samples/sources/smoke_int.c -o /tmp/smoke-aarch64.o
clang -target x86_64-linux-gnu -g -O0 -ffreestanding -fno-builtin -c samples/sources/smoke_int.c -o /tmp/smoke-x86_64.o
```

These are relocatable object builds. They intentionally do not use static or
dynamic linking.

## Compile Configuration Policy

The extractor implementation should keep compile settings in typed
configuration, not hard-coded inside command construction.

Required first-version settings:

- clang binary path, default `clang`;
- guest and host target names, default `aarch64` and `x86-64`;
- debug info toggle, default enabled through `-g`;
- optimization level, default `0`;
- common compile flags, default `-ffreestanding -fno-builtin`;
- optional guest-only and host-only compile flags.

The CLI should expose the clang binary and optimization level immediately.
Additional compile flags can remain API-level configuration until concrete
command-line use cases appear.

## Smoke Fixture

Use `samples/sources/smoke_int.c` for manual extractor checks. The
`samples/sources/` directory is reserved for source inputs that can later be fed
to the learning pipeline, while `examples/` remains focused on verifier
candidate examples. The smoke source is deliberately small but not trivial:

- short integer arithmetic functions;
- bitwise and shift operations;
- one conditional branch function;
- one memory load/store function for skip diagnostics;
- a small `main` function for ordinary source shape.

The fixture avoids headers and external function calls so it remains portable
across object-only cross-target builds.
