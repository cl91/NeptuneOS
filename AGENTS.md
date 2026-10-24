# Repository Guidelines

## Project Structure & Module Organization

Neptune OS is a CMake-based, seL4-backed NT-like operating system.

- `private/`: NT Executive and all direct seL4 interfaces.
- `public/`: shared CRT, NDK, DDK, POSIX, and SDK headers.
- `base/`, `win32/`, `posix/`, `drivers/`: clients, subsystems, and drivers.
- `tools/` and `docs/`: build utilities and architecture notes.
- `sel4/` and `drivers/linux*`: submodules; avoid vendored changes.

Only `private/` may include seL4 headers or call seL4 directly. Do not edit generated headers or `build-*/` outputs.

## Build, Test, and Development Commands

Install LLVM/Clang/lld, `cpio`, `jq`, Python dependencies, and image tools from `readme.md`; initialize submodules with `git submodule update --init --recursive`.

- `./build.sh [amd64] [release]` builds all targets and generates merged `compile_commands.json`; defaults are i386 and debug.
- `./mkhdd.sh [amd64] [release]` creates a BIOS boot disk image.
- `./mkiso.sh [amd64] [release]` creates a bootable ISO.
- `./run.sh direct amd64 release` starts QEMU with the kernel and NT Executive directly.
- `./run.sh nvme amd64 release` boots the generated NVMe disk image. Add `uefi` for UEFI boot.

## Coding Style & Naming Conventions

Use C11 and `.clang-format`: tab indentation, 90-column lines, braces after functions, preserved include order. Run `clang-format -i <files>` on touched C/header files. Apply `.clang-tidy` when available; there is no project-wide lint script.

Use PascalCase for functions, variables, parameters, and members; UPPER_CASE for structs and macros. NT names such as `P`, `ULONG`, and `NTSTATUS` are accepted. Keep CMake targets and source basenames lowercase (`i8042prt.c`, `storport.sys`).

## Testing Guidelines

There is no CTest or host-level automated test target and no coverage threshold. `base/umtests` is the custom in-guest harness; new `.c` files are collected automatically. Name tests `Test<Component>` and call them from `NtProcessStartup` in `base/umtests/umtests.c`.

Build with `./build.sh`, boot with `./run.sh`, and execute `umtests.exe` from the native shell. Report serial or QEMU evidence. Add cases under `private/ntos/src/tests` for core Executive changes; they are gated by `CONFIG_RUN_TESTS`.

## Commit & Pull Request Guidelines

History follows `subsystem: imperative summary`, such as `ntos/mm: fix ...` or `wdm: recheck ...`. Keep commits subsystem-focused and explain the problem and changed behavior.

PRs should explain the approach, list build/test configurations, link applicable issues, and attach serial/QEMU logs for boot or driver changes. Include screenshots for visible changes; no PR template exists. Per project policy, do not submit vibe-coded or LLM-generated pull requests or issues; authors must understand and verify every change.
