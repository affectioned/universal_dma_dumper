# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Universal DMA-based process memory dumper for Windows. Uses a DMA device (FPGA/PCILeech hardware) via MemProcFS to dump encrypted process modules by walking pages iteratively, skipping encrypted/uncommitted pages and retrying until 90% coverage is reached or the 15-minute timeout expires. Reconstructs a proper file-layout PE from the memory dump.

## Build

Build using Visual Studio 2022 (v145) — open `universal_dma_dumper.slnx` and build, or use MSBuild:

```
msbuild universal_dma_dumper.slnx /p:Configuration=Release /p:Platform=x64
```

- Target: Windows x64 console application
- Standard: C++20
- Linked libs: `leechcore.lib`, `vmm.lib` (in `universal_dma_dumper/libs/`)

## Usage

```
universal_dma_dumper.exe -name <ProcessName>
universal_dma_dumper.exe -name <ProcessName> -module <ModuleName.dll>
universal_dma_dumper.exe -name <ProcessName> -out <OutputDir>
```

Requires a connected DMA FPGA device. Output goes to `./dumps/` by default, producing:
- `<ModuleName>_raw.bin` — memory-layout dump
- `<ModuleName>_fixed.exe` or `_fixed.dll` — reconstructed file-layout PE

## Architecture

Split across multiple classes in `universal_dma_dumper/src/`:

```
src/
├── Types.h          — shared ModuleLayout struct
├── Process.h/.cpp   — FindPidByName, GetModuleInfo, GetModuleLayout
├── PageWalker.h/.cpp — page walk loop
├── PEFixer.h/.cpp   — memory→file layout PE reconstruction
└── main.cpp         — arg parsing + orchestration
```

### PageWalker

Reads 4KB pages via `VMMDLL_MemReadEx` with `VMMDLL_FLAG_ZEROPAD_ON_FAIL`. Classifies pages as valid, encrypted (`≥90%` `0xCC` bytes), or uncommitted (`0x00`). Valid pages are written in-place to a pre-allocated output file at `offset = pageAddress - moduleBase`.

**Termination** occurs when 90% page coverage is reached, the 15-minute timeout expires, or END is pressed — whichever comes first. There is no stall-based early exit; the walk keeps retrying pages that are still encrypted or uncommitted until one of these hard stops fires.

**Page acceptance** uses double-read consistency: a page must be read twice and produce identical non-invalid results before being accepted, preventing capture of pages mid-decryption.

### PEFixer

Converts the raw memory-layout dump to a proper file-layout PE. Key behaviours:

- **Section table source**: prefers `ModuleLayout.sections` fetched from MemProcFS's internal module database (cached at attach time, unaffected by the game zeroing its own headers at runtime). Falls back to the dump's in-memory headers.
- **`PointerToRawData`/`SizeOfRawData`**: always recalculated from `VirtualSize` + `FileAlignment` — never trusted from either source since protectors corrupt these.
- **Data directories**: applies `ModuleLayout.directories` from MemProcFS, then zeros the security directory and restores `.pdata` if zeroed (critical for x64 function detection in IDA).
- **Machine type fallback**: if `FileHeader.Machine` is zeroed, infers architecture from `ModuleLayout.fWoW64`, defaulting to x64.

### Process::GetModuleLayout

Calls `VMMDLL_ProcessGetSectionsW` (two-call count-then-fetch pattern) and `VMMDLL_ProcessGetDirectoriesW` to populate a `ModuleLayout`. This data comes from MemProcFS's cached analysis, not live virtual memory, making it reliable for heavily protected targets running on a separate machine.

### ModuleLayout (Types.h)

Shared struct passed from `Process` to `PEFixer`:
- `sections` — `IMAGE_SECTION_HEADER[]` from MemProcFS
- `directories` — `IMAGE_DATA_DIRECTORY[16]` from MemProcFS
- `fWoW64` — used to infer architecture when NT headers are zeroed
- `valid` — false if MemProcFS couldn't provide layout data (PEFixer falls back gracefully)

### Dependencies

- `vmmdll.h` / `vmm.lib` — MemProcFS virtual memory abstraction
- `leechcore.h` / `leechcore.lib` — underlying DMA read/write layer

Both DLLs (`vmm.dll`, `leechcore.dll`) must be present alongside the executable at runtime.
