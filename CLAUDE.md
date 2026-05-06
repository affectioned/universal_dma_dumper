# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Universal DMA-based process memory dumper for Windows. Uses a DMA device (FPGA/PCILeech hardware) via MemProcFS to dump encrypted process modules by walking pages iteratively, skipping encrypted/uncommitted pages and retrying until the dump stalls (no new page writes for 90 seconds) or the 15-minute hard cap expires. Reconstructs a proper file-layout PE from the memory dump.

## Build

Build using Visual Studio 2022 (v143) — open `universal_dma_dumper.slnx` and build, or use MSBuild:

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

**Termination** occurs when the dump stalls (no page writes for `kStallTimeout`, 90 s), the `kHardTimeout` 15-minute cap expires, or END is pressed — whichever comes first. The stall check uses any page write as progress: a first-read pending insert, a refined-write on hash change, or a confirmation. Once nothing is moving forward for 90 s the walk exits; the hard cap exists only as a safety ceiling.

**Page acceptance** uses double-read consistency, fingerprinted with FNV-1a 64: a page is `confirmed` (and stops being retried) only after two consecutive reads produce identical content. The first non-trivial read is written to the output buffer immediately so the file always contains the best-so-far snapshot — subsequent reads with different content overwrite that snapshot, and only matching reads promote the page to confirmed.

### PEFixer

Converts the raw memory-layout dump to a proper file-layout PE. Key behaviours:

- **Section table source**: prefers `ModuleLayout.sections` fetched from MemProcFS's internal module database (cached at attach time, unaffected by the game zeroing its own headers at runtime). Falls back to the dump's in-memory headers.
- **`PointerToRawData`/`SizeOfRawData`**: always recalculated from `VirtualSize` + `FileAlignment` — never trusted from either source since protectors corrupt these.
- **Data directories**: applies `ModuleLayout.directories` from MemProcFS, zeros the security directory, restores `.pdata` if zeroed (critical for x64 function detection in IDA), and restores `.reloc` if zeroed (some games zero the directory pointer even when the section payload is intact). Also strips `LOAD_CONFIG`, `BOUND_IMPORT`, and `DEBUG` directories — they routinely cause IDA auto-analysis to hang on dumped/protected binaries.
- **CFG-flattened anti-tamper auto-strip**: walks every executable section page-by-page and replaces any 4 KB page with ≥10% `0xE9` (JMP rel32) byte density with `0xCC` int3 fill. Anti-tamper protectors (typical of Activision/COD titles) wrap real instructions in chains of near-jumps to stall analyzers; clean x64 code averages ~1% E9 density, so 10% is well above the noise floor and uniquely identifies CFG flattening. Without this, IDA autoanalysis can wedge for hours recursing through the JMP maze when jump tables point into obfuscated regions. Done unconditionally — the user always has the unmodified `_raw.bin` to fall back on.
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
