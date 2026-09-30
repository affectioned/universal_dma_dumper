# universal_dma_dumper

Universal DMA-based process dumper for Windows. Walks memory page by page with encryption-aware retry logic and reconstructs a proper PE file from the dump.

Original page walker logic by [zarboz on UnknownCheats](https://www.unknowncheats.me/forum/4595235-post1774.html).

> **Disclaimer:** This tool is intended strictly for educational purposes — reverse engineering, malware analysis, and understanding how executable formats and memory management work at a low level. Do not use this tool on software you do not own or have explicit permission to analyse. The author takes no responsibility for any misuse.

---

## Requirements

- Windows x64
- DMA device (FPGA / PCILeech)
- [MemProcFS](https://github.com/ufrisk/MemProcFS/releases) — `vmmdll.h`, `vmmdll.lib`, `leechcore.h`, `leechcore.lib`
- Visual Studio 2022 with C++20

---

## Usage

```
universal_dma_dumper.exe -name <ProcessName>
universal_dma_dumper.exe -name <ProcessName> -module <ModuleName.dll>
universal_dma_dumper.exe -name <ProcessName> -base 0x<VA> [-size 0x<N>]
universal_dma_dumper.exe -name <ProcessName> -out <dir>
universal_dma_dumper.exe -list-drivers
universal_dma_dumper.exe -name <ProcessName> -list-modules
universal_dma_dumper.exe -name <ProcessName> -list-unloaded
universal_dma_dumper.exe -name <ProcessName> -scan-hidden
universal_dma_dumper.exe -name <ProcessName> -watch-hidden [-watch-interval <ms>] [-max-concurrent <N>]
```

| Argument | Description |
|---|---|
| `-name` | Target process name (e.g. `game.exe`) — required unless `-list-drivers` is used |
| `-module` | Module to dump — exact name or regex pattern (e.g. `engine.dll`, `elytra.*`). Defaults to the process executable |
| `-base` | Dump an arbitrary VA range directly (no module lookup). Use with `-scan-hidden` output for manually-mapped modules |
| `-size` | Byte length of the `-base` range. Optional — auto-derived from `OptionalHeader.SizeOfImage` when the range begins with an `MZ/PE` header |
| `-out` | Output directory. Defaults to `./dumps` |
| `-list-drivers` | Enumerate every loaded kernel driver (PID 4) and exit. `-name` defaults to `System` |
| `-list-modules` | Enumerate every module in the given process and exit. Includes a **TP** column so MemProcFS-identified `NOTLINKED` / `INJECTED` modules are visible without a hidden scan |
| `-list-unloaded` | Dump the process's unloaded-module ring (or the kernel's `MmUnloadedDrivers` list when `-name System`). Useful for scan modules with a lifetime shorter than one `-list-modules` poll |
| `-scan-hidden` | Single VAD scan for **manually-mapped modules**: private + executable regions not covered by any entry in the module map (VAC scan modules, most kernel-mode cheat protections, some info-stealer loaders). Regions whose first page still holds a valid PE header are marked `MZ` and their `SizeOfImage` is reported so `-base` can auto-derive `-size` |
| `-watch-hidden` | **Continuous** `-scan-hidden` with auto-dump. Baselines the hidden set at startup so long-lived JIT/runtime arenas are ignored, then dumps every new `MZ`-flagged region to `-out` as it appears — designed for catching short-lived scan modules that vanish before a manual dump can be issued. Runs until END is pressed |
| `-watch-interval` | Sleep between scans in ms (default `250`). Lower = better chance of catching sub-second appearances; higher = less DMA bandwidth |
| `-max-concurrent` | Simultaneous background dumps allowed (default `4`). Additional appearances above the cap are logged as `!` skipped |

Press **END** to stop the dump early. The PE fix will still run on whatever was collected.

### Listing modules

`-list-drivers`, `-list-modules` and `-list-unloaded` print a table (base, size, IAT count, TP, name, company, path) sorted by name — useful when you know a target is loaded but don't know its exact filename (kernel driver names sometimes rotate per install; usermode loaders sometimes hide behind generic filenames).

The **TP** column reflects MemProcFS's classification of each module:

| TP | Meaning |
|---|---|
| `NORMAL` | Regular loader-linked module |
| `DATA` | Non-executable image-backed mapping (resource-only DLL etc.) |
| `NOTLINK` | PE image identified in a VAD but missing from `InLoadOrderModuleList` / `InMemoryOrderModuleList` |
| `INJECT` | Loader entry present but MemProcFS flagged it as an injected image (e.g. `LdrpProcessMappedModule` inconsistency) |

`NOTLINK` and `INJECT` rows are exactly the manually-mapped modules that older versions of this tool missed. If a target is fully stealth (PE header wiped + not identifiable via image structure), it still won't appear here — that's what `-scan-hidden` is for.

### Catching manually-mapped modules

Anti-cheat scan modules (VAC's runtime scanner, EasyAntiCheat's user-mode component in a few titles, etc.) are commonly loaded by the parent process into `MEM_PRIVATE` executable memory via `VirtualAlloc` + section-by-section copy, then have their `LDR_DATA_TABLE_ENTRY` unlinked from the PEB's three loader lists so a naïve `EnumProcessModules` / `MODULEENTRY32` walk cannot see them. Same technique is used by manual-map cheat loaders and most modern info-stealers.

`-scan-hidden` walks the VAD tree with MemProcFS's `fIdentifyModules=TRUE` and prints every VAD that is:

- `fPrivateMemory=1` (allocated, not backed by a mapped file/image)
- Executable protection (any of `MM_EXECUTE`, `MM_EXECUTE_READ`, `MM_EXECUTE_READWRITE`, `MM_EXECUTE_WRITECOPY`)
- Not a stack / TEB
- Not covered by any entry in the loader's module map

Regions where the first page still carries a parseable PE header are ranked to the top and annotated with `SizeOfImage`. Typical workflow:

```
universal_dma_dumper.exe -name deadlock.exe -scan-hidden

  BASE                VADSIZE  PROT   MZ   PESIZE     VADHINT
  ----------------------------------------------------------------
  0x00007FFBAABB0000  0x1985000 R-X-  MZ   0x1985000  steamclient64.dll
  0x000001C4A0000000  0x0600000 RWX-  MZ   0x05E0000  (no name)
  0x000001C4A0800000  0x0002000 RWX-  -    -          (no name)
  ...

universal_dma_dumper.exe -name deadlock.exe -base 0x000001C4A0000000
```

With `-base` and no `-size`, the tool probes the PE header and uses `OptionalHeader.SizeOfImage`. Pass an explicit `-size` when the header has been erased post-load.

### Dumping kernel drivers

MemProcFS exposes loaded kernel drivers as modules of the `System` process (PID 4), so the same pipeline works — point `-name` at `System` and `-module` at the driver's filename:

```
universal_dma_dumper.exe -name System -module ntoskrnl.exe
universal_dma_dumper.exe -name System -module EasyAntiCheat_EOSSys.sys
```

---

## How it works

### 1. Page walker

Some games encrypt their code pages at rest and decrypt them on demand at runtime — done by the developers, not anti-cheat. A naive single-shot read captures a mix of real code and encrypted or uncommitted pages, making the dump largely useless.

The page walker reads the module one 4 KB page at a time in a continuous retry loop:

1. **PTE-map filter.** `VMMDLL_Map_GetPteW` enumerates every committed page in the module's VA range; the walk iterates only those instead of the whole image, eliminating hundreds of thousands of uncommitted pages on large protected modules. Falls back to a linear walk if unavailable.
2. The output file is pre-allocated to the full module size and zero-filled, so pages can be written in-place at their correct offsets.
3. Each page is read with `VMMDLL_MemReadEx` + `VMMDLL_FLAG_ZEROPAD_ON_FAIL`, returning zeros for unreadable pages instead of failing.
4. All-`0x00` (uncommitted) and all-`0xCC` (encrypted) pages are skipped and retried next pass. A page that reads zeros five consecutive passes is dropped from the rotation so the stall timer can fire on real inactivity; `0xCC` pages are retried indefinitely.
5. Candidate pages are FNV-1a fingerprinted and read **twice** — the first non-trivial read is written immediately so the file is always "best-so-far", and the page is only marked *confirmed* once two consecutive reads match. Pages whose content keeps changing are treated as still-decrypting and refined each pass.
6. Accepted pages are written at `offset = pageAddress - moduleBase`.

**Termination:** the walk stops when it stalls (no page writes for 90 s), the 15-minute hard cap expires, or **END** is pressed.

> For games where pages decrypt only during active gameplay (e.g. in-match but not in menus), run the tool while actively playing to maximise coverage.

The result is a raw `.bin` file containing the module in its virtual memory layout, plus a `universal_dma_dumper.log` next to the exe.

---

### 2. PE reconstruction (`_raw.bin` → `_fixed.exe`)

The raw dump cannot be opened directly in IDA because it is in **memory layout** (section data at `VirtualAddress` / RVA), not **file layout** (section data at `PointerToRawData`). The fix step rebuilds a proper file-layout PE and repairs several things that routinely break analyzers on protected dumps:

**Header source** — Protectors zero the in-memory section table and data directories at runtime to defeat memory dumpers. The tool pulls this data from MemProcFS's internal module cache (`VMMDLL_ProcessGetSections`, `VMMDLL_ProcessGetDirectories`), populated at attach time and independent of the process's live memory — so it remains valid after the game has wiped its own headers. No disk access to the game's files is required; this works over DMA from a second PC. Machine type falls back to the `fWoW64` flag when the in-memory `FileHeader.Machine` is zeroed.

**Layout recalculation** — `PointerToRawData` and `SizeOfRawData` are recalculated from `VirtualSize` and `FileAlignment` rather than trusting header values, which protectors also corrupt.

**Data directories**
- **Security** — zeroed (authenticode is invalid after reconstruction).
- **Exception** (`.pdata`) — restored from the section table if missing; entries with zero/inverted addresses, addresses outside executable sections, or pointers into int3-stripped pages (see below) are dropped.
- **Base relocation** — restored from the section table if missing. If the `.reloc` payload is all zeros (protectors commonly wipe it post-load), the directory entry is cleared so IDA's relocation pass becomes a no-op instead of dereferencing a dangling pointer.
- **LOAD_CONFIG**, **BOUND_IMPORT**, **DEBUG** — stripped. Corrupted CFG/SEH counts make IDA walk millions of phantom guard-CF targets; bound imports are always stale on a runtime dump; stale CodeView pointers stall symbol load.

**CFG-flattened anti-tamper auto-strip** — Anti-tamper protectors (typical of Activision/COD titles) wrap real instructions in chains of `JMP rel32` (`0xE9 ..`) to explode the basic-block graph. Clean x64 code averages ~1% E9 density; CFG-flattened pages reach 12-15%. Every executable page with ≥10% `0xE9` density is overwritten with `0xCC` int3 fill so IDA's code check fails at the first byte and the analyzer abandons the target instead of wedging for hours. The unmodified `_raw.bin` is always available to fall back on.

---

## Output

```
dumps/
├── <ModuleName>_raw.bin      # raw memory-layout dump
└── <ModuleName>_fixed.exe    # reconstructed file-layout PE  (or _fixed.dll / _fixed.sys)

<exe-dir>/universal_dma_dumper.log    # full session output
```

The output extension is preserved from the module name — `engine.dll` → `engine_fixed.dll`, `driver.sys` → `driver_fixed.sys`, otherwise `_fixed.exe`. Open the fixed file in IDA, Ghidra, or x64dbg directly.
