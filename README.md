# universal_dma_dumper

DMA-based process dumper for Windows. Walks memory page-by-page with retry logic for encrypted / lazily-decrypted pages, and reconstructs a proper file-layout PE from the raw dump.

Original page-walker logic by [zarboz on UnknownCheats](https://www.unknowncheats.me/forum/4595235-post1774.html).

> **Disclaimer.** Educational use only — reverse engineering and malware analysis on software you own or have explicit permission to analyse.

## Requirements

- Windows x64, Visual Studio 2022, C++20
- DMA device (FPGA / PCILeech)
- [MemProcFS](https://github.com/ufrisk/MemProcFS/releases) — `vmmdll.{h,lib}`, `leechcore.{h,lib}`

## Usage

```
universal_dma_dumper.exe -name <ProcessName> [-module <Name|Regex>] [-out <dir>]
universal_dma_dumper.exe -name <ProcessName> -base 0x<VA> [-size 0x<N>]
universal_dma_dumper.exe -name <ProcessName> -scan-hidden
universal_dma_dumper.exe -name <ProcessName> -watch-hidden [-watch-interval <ms>] [-max-concurrent <N>] [-watch-all] [-min-size <bytes>] [-dump-baseline]
universal_dma_dumper.exe -name <ProcessName> -list-modules | -list-unloaded
universal_dma_dumper.exe -list-drivers
```

| Flag | Purpose |
|---|---|
| `-name` | Target process (or `System` for kernel drivers). Required except with `-list-drivers` (which defaults to `System`) |
| `-module` | Exact name or regex. Defaults to the process executable |
| `-base` / `-size` | Dump an arbitrary VA range. `-size` auto-derived from PE header when omitted |
| `-out` | Output directory (default `./dumps`) |
| `-scan-hidden` | One-shot VAD scan for private + executable regions outside the module map |
| `-watch-hidden` | Continuous `-scan-hidden`; auto-dumps every new `MZ`-flagged region |
| `-watch-interval` | Watch scan cadence in ms (default `250`) |
| `-max-concurrent` | Concurrent background dumps under `-watch-hidden` (default `4`) |
| `-watch-all` | Also auto-dump non-`MZ` regions (for manual-mappers that wipe the PE header post-load). PE fix will fail — raw `.bin` is preserved for manual reconstruction |
| `-min-size` | Log/dump noise floor in bytes (default `0x40000` = 256 KB). Filters JIT trampoline pool pages. MZ candidates always pass regardless of size |
| `-dump-baseline` | Also dump every region present at startup (subject to `-watch-all` / `-min-size`). Use when the target module was mapped **before** the watcher started — helpers that init during game/Steam startup are the common case. Baseline entries log as `b 0x…` instead of `+ 0x…` |
| `-list-modules` | Module table with a **TP** column (`NORMAL` / `DATA` / `NOTLINK` / `INJECT`) |
| `-list-unloaded` | Loader's unloaded-module ring (or `MmUnloadedDrivers` for `System`) |
| `-list-drivers` | Kernel drivers (PID 4 modules) |

Press **END** to stop; the PE fix runs on whatever was collected.

## Workflows

**Dump a normal module** — the process's main image, a loaded DLL, or a kernel driver:

```
universal_dma_dumper.exe -name game.exe
universal_dma_dumper.exe -name game.exe -module engine.dll
universal_dma_dumper.exe -name System   -module ntoskrnl.exe
```

**Find a manually-mapped module** — regions allocated with `VirtualAlloc` + section-copy that then unlink from the PEB loader lists. `-list-modules` catches whatever MemProcFS still classifies as `NOTLINK` / `INJECT`; `-scan-hidden` catches the rest via a VAD walk filtered to `fPrivateMemory && executable-protection && !stack/TEB && !covered-by-module-map`:

```
universal_dma_dumper.exe -name game.exe -scan-hidden

  BASE                VADSIZE  PROT  MZ  PESIZE     VADHINT
  ----------------------------------------------------------------
  0x000001C4A0000000  0x0600000 RWX-  MZ  0x05E0000  (no name)
  0x000001C4A0800000  0x0002000 RWX-  -   -          (no name)

universal_dma_dumper.exe -name game.exe -base 0x000001C4A0000000
```

Regions where the first page still holds a parseable PE header are ranked first and annotated with `SizeOfImage`.

**Catch short-lived regions** — some modules exist for less than a second. `-watch-hidden` loops the scan (default 250 ms) with the same MemProcFS handle for speed, baselines everything present at startup, and auto-dumps every new `MZ` region as it appears. Runs until **END**.

```
universal_dma_dumper.exe -name game.exe -watch-hidden -out ./captures
```

Event lines are timestamped: `+ 0x…` appearance, `v 0x…` dump completed, `- 0x…` vanished, `! 0x…` skipped/failed.

## How it works

### Page walker

Some binaries decrypt code pages on demand at runtime. A single-shot read gets a mix of real code, encrypted (`0xCC`), and uncommitted (`0x00`) pages. The walker instead:

- Iterates only committed pages via `VMMDLL_Map_GetPteW` (skips vast uncommitted ranges on large protected modules)
- Pre-allocates the output at full module size, writes each page in-place at `VA − base`
- Reads with `VMMDLL_FLAG_ZEROPAD_ON_FAIL`; retries `0xCC` (encrypted) indefinitely and `0x00` (uncommitted) up to 5 passes before evicting
- FNV-1a fingerprints each page and requires two consecutive matching reads before marking *confirmed* — pages that keep changing are refined every pass
- Stops on 90 s stall, 15 min hard cap, or **END**

For games that decrypt only during active play, run the tool while actively playing.

### PE reconstruction

Rebuilds a file-layout PE (`_raw.bin` → `_fixed.exe`/`.dll`/`.sys`):

- **Headers.** Section table and data directories pulled from MemProcFS's cache (`VMMDLL_ProcessGetSections`/`Directories`), which survives the protector zeroing the in-memory headers. Machine type falls back to `fWoW64` when zeroed.
- **Section layout.** `PointerToRawData` / `SizeOfRawData` recomputed from `VirtualSize` + `FileAlignment`.
- **Data directories.** Security zeroed; `.pdata` and `.reloc` restored from the section table if the directory pointer is missing; `.reloc` cleared when payload is all zero (post-load protector wipe). `LOAD_CONFIG`, `BOUND_IMPORT`, `DEBUG` stripped — they routinely stall IDA on dumped/protected PEs.
- **CFG-flatten auto-strip.** Executable pages with ≥10% `0xE9` density (well above the ~1% clean-x64 baseline) are overwritten with `0xCC` so IDA abandons them at the first byte instead of wedging on the phantom basic-block graph. Raw `.bin` still holds the untouched bytes.
- **Import rebuild.** IAT/import directories are reconstructed from the live process.

Direct-VA dumps (`-base`, `-watch-hidden`) skip the MemProcFS layout cache and fall back to the dump's own PE headers — works when the manual-mapper left them intact (the common case).

## Output

```
dumps/
├── <name>_raw.bin      # raw memory-layout dump
└── <name>_fixed.<ext>  # reconstructed file-layout PE

<exe-dir>/universal_dma_dumper.log
```

Extension follows the module name (`engine.dll` → `_fixed.dll`, `driver.sys` → `_fixed.sys`, otherwise `_fixed.exe`). Hidden-region dumps are named `hidden_<VA>_raw.bin` / `_fixed.dll`. Open the fixed file directly in IDA, Ghidra, or x64dbg.
