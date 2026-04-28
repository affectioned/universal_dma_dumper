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

## Project structure

```
universal_dma_dumper/
├── libs/
│   ├── leechcore.lib
│   ├── leechcore.h
│   ├── vmm.lib
│   └── vmmdll.h
├── src/
│   ├── main.cpp
│   ├── Types.h
│   ├── Process.h / Process.cpp
│   ├── PageWalker.h / PageWalker.cpp
│   ├── PEFixer.h / PEFixer.cpp
│   ├── pch.h / pch.cpp
└── README.md
```

---

## Usage

```
universal_dma_dumper.exe -name <ProcessName>
universal_dma_dumper.exe -name <ProcessName> -module <ModuleName.dll>
universal_dma_dumper.exe -name <ProcessName> -out <dir>
```

| Argument | Description |
|---|---|
| `-name` | Target process name (e.g. `game.exe`) — required |
| `-module` | Specific module to dump within that process (e.g. `engine.dll`). Defaults to the process executable itself |
| `-out` | Output directory. Defaults to `./dumps` |

Press **END** to stop the dump early. The PE fix will still run on whatever was collected.

---

## How it works

### 1. Page walker

Some games encrypt their code pages at rest and decrypt them on demand at runtime — this is done by the developers themselves, not anti-cheat. Pages may start as all `0x00` (uncommitted, not yet executed) and become readable only as the game executes them during normal gameplay.

A naive single-shot read of the entire module will capture a mix of real code and encrypted or uncommitted pages, making the dump largely useless.

The page walker solves this by reading the module one 4KB page at a time in a continuous retry loop:

1. The output file is pre-allocated to the full module size, filled with zeros, so pages can be written in-place at their correct offsets as they become available.
2. Each pass iterates every unread page in the module's address range.
3. For each page, `VMMDLL_MemReadEx` is called with `VMMDLL_FLAG_ZEROPAD_ON_FAIL` — this returns zeros for unreadable pages rather than failing, so they can be detected and skipped.
4. Pages that are all `0x00` (not yet executed) or heavily `0xCC`-filled (not yet decrypted) are skipped and retried next pass.
5. A candidate page is read **twice** and only accepted if both reads match — this prevents capturing pages that are mid-decryption and contain garbage.
6. Accepted pages are written into the output file at `offset = pageAddress - moduleBase`.

**Termination** happens when any of the following is met: **90% page coverage** is reached, the **15-minute timeout** expires, or **END** is pressed. This allows the walk to keep running through idle periods where pages haven't been decrypted or committed yet, rather than bailing out early.

> For games where pages decrypt only during active gameplay (e.g. in-match but not in menus), run the tool while actively playing to maximise coverage.

The result is a raw `.bin` file containing the module in its virtual memory layout.

---

### 2. PE reconstruction (`_raw.bin` → `_fixed.exe`)

The raw dump cannot be opened directly in IDA because it is in **memory layout**, not **file layout**.

| | Memory layout | File layout |
|---|---|---|
| Section data location | `VirtualAddress` (RVA) | `PointerToRawData` (file offset) |
| How Windows uses it | Loaded PE mapped into process | PE on disk |

The fix step rebuilds a proper file-layout PE. It handles several complications common with protected targets:

**Header corruption** — Some protectors zero the in-memory section table and data directories at runtime to defeat memory dumpers. To work around this, the tool queries MemProcFS's internal module database (`VMMDLL_ProcessGetSections`, `VMMDLL_ProcessGetDirectories`) before the walk begins. MemProcFS caches this data at attach time, independently of the process's live virtual memory, so it remains valid even after the game has wiped its own headers. No access to the game's files on disk is required — this works correctly when running on a second PC over DMA.

**Layout recalculation** — `PointerToRawData` and `SizeOfRawData` are recalculated from scratch using `VirtualSize` and `FileAlignment` rather than trusting the values in the headers, which protectors also corrupt.

**Data directories** — The security (authenticode) directory is zeroed since the signature is invalid after reconstruction. The exception directory (`.pdata`) is restored from the section table if missing — IDA uses this for x64 function boundary detection.

---

## Output

```
dumps/
├── <ModuleName>_raw.bin      # raw memory-layout dump
└── <ModuleName>_fixed.exe    # reconstructed file-layout PE  (or _fixed.dll for DLL modules)
```

The output extension is preserved from the module name — dumping `engine.dll` produces `engine_fixed.dll`. Open the fixed file in IDA, Ghidra, or x64dbg directly.
