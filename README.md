# universal_dma_dumper

Universal DMA-based process dumper for Windows. Walks memory page by page with encryption-aware retry logic and reconstructs a proper PE file from the dump.

Original page walker logic by [zarboz on UnknownCheats](https://www.unknowncheats.me/forum/4595235-post1774.html).

---

## Requirements

- Windows x64
- DMA device (FPGA / PCILeech)
- [MemProcFS](https://github.com/ufrisk/MemProcFS/releases) — `vmdll.h`, `vmmdll.lib`, `leechcore.h`, `leechcore.lib`,
- Visual Studio 2022 with C++20

---

## Project structure

```
universal_dma_dumper/
├── libs/
│   ├── leechcore.lib
│   ├── leechcore.h
│   ├── vmmdll.lib
│   └── vmmdll.h
├── src/
│   ├── main.cpp
│   ├── pch.cpp
│   └── pch.h
└── README.md
```

---

## Usage

```
universal_dma_dumper.exe -name <ProcessName>
universal_dma_dumper.exe -name <ProcessName> -out <dir>
```

Press **END** to stop the dump early. The PE fix will still run on whatever was collected.

---

## How it works

### 1. Page walker

Modern games encrypt their code pages at rest and decrypt them on demand at runtime — this is done by the developers themselves, not anti-cheat. At any given moment only a portion of the module's pages are in their decrypted state in memory.

A naive single-shot read of the entire module will capture a mix of real code and still-encrypted pages filled with `0xCC`, making the dump largely useless.

The page walker solves this by reading the module one 4KB page at a time in a continuous retry loop:

1. The output file is pre-allocated to the full module size, filled with zeros, so pages can be written in-place at their correct offsets as they become available.
2. Each pass iterates every page in the module's address range. Pages that have already been successfully dumped are skipped.
3. For each unread page, `VMMDLL_MemReadEx` is called with `VMMDLL_FLAG_ZEROPAD_ON_FAIL` — this returns zeros for unreadable pages rather than failing the whole read, so we can detect and skip them.
4. Pages that are all `0x00` (uncommitted / not yet paged in) or all `0xCC` (not yet decrypted) are skipped and retried on the next pass.
5. Any page with real content is written into the output file at `offset = pageAddress - moduleBase`, preserving the in-memory layout exactly.
6. The loop continues until one of three conditions is met: 95%+ page coverage is reached, the 15-minute timeout expires, or the user presses END.

The result is a raw `.bin` file containing the module in its virtual memory layout — section data sits at each section's RVA from the image base.

---

### 2. PE reconstruction (`_raw.bin` → `_fixed.exe`)

The raw dump cannot be opened directly in IDA because it is in **memory layout**, not **file layout**.

The difference is:

| | Memory layout | File layout |
|---|---|---|
| Section data location | `VirtualAddress` (RVA) | `PointerToRawData` (file offset) |
| How Windows uses it | Loaded PE mapped into process | PE on disk |

When Windows loads a PE it maps each section to its `VirtualAddress`. So in the raw dump, `.text` is at offset `0x1000` because that is its `VirtualAddress`, not because its `PointerToRawData` says `0x1000`. IDA reads files using `PointerToRawData`, so it would look at the wrong offset and see garbage.

The fix step rebuilds a proper file-layout PE:

1. Read the raw dump into a buffer.
2. Validate the `MZ` signature (`IMAGE_DOS_HEADER.e_magic`) and `PE\0\0` signature (`IMAGE_NT_HEADERS.Signature`).
3. Check `FileHeader.Machine` to detect x86 vs x64 and read `SizeOfHeaders` from the correct typed struct (`IMAGE_NT_HEADERS32` or `IMAGE_NT_HEADERS64`).
4. Allocate an output buffer sized to fit the headers plus all sections at their file offsets.
5. Copy the headers verbatim into the output buffer.
6. For each section, copy from `rawDump[VirtualAddress]` into `outBuffer[PointerToRawData]` for `SizeOfRawData` bytes.
7. Write the output buffer to `_fixed.exe`.

The resulting file has section data where IDA expects it, so it opens and analyses correctly.

---

## Output

```
dumps/
├── <ProcessName>_raw.bin     # raw memory-layout dump
└── <ProcessName>_fixed.exe   # reconstructed file-layout PE
```

Open `_fixed.exe` in IDA, Ghidra, or x64dbg directly.
