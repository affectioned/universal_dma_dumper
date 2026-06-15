#include "pch.h"
#include "PEFixer.h"
#include "ImportRebuilder.h"

bool PEFixer::Fix(const std::string& dumpFile, const std::string& peFile,
                  const ModuleLayout& layout,
                  VMM_HANDLE hVMM, DWORD pid, ULONG64 modBase) {
    // --------------------------------------------------------
    //  Load memory dump
    // --------------------------------------------------------
    std::ifstream dump(dumpFile, std::ios::binary);
    if (!dump) return false;
    dump.seekg(0, std::ios::end);
    const size_t dumpSize = static_cast<size_t>(dump.tellg());
    dump.seekg(0);
    std::vector<uint8_t> buf(dumpSize);
    dump.read(reinterpret_cast<char*>(buf.data()), dumpSize);
    dump.close();

    if (dumpSize < sizeof(IMAGE_DOS_HEADER)) return false;

    // --------------------------------------------------------
    //  Validate DOS and NT signatures
    // --------------------------------------------------------
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false; // "MZ"

    if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > dumpSize) return false;

    auto* ntGeneric = reinterpret_cast<IMAGE_NT_HEADERS*>(buf.data() + dos->e_lfanew);
    if (ntGeneric->Signature != IMAGE_NT_SIGNATURE) return false; // "PE\0\0"

    // --------------------------------------------------------
    //  Determine architecture.
    //  Prefer the in-memory Machine field; if it has been zeroed by the
    //  protector, fall back to MemProcFS's fWoW64 flag, then default to x64.
    // --------------------------------------------------------
    bool is64;
    if (ntGeneric->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        is64 = true;
    else if (ntGeneric->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        is64 = false;
    else if (layout.valid)
        is64 = !layout.fWoW64;
    else
        is64 = true; // safe default for modern game targets

    // --------------------------------------------------------
    //  Read SizeOfHeaders and FileAlignment from the optional header.
    //  If either is missing or unreasonable (zeroed header), use safe defaults.
    // --------------------------------------------------------
    DWORD sizeOfHeaders = is64
        ? reinterpret_cast<IMAGE_NT_HEADERS64*>(ntGeneric)->OptionalHeader.SizeOfHeaders
        : reinterpret_cast<IMAGE_NT_HEADERS32*>(ntGeneric)->OptionalHeader.SizeOfHeaders;

    DWORD fileAlignment = is64
        ? reinterpret_cast<IMAGE_NT_HEADERS64*>(ntGeneric)->OptionalHeader.FileAlignment
        : reinterpret_cast<IMAGE_NT_HEADERS32*>(ntGeneric)->OptionalHeader.FileAlignment;

    if (fileAlignment == 0 || fileAlignment > 0x10000)
        fileAlignment = 0x200;

    if (sizeOfHeaders == 0 || sizeOfHeaders > 0x10000) {
        // Compute minimum header size from scratch
        const size_t numSec  = layout.valid ? layout.sections.size()
                                            : ntGeneric->FileHeader.NumberOfSections;
        const size_t ntSize  = is64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
        const size_t rawSize = static_cast<size_t>(dos->e_lfanew) + ntSize
                               + numSec * sizeof(IMAGE_SECTION_HEADER);
        sizeOfHeaders = static_cast<DWORD>((rawSize + fileAlignment - 1) & ~(fileAlignment - 1));
    }

    // --------------------------------------------------------
    //  Determine which sections to use.
    //  MemProcFS caches module metadata independently of live virtual memory,
    //  so layout.sections is reliable even when the game has zeroed its own
    //  in-memory section table.
    // --------------------------------------------------------
    std::vector<IMAGE_SECTION_HEADER> workingSections;

    if (layout.valid && !layout.sections.empty()) {
        workingSections = layout.sections;
        std::cout << std::format("[*] Using {} sections from MemProcFS module map\n",
                                 workingSections.size());
    } else {
        const auto* rawSections = IMAGE_FIRST_SECTION(ntGeneric);
        workingSections.assign(rawSections,
                               rawSections + ntGeneric->FileHeader.NumberOfSections);
    }

    std::cout << std::format("[*] PE architecture : {}\n", is64 ? "x64" : "x86");
    std::cout << std::format("[*] Sections        : {}\n", workingSections.size());
    std::cout << std::format("[*] File alignment  : 0x{:X}\n", fileAlignment);

    // --------------------------------------------------------
    //  Recalculate PointerToRawData and SizeOfRawData.
    //  Protectors corrupt these fields in-memory; derive them from
    //  VirtualSize + FileAlignment so the layout is always correct.
    // --------------------------------------------------------
    {
        DWORD nextRawOffset = sizeOfHeaders;
        for (auto& sec : workingSections) {
            sec.PointerToRawData = nextRawOffset;
            sec.SizeOfRawData    = (sec.Misc.VirtualSize + fileAlignment - 1) & ~(fileAlignment - 1);
            nextRawOffset       += sec.SizeOfRawData;
        }
    }

    // --------------------------------------------------------
    //  Allocate output buffer and copy PE headers from dump
    // --------------------------------------------------------
    size_t outSize = sizeOfHeaders;
    for (const auto& sec : workingSections) {
        const size_t sectionEnd = static_cast<size_t>(sec.PointerToRawData) + sec.SizeOfRawData;
        if (sectionEnd > outSize) outSize = sectionEnd;
    }

    std::vector<uint8_t> outBuf(outSize, 0);
    const size_t headerCopySize = std::min(static_cast<size_t>(sizeOfHeaders), dumpSize);
    memcpy(outBuf.data(), buf.data(), headerCopySize);

    // If MemProcFS provided the sections, patch NumberOfSections and write the
    // recalculated section table into the output buffer (the dump's copy may be zeroed).
    if (layout.valid && !layout.sections.empty()) {
        auto* ntOut = reinterpret_cast<IMAGE_NT_HEADERS*>(outBuf.data() + dos->e_lfanew);
        ntOut->FileHeader.NumberOfSections = static_cast<WORD>(workingSections.size());

        const size_t sectionTableOffset =
            reinterpret_cast<const uint8_t*>(IMAGE_FIRST_SECTION(ntGeneric)) - buf.data();

        if (sectionTableOffset + workingSections.size() * sizeof(IMAGE_SECTION_HEADER) <= outBuf.size()) {
            memcpy(outBuf.data() + sectionTableOffset,
                   workingSections.data(),
                   workingSections.size() * sizeof(IMAGE_SECTION_HEADER));
        }
    }

    // --------------------------------------------------------
    //  Copy each section's data from the memory dump into the
    //  output buffer at the recalculated on-disk file offset
    // --------------------------------------------------------
    for (const auto& sec : workingSections) {
        const size_t rva    = sec.VirtualAddress;
        const size_t rawOff = sec.PointerToRawData;
        size_t       copySize = sec.SizeOfRawData;

        // Clamp source against dump bounds
        if (rva + copySize > buf.size())
            copySize = (rva < buf.size()) ? buf.size() - rva : 0;
        if (copySize == 0) continue;

        // Clamp destination against output bounds
        if (rawOff + copySize > outBuf.size())
            copySize = (rawOff < outBuf.size()) ? outBuf.size() - rawOff : 0;
        if (copySize == 0) continue;

        memcpy(outBuf.data() + rawOff, buf.data() + rva, copySize);
    }

    // --------------------------------------------------------
    //  Fix up DataDirectory entries in the output buffer
    // --------------------------------------------------------
    auto* ntOut = reinterpret_cast<IMAGE_NT_HEADERS*>(outBuf.data() + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY* dirs = is64
        ? reinterpret_cast<IMAGE_NT_HEADERS64*>(ntOut)->OptionalHeader.DataDirectory
        : reinterpret_cast<IMAGE_NT_HEADERS32*>(ntOut)->OptionalHeader.DataDirectory;

    // Apply MemProcFS-sourced directories. These come from MemProcFS's analysis
    // of the module and are more reliable than whatever is in the dump's headers.
    if (layout.valid) {
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
            if (layout.directories[i].VirtualAddress || layout.directories[i].Size)
                dirs[i] = layout.directories[i];
        }
        std::cout << "[*] Applied data directories from MemProcFS\n";
    }

    // Zero the security (authenticode) directory — the signature is invalid
    // after reconstruction and some tools refuse to open a PE with a dangling pointer.
    {
        auto& secDir = dirs[IMAGE_DIRECTORY_ENTRY_SECURITY];
        if (secDir.VirtualAddress || secDir.Size) {
            secDir = {};
            std::cout << "[*] Cleared security directory\n";
        }
    }

    // Restore the exception directory (.pdata) if zeroed.
    // IDA uses RUNTIME_FUNCTION entries from .pdata to detect x64 function boundaries.
    // MemProcFS already covers this via layout.directories, but if that was also
    // empty, fall back to scanning the section table by name.
    if (is64) {
        auto& exDir = dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exDir.VirtualAddress == 0) {
            for (const auto& sec : workingSections) {
                if (strncmp(reinterpret_cast<const char*>(sec.Name), ".pdata", 6) == 0) {
                    exDir.VirtualAddress = sec.VirtualAddress;
                    exDir.Size           = sec.Misc.VirtualSize;
                    std::cout << "[*] Restored .pdata exception directory from section table\n";
                    break;
                }
            }
        }
    }

    // Restore the base relocation directory if zeroed.
    // Loaders/analyzers may use the directory entry (not the section name) to
    // locate .reloc; some games zero the directory pointer even when the
    // section payload is intact.
    {
        auto& relocDir = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress == 0) {
            for (const auto& sec : workingSections) {
                if (strncmp(reinterpret_cast<const char*>(sec.Name), ".reloc", 6) == 0) {
                    relocDir.VirtualAddress = sec.VirtualAddress;
                    relocDir.Size           = sec.Misc.VirtualSize;
                    std::cout << "[*] Restored .reloc base relocation directory from section table\n";
                    break;
                }
            }
        }
    }

    // Clear the .reloc directory if the payload is empty.
    //
    // IDA walks the relocation table sequentially: each block has an 8-byte
    // header (VirtualAddress + SizeOfBlock) and a zero header terminates the
    // walk. Anti-tamper protectors (Marathon's VMProtect build is the case
    // that motivated this) commonly wipe .reloc after the loader applies
    // relocations — the section payload is then all zeros but the directory
    // still advertises it, so IDA chases the pointer into nothing and either
    // disables relocation analysis silently or trips up plugins that assume
    // a present directory means valid data.
    //
    // Detecting an entirely-zero header is enough: if the first block header
    // is zero, IDA cannot walk past it regardless of what comes after, so
    // clearing the directory is strictly more honest than leaving a dangling
    // pointer.
    {
        auto& relocDir = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress && relocDir.Size) {
            size_t relocRaw = SIZE_MAX;
            for (const auto& sec : workingSections) {
                if (relocDir.VirtualAddress >= sec.VirtualAddress &&
                    relocDir.VirtualAddress <  sec.VirtualAddress + sec.SizeOfRawData) {
                    relocRaw = static_cast<size_t>(sec.PointerToRawData) +
                               (relocDir.VirtualAddress - sec.VirtualAddress);
                    break;
                }
            }

            // Scan the first page of the reloc payload. Catches both
            // "entirely stripped" (the Marathon case) and "first block header
            // zeroed" — IDA's walker stops dead on a zero header either way.
            const size_t scanBytes = std::min<size_t>(relocDir.Size, 0x1000);
            if (relocRaw != SIZE_MAX && relocRaw + scanBytes <= outBuf.size()) {
                const bool headerZero = std::all_of(
                    outBuf.data() + relocRaw,
                    outBuf.data() + relocRaw + scanBytes,
                    [](uint8_t b) { return b == 0; });

                if (headerZero) {
                    std::cout << std::format(
                        "[*] Cleared .reloc directory — payload is zero "
                        "({} KB stripped by protector, directory pointer dropped)\n",
                        relocDir.Size / 1024);
                    relocDir = {};
                }
            }
        }
    }

    // --------------------------------------------------------
    //  Strip directories that routinely cause IDA to hang or
    //  spend forever in auto-analysis on dumped/protected PEs:
    //    - LOAD_CONFIG:  protectors corrupt CFG/SEH counts so IDA
    //      walks millions of phantom guard-CF call targets.
    //    - BOUND_IMPORT: always stale on a runtime dump.
    //    - DEBUG:        stale CodeView pointers can stall symbol load.
    // --------------------------------------------------------
    {
        static constexpr int kStripDirs[] = {
            IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
            IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
            IMAGE_DIRECTORY_ENTRY_DEBUG,
        };
        for (int idx : kStripDirs) {
            if (dirs[idx].VirtualAddress || dirs[idx].Size) {
                std::cout << std::format("[*] Stripped directory entry {}\n", idx);
                dirs[idx] = {};
            }
        }
    }

    // --------------------------------------------------------
    //  Auto-strip CFG-flattened obfuscated pages.
    //
    //  Anti-tamper protectors used by AAA titles (e.g. Activision/COD)
    //  wrap nearly every real instruction in an unconditional `JMP rel32`
    //  to explode the basic-block graph and stall analyzers. The signature
    //  is unmistakable: `0xE9` becomes the most common byte on the page,
    //  reaching 12-15% density vs ~1% for normal x64 code.
    //
    //  When IDA tries to autoanalyze these pages — typically reached via
    //  jump tables that point into them — it recurses through the JMP
    //  maze, validating thousands of phantom basic blocks per function and
    //  wedging the UI for hours. Overwriting these pages with `0xCC` int3
    //  fill makes IDA's "is this code?" check fail at the first byte and
    //  the analyzer abandons the target instead of recursing.
    //
    //  The 10% threshold is well above the noise floor: average E9 density
    //  in clean code is ~1%, and even branch-heavy normal code rarely
    //  exceeds 5%. A page above 10% is essentially always CFG-flattened.
    //
    //  Must run BEFORE the .pdata filter so the filter can drop entries
    //  whose target page we just nuked — otherwise IDA creates one phantom
    //  function per surviving entry and stalls in autoanalysis.
    // --------------------------------------------------------
    constexpr size_t kPageSize = 0x1000;
    std::unordered_set<DWORD> strippedPageRvas;
    {
        constexpr size_t kE9Threshold = (kPageSize * 10) / 100; // 10% = 410 bytes

        size_t totalStripped = 0;
        for (const auto& sec : workingSections) {
            if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;

            size_t       secStripped = 0;
            const DWORD  secVAEnd    = sec.VirtualAddress + sec.Misc.VirtualSize;

            for (DWORD rvaPage = sec.VirtualAddress;
                 rvaPage + kPageSize <= secVAEnd;
                 rvaPage += static_cast<DWORD>(kPageSize)) {
                const size_t fileOff =
                    static_cast<size_t>(sec.PointerToRawData) +
                    static_cast<size_t>(rvaPage - sec.VirtualAddress);
                if (fileOff + kPageSize > outBuf.size()) break;

                size_t e9Count = 0;
                for (size_t i = 0; i < kPageSize; ++i)
                    if (outBuf[fileOff + i] == 0xE9) ++e9Count;

                if (e9Count >= kE9Threshold) {
                    memset(outBuf.data() + fileOff, 0xCC, kPageSize);
                    strippedPageRvas.insert(rvaPage);
                    ++secStripped;
                }
            }

            if (secStripped > 0) {
                char name[9] = {};
                memcpy(name, sec.Name, 8);
                std::cout << std::format("[*] Stripped {} obfuscated pages ({} KB) from {}\n",
                                         secStripped, secStripped * 4, name);
                totalStripped += secStripped;
            }
        }
        if (totalStripped > 0) {
            std::cout << std::format("[!] CFG-flattened anti-tamper detected — "
                                     "auto-stripped {} pages ({} KB) total to 0xCC int3\n",
                                     totalStripped, totalStripped * 4);
        }
    }

    // --------------------------------------------------------
    //  Filter .pdata. Drop RUNTIME_FUNCTION entries whose addresses
    //  are zero, inverted, land outside an executable section, or point
    //  into a page we just stripped to 0xCC.
    //
    //  The stripped-page check is what keeps IDA from creating a phantom
    //  function for every entry into a CFG-flattened region: a
    //  multi-million-line .pdata can survive the basic-validity filter
    //  but every entry then resolves to int3 fill, making IDA's autoanalysis
    //  spin for hours validating non-functions.
    // --------------------------------------------------------
    if (is64) {
        auto& exDir = dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exDir.VirtualAddress && exDir.Size >= sizeof(RUNTIME_FUNCTION)) {
            auto rvaToRaw = [&](DWORD rva) -> size_t {
                for (const auto& sec : workingSections) {
                    if (rva >= sec.VirtualAddress &&
                        rva <  sec.VirtualAddress + sec.SizeOfRawData)
                        return static_cast<size_t>(sec.PointerToRawData) +
                               (rva - sec.VirtualAddress);
                }
                return SIZE_MAX;
            };

            auto isExecRva = [&](DWORD rva) {
                for (const auto& sec : workingSections) {
                    if (rva >= sec.VirtualAddress &&
                        rva <  sec.VirtualAddress + sec.Misc.VirtualSize)
                        return (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                }
                return false;
            };

            auto isStrippedRva = [&](DWORD rva) {
                return strippedPageRvas.contains(
                    rva & ~static_cast<DWORD>(kPageSize - 1));
            };

            const size_t pdataRaw = rvaToRaw(exDir.VirtualAddress);
            if (pdataRaw != SIZE_MAX && pdataRaw + exDir.Size <= outBuf.size()) {
                auto* entries = reinterpret_cast<RUNTIME_FUNCTION*>(outBuf.data() + pdataRaw);
                const size_t count = exDir.Size / sizeof(RUNTIME_FUNCTION);
                size_t kept = 0;
                size_t droppedStripped = 0;
                for (size_t i = 0; i < count; ++i) {
                    const auto& e = entries[i];
                    if (e.BeginAddress == 0 && e.EndAddress == 0) continue;
                    if (e.BeginAddress >= e.EndAddress) continue;
                    if (!isExecRva(e.BeginAddress)) continue;
                    if (isStrippedRva(e.BeginAddress)) { ++droppedStripped; continue; }
                    entries[kept++] = e;
                }
                memset(entries + kept, 0, (count - kept) * sizeof(RUNTIME_FUNCTION));
                exDir.Size = static_cast<DWORD>(kept * sizeof(RUNTIME_FUNCTION));
                std::cout << std::format("[*] Filtered .pdata: kept {}/{} RUNTIME_FUNCTION entries"
                                         " ({} dropped pointing into stripped pages)\n",
                                         kept, count, droppedStripped);
            }
        }
    }

    // --------------------------------------------------------
    //  Rebuild IMPORT / IAT directories from the live process.
    //
    //  Runs after .pdata filtering so the new section's RVAs can't
    //  accidentally collide with anything the filter just trimmed, and
    //  after CFG-flatten stripping so the displacement patcher doesn't
    //  waste cycles scanning solid-0xCC pages.
    // --------------------------------------------------------
    ImportRebuilder::Rebuild(outBuf, workingSections, hVMM, pid, modBase);

    // --------------------------------------------------------
    //  Write output
    // --------------------------------------------------------
    std::ofstream out(peFile, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(outBuf.data()), outBuf.size());

    std::cout << std::format("[+] Fixed PE written: {} ({} KB)\n",
                             peFile, outBuf.size() / 1024);
    return true;
}
