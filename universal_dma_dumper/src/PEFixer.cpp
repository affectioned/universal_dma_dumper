#include "pch.h"
#include "PEFixer.h"

bool PEFixer::Fix(const std::string& dumpFile, const std::string& peFile,
                  const ModuleLayout& layout) {
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
