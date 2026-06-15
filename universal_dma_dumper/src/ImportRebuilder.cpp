#include "pch.h"
#include "ImportRebuilder.h"

namespace {

struct ImportFunc {
    std::string funcName;
    uint64_t    apiVA;
};

// VA -> (module basename, function name). Populated from every module in
// the target process except the module we're dumping.
using ExportMap = std::unordered_map<uint64_t, std::pair<std::string, std::string>>;

// Lower-cases an ASCII module name so different casings ("KERNEL32.DLL" vs
// "kernel32.dll") collapse into one descriptor.
std::string LowerAscii(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return s;
}

std::string Utf16ToUtf8(LPCWSTR w) {
    if (!w) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

// Walk every loaded module in the process and pull its exports through
// MemProcFS's parsed EAT map (no manual export-directory reads needed —
// MemProcFS already resolves forwarders and ordinals).
ExportMap BuildExportMap(VMM_HANDLE hVMM, DWORD pid, ULONG64 skipModBase) {
    ExportMap map;

    PVMMDLL_MAP_MODULE modMap = nullptr;
    if (!VMMDLL_Map_GetModuleW(hVMM, pid, &modMap, 0) || !modMap)
        return map;

    size_t totalExports = 0;
    size_t modulesUsed  = 0;
    for (DWORD i = 0; i < modMap->cMap; ++i) {
        const auto& m = modMap->pMap[i];
        if (m.vaBase == skipModBase) continue;
        if (!m.wszText) continue;

        PVMMDLL_MAP_EAT eatMap = nullptr;
        if (!VMMDLL_Map_GetEATW(hVMM, pid, m.wszText, &eatMap) || !eatMap)
            continue;

        const std::string modName = LowerAscii(Utf16ToUtf8(m.wszText));
        if (modName.empty()) { VMMDLL_MemFree(eatMap); continue; }

        for (DWORD j = 0; j < eatMap->cMap; ++j) {
            const auto& e = eatMap->pMap[j];
            // Skip forwarders (their vaFunction lies inside the export
            // directory of the source module — MemProcFS reports them with
            // a non-null wszForwardedFunction).
            if (e.wszForwardedFunction && e.wszForwardedFunction[0]) continue;
            if (!e.vaFunction || !e.wszFunction || !e.wszFunction[0]) continue;

            std::string fn = Utf16ToUtf8(e.wszFunction);
            if (fn.empty()) continue;

            // First write wins — if the same VA is reachable through two
            // module aliases (typical for kernelbase/kernel32 forwards), the
            // earlier hit is fine for naming purposes.
            map.try_emplace(e.vaFunction, modName, std::move(fn));
        }

        totalExports += eatMap->cMap;
        ++modulesUsed;
        VMMDLL_MemFree(eatMap);
    }
    VMMDLL_MemFree(modMap);

    std::cout << std::format("[*] Import scan: collected {} exports across {} modules\n",
                             map.size(), modulesUsed);
    return map;
}

// Scan every non-executable section of the dumped buffer at 8-byte stride
// for qwords that match a known export VA. Returns one entry per unique
// API VA (so a function referenced from multiple .rdata slots collapses to
// one IAT entry).
struct CollectedImport {
    std::string mod;        // lower-case basename
    std::string func;
    uint64_t    apiVA;
};

std::vector<CollectedImport> CollectImports(const std::vector<uint8_t>& outBuf,
                                            const std::vector<IMAGE_SECTION_HEADER>& sections,
                                            const ExportMap& exportMap) {
    std::unordered_set<uint64_t> seen;
    std::vector<CollectedImport> out;

    for (const auto& sec : sections) {
        if (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
        if ((sec.Characteristics & IMAGE_SCN_MEM_READ) == 0) continue;
        if (!sec.PointerToRawData || !sec.SizeOfRawData) continue;

        const size_t off  = sec.PointerToRawData;
        const size_t size = sec.SizeOfRawData;
        if (off + size > outBuf.size()) continue;

        const uint8_t* base = outBuf.data() + off;
        // x64 IAT slots are 8-byte aligned. Stride at 8 to avoid trillions
        // of useless 1-byte-aligned probes through a multi-MB .rdata.
        for (size_t i = 0; i + 8 <= size; i += 8) {
            uint64_t v;
            std::memcpy(&v, base + i, sizeof(v));
            if (v < 0x0000010000000000ULL) continue; // cheap pre-filter: user-mode addresses are way above this
            if (seen.contains(v)) continue;

            auto it = exportMap.find(v);
            if (it == exportMap.end()) continue;

            seen.insert(v);
            out.push_back({ it->second.first, it->second.second, v });
        }
    }
    return out;
}

} // namespace

bool ImportRebuilder::Rebuild(std::vector<uint8_t>& outBuf,
                              std::vector<IMAGE_SECTION_HEADER>& workingSections,
                              VMM_HANDLE hVMM,
                              DWORD pid,
                              ULONG64 targetModBase) {
    if (!hVMM || !pid) {
        std::cout << "[~] Import rebuild skipped (no VMM context)\n";
        return false;
    }
    if (outBuf.size() < sizeof(IMAGE_DOS_HEADER)) return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(outBuf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > outBuf.size()) return false;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(outBuf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        std::cout << "[~] Import rebuild skipped (x86 PEs not supported)\n";
        return false;
    }

    const ExportMap exportMap = BuildExportMap(hVMM, pid, targetModBase);
    if (exportMap.empty()) {
        std::cout << "[~] Import rebuild skipped (export map empty)\n";
        return false;
    }

    const auto imports = CollectImports(outBuf, workingSections, exportMap);
    if (imports.empty()) {
        std::cout << "[~] Import rebuild skipped (no IAT-shaped hits in data sections)\n";
        return false;
    }

    // ----------------------------------------------------------------
    //  Group by module (preserve insertion order for deterministic
    //  output) and lay out IAT / INT / descriptor / name regions.
    // ----------------------------------------------------------------
    std::vector<std::string> moduleOrder;
    std::unordered_map<std::string, std::vector<const CollectedImport*>> byModule;
    for (const auto& imp : imports) {
        auto [it, inserted] = byModule.try_emplace(imp.mod);
        if (inserted) moduleOrder.push_back(imp.mod);
        it->second.push_back(&imp);
    }

    const uint32_t fileAlignment    = nt->OptionalHeader.FileAlignment ? nt->OptionalHeader.FileAlignment : 0x200;
    const uint32_t sectionAlignment = nt->OptionalHeader.SectionAlignment ? nt->OptionalHeader.SectionAlignment : 0x1000;
    auto alignUp = [](uint32_t v, uint32_t a) { return (v + a - 1) & ~(a - 1); };

    // Region sizes. The IAT block sits at the start of the section so
    // IMAGE_DIRECTORY_ENTRY_IAT can point at it without an offset.
    size_t iatBytes  = 0;
    size_t intBytes  = 0;
    size_t descBytes = (moduleOrder.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    size_t nameBytes = 0;
    for (const auto& mod : moduleOrder) {
        const auto& fns = byModule[mod];
        iatBytes += (fns.size() + 1) * sizeof(uint64_t);
        intBytes += (fns.size() + 1) * sizeof(uint64_t);
        nameBytes += mod.size() + 1; // module name + null
        for (const auto* f : fns)
            nameBytes += sizeof(WORD) + f->func.size() + 1; // Hint + name + null
    }

    const uint32_t rawSize   = static_cast<uint32_t>(iatBytes + intBytes + descBytes + nameBytes);
    const uint32_t rawAlign  = alignUp(rawSize, fileAlignment);
    const uint32_t virtAlign = alignUp(rawSize, sectionAlignment);

    // ----------------------------------------------------------------
    //  Pick RVA + raw offset for the new section. RVA goes after the
    //  last existing section's virtual extent; raw offset goes after
    //  the current end of outBuf (which is already file-aligned because
    //  every prior section was sized with alignUp(VSize, FileAlignment)).
    // ----------------------------------------------------------------
    uint32_t newVA  = 0;
    for (const auto& sec : workingSections)
        newVA = std::max<uint32_t>(newVA, alignUp(sec.VirtualAddress + sec.Misc.VirtualSize, sectionAlignment));
    const uint32_t newRaw = static_cast<uint32_t>(alignUp(static_cast<uint32_t>(outBuf.size()), fileAlignment));

    // Make sure we have room in the header for one more section table entry.
    const size_t sectionTableOffset = static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64);
    const size_t neededHeaderEnd    = sectionTableOffset + (workingSections.size() + 1) * sizeof(IMAGE_SECTION_HEADER);
    if (neededHeaderEnd > nt->OptionalHeader.SizeOfHeaders) {
        std::cout << "[~] Import rebuild skipped (SizeOfHeaders has no room for a new section)\n";
        return false;
    }

    // ----------------------------------------------------------------
    //  Grow outBuf and lay out the new section.
    // ----------------------------------------------------------------
    outBuf.resize(static_cast<size_t>(newRaw) + rawAlign, 0);
    uint8_t* base = outBuf.data() + newRaw;

    const uint32_t iatRva  = newVA;
    const uint32_t intRva  = iatRva + static_cast<uint32_t>(iatBytes);
    const uint32_t descRva = intRva + static_cast<uint32_t>(intBytes);
    const uint32_t nameRva = descRva + static_cast<uint32_t>(descBytes);

    uint64_t* iat  = reinterpret_cast<uint64_t*>(base);
    uint64_t* intp = reinterpret_cast<uint64_t*>(base + iatBytes);
    auto*     desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + iatBytes + intBytes);
    uint8_t*  names = base + iatBytes + intBytes + descBytes;
    uint32_t  nameCursor = nameRva;
    auto      writeName = [&](const std::string& s) -> uint32_t {
        const uint32_t rva = nameCursor;
        std::memcpy(names, s.c_str(), s.size() + 1);
        names      += s.size() + 1;
        nameCursor += static_cast<uint32_t>(s.size() + 1);
        return rva;
    };
    auto writeHintName = [&](const std::string& s) -> uint32_t {
        const uint32_t rva = nameCursor;
        // Hint = 0 (we don't carry ordinal hints).
        names[0] = 0;
        names[1] = 0;
        std::memcpy(names + 2, s.c_str(), s.size() + 1);
        names      += 2 + s.size() + 1;
        nameCursor += static_cast<uint32_t>(2 + s.size() + 1);
        return rva;
    };

    // Maps API VA -> RVA of its IAT slot. Used by the displacement
    // patcher below.
    std::unordered_map<uint64_t, uint32_t> apiToIatRva;

    uint64_t* iatCursor = iat;
    uint64_t* intCursor = intp;
    for (const auto& mod : moduleOrder) {
        const auto& fns = byModule[mod];

        desc->FirstThunk         = static_cast<DWORD>(reinterpret_cast<uint8_t*>(iatCursor) - base) + iatRva;
        desc->OriginalFirstThunk = static_cast<DWORD>(reinterpret_cast<uint8_t*>(intCursor) - base) + iatRva;
        desc->TimeDateStamp      = 0;
        desc->ForwarderChain     = 0;

        for (const auto* f : fns) {
            const uint32_t hintRva = writeHintName(f->func);
            *intCursor++ = hintRva;          // INT entry -> IMAGE_IMPORT_BY_NAME
            const uint32_t slotRva = static_cast<uint32_t>(reinterpret_cast<uint8_t*>(iatCursor) - base) + iatRva;
            apiToIatRva.emplace(f->apiVA, slotRva);
            *iatCursor++ = f->apiVA;         // IAT entry pre-filled with resolved VA
        }
        *intCursor++ = 0;
        *iatCursor++ = 0;

        desc->Name = writeName(mod);
        ++desc;
    }
    // Trailing zero descriptor (already zero-init from resize fill).
    (void)desc;

    // ----------------------------------------------------------------
    //  Build & emit the new section header.
    // ----------------------------------------------------------------
    IMAGE_SECTION_HEADER newSec{};
    std::memcpy(newSec.Name, ".idata2", 7);
    newSec.Misc.VirtualSize = static_cast<DWORD>(rawSize);
    newSec.VirtualAddress   = newVA;
    newSec.SizeOfRawData    = rawAlign;
    newSec.PointerToRawData = newRaw;
    newSec.Characteristics  = IMAGE_SCN_CNT_INITIALIZED_DATA |
                              IMAGE_SCN_MEM_READ |
                              IMAGE_SCN_MEM_WRITE; // IAT is writable

    std::memcpy(outBuf.data() + sectionTableOffset
                + workingSections.size() * sizeof(IMAGE_SECTION_HEADER),
                &newSec, sizeof(newSec));
    workingSections.push_back(newSec);

    nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(outBuf.data() + dos->e_lfanew);
    nt->FileHeader.NumberOfSections = static_cast<WORD>(workingSections.size());
    nt->OptionalHeader.SizeOfImage += virtAlign;

    // ----------------------------------------------------------------
    //  Point IMPORT and IAT data directories at the new layout.
    // ----------------------------------------------------------------
    auto& dirs = nt->OptionalHeader.DataDirectory;
    dirs[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress    = iatRva;
    dirs[IMAGE_DIRECTORY_ENTRY_IAT].Size              = static_cast<DWORD>(iatBytes);
    dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = descRva;
    dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size           = static_cast<DWORD>(descBytes);

    // ----------------------------------------------------------------
    //  Patch `call [rip+disp]` / `jmp [rip+disp]` displacements that
    //  originally targeted the in-memory IAT slots. Without this the
    //  disassembler keeps showing raw `qword_xxxx` references instead
    //  of import names — the new IAT exists but nothing points at it.
    //
    //  Patterns covered:
    //    FF 15 disp32       call qword [rip+disp32]
    //    FF 25 disp32       jmp  qword [rip+disp32]
    //    48 FF 25 disp32    jmp  qword [rip+disp32] (REX.W form, common in thunks)
    // ----------------------------------------------------------------
    auto rvaToRaw = [&](uint32_t rva) -> size_t {
        for (const auto& sec : workingSections) {
            if (rva >= sec.VirtualAddress &&
                rva <  sec.VirtualAddress + sec.SizeOfRawData)
                return static_cast<size_t>(sec.PointerToRawData) +
                       (rva - sec.VirtualAddress);
        }
        return SIZE_MAX;
    };

    uint32_t patched = 0;
    for (const auto& sec : workingSections) {
        if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        const size_t off  = sec.PointerToRawData;
        const size_t size = sec.SizeOfRawData;
        if (off + size > outBuf.size()) continue;

        uint8_t* code = outBuf.data() + off;
        for (size_t i = 0; i + 6 <= size; ++i) {
            uint32_t dispOff   = 0;
            uint32_t instrLen  = 0;
            if (code[i] == 0xFF && (code[i + 1] == 0x15 || code[i + 1] == 0x25)) {
                dispOff  = 2;
                instrLen = 6;
            } else if (i + 7 <= size &&
                       code[i] == 0x48 && code[i + 1] == 0xFF && code[i + 2] == 0x25) {
                dispOff  = 3;
                instrLen = 7;
            } else {
                continue;
            }

            const uint32_t startRva = static_cast<uint32_t>(sec.VirtualAddress + i);
            const uint32_t nextRva  = startRva + instrLen;

            int32_t disp = 0;
            std::memcpy(&disp, code + i + dispOff, sizeof(disp));
            const uint32_t targetRva = nextRva + static_cast<uint32_t>(disp);

            const size_t targetRaw = rvaToRaw(targetRva);
            if (targetRaw == SIZE_MAX || targetRaw + sizeof(uint64_t) > outBuf.size()) continue;

            uint64_t apiVA;
            std::memcpy(&apiVA, outBuf.data() + targetRaw, sizeof(apiVA));
            if (apiVA < 0x0000010000000000ULL) continue;

            const auto it = apiToIatRva.find(apiVA);
            if (it == apiToIatRva.end()) continue;

            const int32_t newDisp = static_cast<int32_t>(it->second) -
                                    static_cast<int32_t>(nextRva);
            std::memcpy(code + i + dispOff, &newDisp, sizeof(newDisp));
            ++patched;
            // Skip past this instruction so we don't try to repatch its
            // tail bytes as a new pattern.
            i += instrLen - 1;
        }
    }

    std::cout << std::format(
        "[+] Import rebuild: {} functions across {} modules, "
        "new section .idata2 @ RVA 0x{:X} ({} bytes), {} call/jmp displacements patched\n",
        imports.size(), moduleOrder.size(), iatRva, rawSize, patched);
    return true;
}
