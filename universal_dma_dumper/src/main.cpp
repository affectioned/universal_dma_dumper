#include "pch.h"

// based off https://www.unknowncheats.me/forum/4595235-post1774.html
// original logic credit goes to them

VMM_HANDLE  g_hVMM = nullptr;
std::string g_outDir = "./dumps";

bool g_running = true;

// ============================================================
//  Some games encrypt pages at rest and decrypt them on demand
//  at runtime — this is implemented by the developers themselves.
//  Not-yet-decrypted pages are filled with 0xCC,
//  uncommitted/not-yet-paged-in memory shows as all 0x00.
//  We skip both and retry on the next pass.
// ============================================================
static bool IsEncrypted(std::span<const uint8_t> buf) {
    return std::ranges::all_of(buf, [](uint8_t b) { return b == 0xCC; });
}

static bool IsBlank(std::span<const uint8_t> buf) {
    return std::ranges::all_of(buf, [](uint8_t b) { return b == 0x00; });
}

// ============================================================
//  FindPidByName
// ============================================================
DWORD FindPidByName(std::string_view processName) {
    DWORD pid = 0;
    if (!VMMDLL_PidGetFromName(g_hVMM, processName.data(), &pid)) {
        std::cerr << std::format("[!] Process not found: {}\n", processName);
        return 0;
    }
    std::cout << std::format("[+] Found: {} (PID {})\n", processName, pid);
    return pid;
}

// ============================================================
//  GetModuleInfo
// ============================================================
bool GetModuleInfo(DWORD pid, std::string_view moduleName, ULONG64& outBase, DWORD& outSize) {
    std::wstring wName(moduleName.begin(), moduleName.end());
    PVMMDLL_MAP_MODULEENTRY entry = nullptr;

    if (!VMMDLL_Map_GetModuleFromNameW(g_hVMM, pid, const_cast<LPWSTR>(wName.c_str()), &entry, VMMDLL_MODULE_FLAG_NORMAL))
        return false;

    outBase = entry->vaBase;
    outSize = entry->cbImageSize;
    VMMDLL_MemFree(entry);
    return true;
}

// ============================================================
//  Walks the module region one 4KB page at a time.
//  Pages that are blank or still encrypted are skipped and
//  retried on the next pass — the loop keeps running until
//  either 95% of pages have been successfully dumped,
//  the 15-minute timeout is hit, or Ctrl+C is pressed.
//
//  The output file is pre-allocated to the full module size
//  and written in-place as pages are decoded, so the offsets
//  in the binary match the module's virtual layout exactly.
// ============================================================
static void PageWalker(DWORD pid, ULONG64 base, DWORD imageSize, const std::string& outFile) {
    const size_t PAGE = 0x1000;
    std::vector<uint8_t> pageBuf(PAGE);
    std::unordered_set<ULONG64> dumpedPages;

    // Pre-allocate the full file with zeros so we can seek + patch in place
    {
        std::ofstream ostrm(outFile, std::ios::binary);
        std::ofstream pre(outFile, std::ios::binary | std::ios::trunc);
        std::vector<uint8_t> zero(imageSize, 0);
        pre.write(reinterpret_cast<const char*>(zero.data()), imageSize);
    }

    std::fstream outf(outFile, std::ios::in | std::ios::out | std::ios::binary);
    if (!outf) {
        std::cerr << std::format("[!] Cannot open output file: {}\n", outFile);
        return;
    }

    const size_t totalPages = (imageSize + PAGE - 1) / PAGE;
    const auto   startTime = std::chrono::steady_clock::now();

    std::cout << std::format("[*] Starting page walk — {} pages total\n", totalPages);

    while (g_running) {
        if (GetAsyncKeyState(VK_END) & 1) g_running = false;

        for (ULONG64 addr = base; addr < base + imageSize; addr += PAGE) 
        {
            if (!g_running) break;

            if (dumpedPages.contains(addr)) continue;

            // VMMDLL_FLAG_ZEROPAD_ON_FAIL: don't abort on unreadable pages,
            // return zeros so we can detect them and retry next pass
            DWORD bytesRead = 0;
            if (!VMMDLL_MemReadEx(g_hVMM, pid, addr, pageBuf.data(), (DWORD)PAGE,
                &bytesRead, VMMDLL_FLAG_ZEROPAD_ON_FAIL))
                continue;

            if (IsBlank(pageBuf) || IsEncrypted(pageBuf))
                continue; // page still encrypted or not yet committed — retry next pass

            outf.seekp(static_cast<std::streamoff>(addr - base));
            outf.write(reinterpret_cast<const char*>(pageBuf.data()), PAGE);
            outf.flush();
            dumpedPages.insert(addr);

            std::cout << std::format("  [p] 0x{:016X}  ({}/{})\n", addr, dumpedPages.size(), totalPages);
        }

        // Coverage check: stop once we have 95%+ of pages
        const double coverage = static_cast<double>(dumpedPages.size()) / static_cast<double>(totalPages);
        if (coverage >= 0.95) {
            std::cout << std::format("[+] Reached {:.1f}% coverage, stopping.\n", coverage * 100.0);
            break;
        }

        // Timeout: bail out after 15 minutes regardless
        if (std::chrono::steady_clock::now() - startTime > std::chrono::minutes(15)) {
            std::cout << std::format("[!] 15-minute timeout reached ({}/{} pages dumped, {:.1f}% coverage).\n",
                dumpedPages.size(), totalPages, coverage * 100.0);
            break;
        }

        // Brief sleep before the next retry pass to avoid hammering the DMA bus
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    outf.close();
    std::cout << std::format("[+] Page walk done — {} pages written to {}\n", dumpedPages.size(), outFile);
}

// ============================================================
//  The raw dump file has the module in its memory layout:
//  section data is at its VirtualAddress (RVA) offset.
//  A proper PE file on disk has section data at PointerToRawData.
//
//  This function builds a new file-layout PE by:
//    1. Copying the headers verbatim
//    2. For each section, copying from dump[VirtualAddress]
//       into outbuf[PointerToRawData]
//
//  The result opens correctly in IDA/Ghidra/x64dbg.
// ============================================================
static bool FixPEFromMemory(const std::string& dumpFile, const std::string& peFile) {
    std::ifstream dump(dumpFile, std::ios::binary);
    if (!dump) return false;
    dump.seekg(0, std::ios::end);
    size_t dumpSize = (size_t)dump.tellg();
    dump.seekg(0);
    std::vector<uint8_t> buf(dumpSize);
    dump.read(reinterpret_cast<char*>(buf.data()), dumpSize);
    dump.close();

    if (dumpSize < sizeof(IMAGE_DOS_HEADER)) return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false; // "MZ"

    // Read NT headers generically first — FileHeader is at the same offset
    // in both 32 and 64-bit PE, so we can safely read Machine from it
    // before deciding which typed struct to use.
    auto* ntGeneric = reinterpret_cast<IMAGE_NT_HEADERS*>(buf.data() + dos->e_lfanew);
    if (ntGeneric->Signature != IMAGE_NT_SIGNATURE) return false; // "PE\0\0"

    const bool is64 = ntGeneric->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;

    // SizeOfHeaders differs between 32 and 64-bit optional headers
    const DWORD sizeOfHeaders = is64
        ? reinterpret_cast<IMAGE_NT_HEADERS64*>(ntGeneric)->OptionalHeader.SizeOfHeaders
        : reinterpret_cast<IMAGE_NT_HEADERS32*>(ntGeneric)->OptionalHeader.SizeOfHeaders;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntGeneric);
    const WORD            numSections = ntGeneric->FileHeader.NumberOfSections;

    std::cout << std::format("[*] PE architecture: {}\n", is64 ? "x64" : "x86");

    // Calculate total output size: headers + furthest section end
    size_t outSize = sizeOfHeaders;
    for (const auto& sec : std::span(sections, numSections)) {
        const size_t sectionEnd = static_cast<size_t>(sec.PointerToRawData) + sec.SizeOfRawData;
        if (sectionEnd > outSize) outSize = sectionEnd;
    }

    std::vector<uint8_t> outBuf(outSize, 0);
    memcpy(outBuf.data(), buf.data(), sizeOfHeaders);

    // Copy each section from its in-memory RVA to its on-disk file offset
    for (const auto& sec : std::span(sections, numSections)) {
        const size_t rva = sec.VirtualAddress;
        const size_t rawOff = sec.PointerToRawData;
        size_t       copySize = sec.SizeOfRawData;

        if (rva + copySize > buf.size())
            copySize = (rva < buf.size()) ? buf.size() - rva : 0;
        if (copySize == 0) continue;

        memcpy(outBuf.data() + rawOff, buf.data() + rva, copySize);
    }

    std::ofstream out(peFile, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(outBuf.data()), outBuf.size());

    std::cout << std::format("[+] Fixed PE written: {} ({} KB)\n", peFile, outBuf.size() / 1024);
    return true;
}

int main(int argc, char* argv[]) {
    std::cout << "=== Process Dumper (MemProcFS) ===\n\n";

    // --------------------------------------------------------
    //  Parse -name (required)
    // --------------------------------------------------------
    auto it = std::find(argv + 1, argv + argc, std::string_view("-name"));
    if (it == argv + argc || std::next(it) == argv + argc) {
        std::cout << "Usage:\n"
            << "  dumper.exe -name <ProcessName>\n"
            << "  dumper.exe -name <ProcessName> -module <ModuleName>\n"
            << "  dumper.exe -name <ProcessName> -module <ModuleName> -out <dir>\n";
        return 1;
    }
    const std::string nameArg = *std::next(it);

    // --------------------------------------------------------
    //  Parse -module (optional, defaults to process name)
    // --------------------------------------------------------
    std::string moduleArg = nameArg;   // default: same as process
    it = std::find(argv + 1, argv + argc, std::string_view("-module"));
    if (it != argv + argc && std::next(it) != argv + argc)
        moduleArg = *std::next(it);

    // --------------------------------------------------------
    //  Parse -out (optional)
    // --------------------------------------------------------
    it = std::find(argv + 1, argv + argc, std::string_view("-out"));
    if (it != argv + argc && std::next(it) != argv + argc)
        g_outDir = *std::next(it);

    // --------------------------------------------------------
    //  Init MemProcFS
    // --------------------------------------------------------
    LPCSTR vmmArgs[] = { (LPSTR)"", (LPSTR)"-device", (LPSTR)"FPGA" };
    std::cout << "[*] Initializing MemProcFS...\n";
    g_hVMM = VMMDLL_Initialize(3, vmmArgs);
    if (!g_hVMM) {
        std::cerr << "[!] VMMDLL_Initialize failed.\n";
        return 1;
    }
    std::cout << "[+] Initialized\n\n";

    // --------------------------------------------------------
    //  Find process
    // --------------------------------------------------------
    const DWORD pid = FindPidByName(nameArg);
    if (pid == 0) {
        VMMDLL_Close(g_hVMM);
        return 1;
    }

    // --------------------------------------------------------
    //  Get module base + size
    // --------------------------------------------------------
    ULONG64 modBase = 0;
    DWORD   modSize = 0;
    if (!GetModuleInfo(pid, moduleArg, modBase, modSize)) {
        std::cerr << std::format("[!] Could not find module: {}\n", moduleArg);
        VMMDLL_Close(g_hVMM);
        return 1;
    }

    std::cout << std::format("[*] Module : {}\n", nameArg);
    std::cout << std::format("[*] Base   : 0x{:016X}\n", modBase);
    std::cout << std::format("[*] Size   : 0x{:08X} ({} KB)\n\n", modSize, modSize / 1024);

    // --------------------------------------------------------
    //  Set up output paths
    // --------------------------------------------------------
    std::filesystem::create_directories(g_outDir);

    std::string baseName = nameArg;
    if (const size_t dot = baseName.rfind('.'); dot != std::string::npos)
        baseName = baseName.substr(0, dot);

    const std::string rawFile = std::format("{}/{}_raw.bin", g_outDir, baseName);
    const std::string fixedFile = std::format("{}/{}_fixed.exe", g_outDir, baseName);

    // --------------------------------------------------------
    //  Page walk
    // --------------------------------------------------------
    std::cout << "[*] Starting page walker...\n";
    PageWalker(pid, modBase, modSize, rawFile);

    if (!g_running)
        std::cout << "\n[!] Interrupted by user.\n";

    // --------------------------------------------------------
    //  Fix PE layout
    // --------------------------------------------------------
    std::cout << "\n[*] Fixing PE layout...\n";
    if (!FixPEFromMemory(rawFile, fixedFile)) {
        std::cerr << std::format("[!] FixPE failed — raw dump is still at: {}\n", rawFile);
        VMMDLL_Close(g_hVMM);
        return 1;
    }

    std::cout << std::format("\n[+] Done.\n    Raw dump : {}\n    Fixed PE : {}\n", rawFile, fixedFile);

    VMMDLL_Close(g_hVMM);
    return 0;
}