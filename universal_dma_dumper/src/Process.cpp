#include "pch.h"
#include "Process.h"

DWORD Process::FindPidByName(VMM_HANDLE hVMM, const std::string& name) {
    DWORD pid = 0;
    if (!VMMDLL_PidGetFromName(hVMM, name.c_str(), &pid)) {
        std::cerr << std::format("[!] Process not found: {}\n", name);
        return 0;
    }
    std::cout << std::format("[+] Found: {} (PID {})\n", name, pid);
    return pid;
}

bool Process::GetModuleInfo(VMM_HANDLE hVMM, DWORD pid, const std::string& moduleName,
                            ULONG64& outBase, DWORD& outSize) {
    // Use MultiByteToWideChar for correct UTF-8 -> UTF-16 conversion
    const int wLen = MultiByteToWideChar(CP_UTF8, 0, moduleName.c_str(), -1, nullptr, 0);
    if (wLen <= 0) return false;
    std::wstring wName(wLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, moduleName.c_str(), -1, wName.data(), wLen);

    PVMMDLL_MAP_MODULEENTRY entry = nullptr;
    // wName owns a non-const buffer — no const_cast needed
    if (!VMMDLL_Map_GetModuleFromNameW(hVMM, pid, wName.data(), &entry, VMMDLL_MODULE_FLAG_NORMAL))
        return false;

    outBase   = entry->vaBase;
    outSize   = entry->cbImageSize;
    VMMDLL_MemFree(entry);
    return true;
}

namespace {
    // UTF-16 wchar_t* -> UTF-8 std::string. Returns empty on null/failure.
    std::string wtou8(const wchar_t* w) {
        if (!w || !*w) return {};
        const int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
        if (len <= 1) return {};
        std::string out(static_cast<size_t>(len) - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), len, nullptr, nullptr);
        return out;
    }

    // Truncate a UTF-8 string to `width` display columns (naive: byte count).
    // Good enough for the ASCII-heavy CompanyName / path strings we render.
    std::string clip(std::string s, size_t width) {
        if (s.size() > width) {
            s.resize(width);
            if (width >= 3) s.replace(width - 3, 3, "...");
        }
        return s;
    }
}

void Process::ListModules(VMM_HANDLE hVMM, DWORD pid) {
    PVMMDLL_MAP_MODULE pMap = nullptr;
    if (!VMMDLL_Map_GetModuleW(hVMM, pid, &pMap, VMMDLL_MODULE_FLAG_VERSIONINFO)) {
        std::cerr << "[!] ListModules: VMMDLL_Map_GetModuleW failed\n";
        return;
    }

    struct Row {
        ULONG64 vaBase;
        DWORD   cbImageSize;
        DWORD   cIAT;
        std::string name;
        std::string company;
        std::string fullName;
    };
    std::vector<Row> rows;
    rows.reserve(pMap->cMap);
    for (DWORD i = 0; i < pMap->cMap; ++i) {
        const auto& e = pMap->pMap[i];
        Row r{
            .vaBase       = e.vaBase,
            .cbImageSize  = e.cbImageSize,
            .cIAT         = e.cIAT,
            .name         = wtou8(e.wszText),
            .company      = e.pExVersionInfo ? wtou8(e.pExVersionInfo->wszCompanyName) : std::string{},
            .fullName     = wtou8(e.wszFullName),
        };
        rows.push_back(std::move(r));
    }
    VMMDLL_MemFree(pMap);

    // Alphabetical by name (case-insensitive, ASCII-only fold — good enough for module names).
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        return std::lexicographical_compare(
            a.name.begin(), a.name.end(),
            b.name.begin(), b.name.end(),
            [](char x, char y) {
                return std::tolower(static_cast<unsigned char>(x)) <
                       std::tolower(static_cast<unsigned char>(y));
            });
    });

    // ------------------- render -------------------
    constexpr size_t kNameCol    = 40;
    constexpr size_t kCompanyCol = 34;
    constexpr size_t kPathCol    = 60;

    std::cout << std::format("\n[+] {} modules in PID {}:\n\n", rows.size(), pid);
    std::cout << std::format("  {:<18}  {:>9}  {:>5}  {:<{}}  {:<{}}  {}\n",
                             "BASE", "SIZE", "IAT",
                             "NAME",    kNameCol,
                             "COMPANY", kCompanyCol,
                             "PATH");
    std::cout << "  " << std::string(18 + 2 + 9 + 2 + 5 + 2 + kNameCol + 2 + kCompanyCol + 2 + kPathCol, '-') << '\n';

    for (const auto& r : rows) {
        std::cout << std::format("  0x{:016X}  {:>9}  {:>5}  {:<{}}  {:<{}}  {}\n",
                                 r.vaBase,
                                 std::format("0x{:07X}", r.cbImageSize),
                                 r.cIAT,
                                 clip(r.name,    kNameCol),    kNameCol,
                                 clip(r.company, kCompanyCol), kCompanyCol,
                                 clip(r.fullName, kPathCol));
    }
    std::cout << '\n';
}

ModuleLayout Process::GetModuleLayout(VMM_HANDLE hVMM, DWORD pid, const std::string& moduleName) {
    ModuleLayout layout;

    const int wLen = MultiByteToWideChar(CP_UTF8, 0, moduleName.c_str(), -1, nullptr, 0);
    if (wLen <= 0) return layout;
    std::wstring wName(wLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, moduleName.c_str(), -1, wName.data(), wLen);

    // Fetch fWoW64 from the module map entry
    PVMMDLL_MAP_MODULEENTRY entry = nullptr;
    if (VMMDLL_Map_GetModuleFromNameW(hVMM, pid, wName.data(), &entry, VMMDLL_MODULE_FLAG_NORMAL)) {
        layout.fWoW64 = entry->fWoW64;
        VMMDLL_MemFree(entry);
    }

    // Two-call pattern: first call with null buffer to get section count
    DWORD cSections = 0;
    VMMDLL_ProcessGetSectionsW(hVMM, pid, wName.data(), nullptr, 0, &cSections);
    if (cSections == 0) {
        std::cerr << "[!] GetModuleLayout: no sections returned by MemProcFS\n";
        return layout;
    }

    layout.sections.resize(cSections);
    if (!VMMDLL_ProcessGetSectionsW(hVMM, pid, wName.data(),
                                    layout.sections.data(), cSections, &cSections)) {
        std::cerr << "[!] GetModuleLayout: VMMDLL_ProcessGetSections failed\n";
        return layout;
    }

    // Fetch all 16 data directory entries
    if (!VMMDLL_ProcessGetDirectoriesW(hVMM, pid, wName.data(), layout.directories.data())) {
        std::cerr << "[!] GetModuleLayout: VMMDLL_ProcessGetDirectories failed\n";
        return layout;
    }

    layout.valid = true;
    std::cout << std::format("[+] MemProcFS module layout: {} sections, fWoW64={}\n",
                             cSections, layout.fWoW64);
    return layout;
}
