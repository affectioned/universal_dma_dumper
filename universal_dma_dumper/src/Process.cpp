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
