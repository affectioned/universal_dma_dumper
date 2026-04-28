#pragma once
#include <string>
#include "..\libs\vmmdll.h"
#include "Types.h"

class Process {
public:
    // Returns 0 and prints an error on failure.
    static DWORD FindPidByName(VMM_HANDLE hVMM, const std::string& name);

    // Fills outBase and outSize from the named module's map entry.
    // Returns false if the module is not found.
    static bool GetModuleInfo(VMM_HANDLE hVMM, DWORD pid, const std::string& moduleName,
                              ULONG64& outBase, DWORD& outSize);

    // Fetches the section table and data directories for a module using
    // MemProcFS's internal module analysis. This data is cached by MemProcFS
    // independently of the process's live virtual memory, so it remains valid
    // even when the game has zeroed or corrupted its own in-memory PE headers.
    static ModuleLayout GetModuleLayout(VMM_HANDLE hVMM, DWORD pid, const std::string& moduleName);
};
