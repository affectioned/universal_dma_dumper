#pragma once
#include <vector>
#include <array>
#include <Windows.h>

// PE metadata fetched from MemProcFS's internal module analysis.
// MemProcFS caches this independently of the process's live virtual memory,
// so it remains valid even when the game has zeroed its own in-memory headers.
struct ModuleLayout {
    bool fWoW64 = false;                              // true = x86 WoW64, false = native x64
    std::vector<IMAGE_SECTION_HEADER>    sections;    // from VMMDLL_ProcessGetSections
    std::array<IMAGE_DATA_DIRECTORY, 16> directories{}; // from VMMDLL_ProcessGetDirectories
    bool valid = false;
};
