#pragma once
#include <vector>
#include <array>
#include <string>
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

// A private, executable VAD region that is NOT covered by any entry in the
// process's module map. Candidate for "manually-mapped module" — modules that
// unlink themselves from the PEB after loading (VAC scan modules, most
// user-mode cheat protections, some info-stealer loaders).
//
// Populated from VMMDLL_Map_GetVadW with fIdentifyModules=TRUE:
//   - vaStart / vaEnd    : VAD range. vaEnd is EXCLUSIVE (one past the last
//                          byte). MemProcFS returns an inclusive last-byte
//                          address; ScanHiddenRegions adds 1 so that
//                          (vaEnd - vaStart) is the real byte size.
//   - protection         : raw 5-bit MM_PROTECTION_MASK value
//   - fImage             : VAD backs a mapped PE image (should be false for hidden mods)
//   - fPrivate           : VAD is private memory (VirtualAlloc / NtAllocateVirtualMemory)
//   - hasMZ              : first two bytes at vaStart are "MZ"
//   - peSizeOfImage      : if hasMZ and PE header parses, OptionalHeader.SizeOfImage; else 0
//   - vadText            : VMMDLL_MAP_VADENTRY.wszText (module hint when MemProcFS identified one)
struct HiddenRegion {
    ULONG64 vaStart      = 0;
    ULONG64 vaEnd        = 0;    // EXCLUSIVE — see comment above
    DWORD   protection   = 0;
    bool    fImage       = false;
    bool    fPrivate     = false;
    bool    hasMZ        = false;
    DWORD   peSizeOfImage = 0;
    std::string vadText;
};
