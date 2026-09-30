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

    // Enumerates every module loaded in the target PID (kernel drivers when
    // pid == 4) with VERSIONINFO enrichment and prints a neutral table sorted
    // alphabetically by name. Includes a TP column showing MemProcFS's module
    // classification (NORMAL / DATA / NOTLINKED / INJECTED) so unlinked
    // modules that MemProcFS still detected (e.g. via PE image identification
    // in the VAD map) are visible even without the -scan-hidden pass.
    static void ListModules(VMM_HANDLE hVMM, DWORD pid);

    // Dumps the kernel's unloaded-driver list (kernel PID 4) or the loader's
    // unloaded-module ring (user PID). Useful for catching short-lived scan
    // modules whose lifetime spans less than one -list-modules poll.
    static void ListUnloadedModules(VMM_HANDLE hVMM, DWORD pid);

    // Walks the VAD tree with fIdentifyModules=TRUE and returns every private,
    // executable region that is NOT covered by an entry in the process's
    // module map. Regions are enriched with a first-page probe: hasMZ +
    // peSizeOfImage. Suitable inputs for -base/-size dumping.
    static std::vector<HiddenRegion> ScanHiddenRegions(VMM_HANDLE hVMM, DWORD pid);

    // Renders the ScanHiddenRegions result as a table with the same styling as
    // ListModules. Kept out of the scanner so callers can reuse the raw data.
    static void PrintHiddenRegions(const std::vector<HiddenRegion>& regions);

    // Probes [base, base+0x1000) for a valid MZ/PE header and returns
    // OptionalHeader.SizeOfImage. Returns 0 if the region does not contain a
    // parseable PE header. Both PE32 and PE32+ are recognized.
    static DWORD ProbePEImageSize(VMM_HANDLE hVMM, DWORD pid, ULONG64 base);

    // Continuous scan loop. Every intervalMs, walks the VAD tree via
    // ScanHiddenRegions and:
    //   - logs '+ VA' when a new region appears
    //   - logs '- VA' when a previously seen region vanishes
    //   - for each new MZ-flagged region, spawns a background PageWalker +
    //     PEFixer that writes a snapshot to outDir. Regions present at
    //     startup are treated as baseline (visible+dumped set) so only new
    //     appearances after the tool starts trigger dumps.
    //
    // maxConcurrent bounds active dump threads; over-the-cap candidates are
    // logged as '!' skipped. Runs until END is pressed. Blocks the caller
    // until all outstanding dumps complete.
    static void WatchHidden(VMM_HANDLE hVMM, DWORD pid, const std::string& outDir,
                            uint32_t intervalMs, size_t maxConcurrent);

    // Resolves a module name pattern (substring or regex) against the module
    // list.  Returns the exact module name on a single match, or empty string
    // on zero / ambiguous matches (printing diagnostics in both cases).
    // A pattern that already matches a module name exactly is returned as-is
    // without enumeration.
    static std::string ResolveModuleName(VMM_HANDLE hVMM, DWORD pid,
                                         const std::string& pattern);
};
