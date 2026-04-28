#pragma once
#include <string>
#include "Types.h"

// Converts a raw memory-layout dump into a proper file-layout PE.
//
// The raw dump has section data at each section's VirtualAddress (RVA).
// A loadable PE on disk has section data at PointerToRawData.
// This class rebuilds the file-layout PE so IDA/Ghidra/x64dbg can open it directly.
//
// layout (optional): PE metadata fetched from MemProcFS's internal module analysis.
// When valid, the section table and data directories from MemProcFS are used instead
// of whatever is in the dump's virtual memory — recovering correct structure even
// when the game has zeroed or corrupted its own in-memory PE headers.
class PEFixer {
public:
    static bool Fix(const std::string& dumpFile, const std::string& peFile,
                    const ModuleLayout& layout = {});
};
