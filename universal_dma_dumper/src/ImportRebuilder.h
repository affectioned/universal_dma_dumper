#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include "..\libs\vmmdll.h"

// Rebuilds the IMPORT and IAT data directories of a dumped PE by:
//   1. Enumerating loaded modules in the target process via MemProcFS.
//   2. Reading each module's export table to build VA -> (module, function).
//   3. Scanning the dumped PE's read-only data sections for 8-byte values
//      that hit the export map — those are the original resolved IAT slots.
//   4. Appending a new ".idata2" section to the output buffer that holds
//      synthetic IMAGE_IMPORT_DESCRIPTOR / INT / IAT / name pool blocks.
//   5. Pointing IMAGE_DIRECTORY_ENTRY_IMPORT and ..._IAT at the new section.
//   6. Patching call/jmp displacements (`FF 15`, `FF 25`, `48 FF 25`) in
//      executable sections so call sites point at the synthetic IAT — without
//      this, IDA shows raw `qword_xxxx` references instead of import names.
//
// Skipped when:
//   - hVMM is null or pid is 0 (the dump was loaded from disk without VMM access).
//   - The PE is x86 (this rebuilder is x64-only — most DMA targets are x64).
//   - SizeOfHeaders has no room for one more IMAGE_SECTION_HEADER.
//
// Returns true if a new section was appended and the directories were updated.
// Returns false if no imports were found or the rebuild had to be skipped.
// The output buffer is left untouched when false is returned.
class ImportRebuilder {
public:
    static bool Rebuild(std::vector<uint8_t>& outBuf,
                        std::vector<IMAGE_SECTION_HEADER>& workingSections,
                        VMM_HANDLE hVMM,
                        DWORD pid,
                        ULONG64 targetModBase);
};
