#pragma once
#include <string>
#include <atomic>
#include "..\libs\vmmdll.h"

// Walks a module's virtual address range one 4 KB page at a time,
// skipping encrypted (0xCC) and uncommitted (0x00) pages and retrying
// them on subsequent passes until 90% coverage is reached, the 15-minute
// timeout expires, or Stop() is called.
//
// The output file is pre-allocated to the full module size and written
// in-place, so page offsets match the module's virtual memory layout.
class PageWalker {
public:
    PageWalker(VMM_HANDLE hVMM, DWORD pid, ULONG64 base, DWORD imageSize,
               const std::string& outFile);

    // Blocks until the walk completes or is stopped.
    void Run();

    // Signals the walk loop to exit after the current page.
    void Stop();

    bool WasInterrupted() const { return !m_running; }

private:
    static constexpr size_t kPageSize = 0x1000;

    VMM_HANDLE        m_hVMM;
    DWORD             m_pid;
    ULONG64           m_base;
    DWORD             m_imageSize;
    std::string       m_outFile;
    std::atomic<bool> m_running{ true };

    void Preallocate() const;

    static bool IsEncrypted(std::span<const uint8_t> buf);
    static bool IsBlank(std::span<const uint8_t> buf);
};
