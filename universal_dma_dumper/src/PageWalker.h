#pragma once
#include <string>
#include <atomic>
#include "..\libs\vmmdll.h"

// Walks a module's virtual address range one 4 KB page at a time,
// skipping encrypted (0xCC) and uncommitted (0x00) pages and retrying
// them on subsequent passes until the dump stalls (no new page writes
// for kStallTimeout), the 15-minute hard cap expires, or Stop() is
// called. A page is "confirmed" only after two consecutive reads produce
// identical content (double-read consistency); pages whose content keeps
// changing are treated as still decrypting and refined on each pass.
//
// Iteration is restricted to pages the PTE map reports as committed in
// the process, which skips entire uncommitted ranges (paged-out code,
// reserved-but-uncommitted regions) that would otherwise burn DMA
// bandwidth returning zeros every pass. Within the committed set, pages
// that return all-zero kZeroEvictThreshold consecutive passes are evicted
// from the rotation so the stall timer can fire when real progress stops.
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
    static constexpr size_t   kPageSize           = 0x1000;
    static constexpr auto     kStallTimeout       = std::chrono::seconds(90);
    static constexpr auto     kHardTimeout        = std::chrono::minutes(15);
    static constexpr uint32_t kZeroEvictThreshold = 5;

    VMM_HANDLE        m_hVMM;
    DWORD             m_pid;
    ULONG64           m_base;
    DWORD             m_imageSize;
    std::string       m_outFile;
    std::atomic<bool> m_running{ true };

    void Preallocate() const;

    // Builds the list of page addresses within [m_base, m_base+m_imageSize)
    // that the PTE map reports as committed. Returns an empty vector on
    // failure; the caller should fall back to a linear walk in that case.
    std::vector<ULONG64> BuildCommittedPageList() const;

    static bool IsEncrypted(std::span<const uint8_t> buf);
    static bool IsBlank(std::span<const uint8_t> buf);
};
