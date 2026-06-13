#include "pch.h"
#include "PageWalker.h"

PageWalker::PageWalker(VMM_HANDLE hVMM, DWORD pid, ULONG64 base, DWORD imageSize,
                       const std::string& outFile)
    : m_hVMM(hVMM), m_pid(pid), m_base(base), m_imageSize(imageSize), m_outFile(outFile) {}

void PageWalker::Stop() {
    m_running = false;
}

bool PageWalker::IsEncrypted(std::span<const uint8_t> buf) {
    return std::ranges::all_of(buf, [](uint8_t b) { return b == 0xCC; });
}

bool PageWalker::IsBlank(std::span<const uint8_t> buf) {
    return std::ranges::all_of(buf, [](uint8_t b) { return b == 0x00; });
}

void PageWalker::Preallocate() const {
    std::ofstream pre(m_outFile, std::ios::binary | std::ios::trunc);
    std::vector<uint8_t> zero(m_imageSize, 0);
    pre.write(reinterpret_cast<const char*>(zero.data()), m_imageSize);
}

std::vector<ULONG64> PageWalker::BuildCommittedPageList() const {
    std::vector<ULONG64> pages;

    PVMMDLL_MAP_PTE pteMap = nullptr;
    if (!VMMDLL_Map_GetPteW(m_hVMM, m_pid, FALSE, &pteMap) || !pteMap)
        return pages;

    const ULONG64 rangeStart = m_base;
    const ULONG64 rangeEnd   = m_base + m_imageSize;

    // PTE map entries are sorted by vaBase. Each entry covers `cPages`
    // contiguous 4 KB pages starting at vaBase. Enumerate every page that
    // falls inside our module's VA range.
    for (DWORD i = 0; i < pteMap->cMap; ++i) {
        const auto& e = pteMap->pMap[i];
        const ULONG64 entryStart = e.vaBase;
        const ULONG64 entryEnd   = e.vaBase + e.cPages * kPageSize;

        if (entryEnd <= rangeStart) continue;
        if (entryStart >= rangeEnd) break;

        const ULONG64 first = std::max(entryStart, rangeStart) & ~(kPageSize - 1);
        const ULONG64 last  = std::min(entryEnd,   rangeEnd);

        for (ULONG64 addr = first; addr < last; addr += kPageSize)
            pages.push_back(addr);
    }

    VMMDLL_MemFree(pteMap);
    return pages;
}

// FNV-1a 64-bit. Used to fingerprint pages for double-read consistency without
// keeping a 4 KB snapshot per pending page (8 bytes per page instead).
static uint64_t HashPage(std::span<const uint8_t> buf) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (uint8_t b : buf) h = (h ^ b) * 0x100000001b3ULL;
    return h;
}

void PageWalker::Run() {
    Preallocate();

    std::fstream outf(m_outFile, std::ios::in | std::ios::out | std::ios::binary);
    if (!outf) {
        std::cerr << std::format("[!] Cannot open output file: {}\n", m_outFile);
        return;
    }

    std::vector<uint8_t>                  pageBuf(kPageSize);
    std::unordered_set<ULONG64>           confirmedPages;   // two consistent reads, no longer retried
    std::unordered_map<ULONG64, uint64_t> pendingHashes;    // hash of last successful read
    std::unordered_set<ULONG64>           evictedPages;     // returned all-zero too many times in a row
    std::unordered_map<ULONG64, uint32_t> zeroReadCount;    // consecutive all-zero reads per page

    // Query the process PTE map and walk only pages it reports as committed.
    // For a heavily-protected ~1 GB module this typically excludes hundreds of
    // thousands of paged-out / never-committed pages that the linear walk
    // would otherwise re-read every pass.
    std::vector<ULONG64> walkOrder = BuildCommittedPageList();
    const bool usingPteMap = !walkOrder.empty();
    if (!usingPteMap) {
        const size_t total = (m_imageSize + kPageSize - 1) / kPageSize;
        walkOrder.reserve(total);
        for (ULONG64 addr = m_base; addr < m_base + m_imageSize; addr += kPageSize)
            walkOrder.push_back(addr);
    }

    const size_t totalPages       = (m_imageSize + kPageSize - 1) / kPageSize;
    const size_t candidatePages   = walkOrder.size();
    const auto   startTime        = std::chrono::steady_clock::now();
    auto         lastProgress     = startTime;

    if (usingPteMap) {
        std::cout << std::format("[*] PTE map: {} committed pages of {} total "
                                 "({:.1f}% — skipping {} uncommitted)\n",
                                 candidatePages, totalPages,
                                 candidatePages * 100.0 / static_cast<double>(totalPages),
                                 totalPages - candidatePages);
    } else {
        std::cout << "[~] PTE map unavailable — falling back to linear walk\n";
    }

    std::cout << std::format("[*] Starting page walk — {} candidate pages, "
                             "{}s stall timeout, {}min hard cap, "
                             "evict after {} consecutive zero reads\n",
                             candidatePages,
                             std::chrono::duration_cast<std::chrono::seconds>(kStallTimeout).count(),
                             std::chrono::duration_cast<std::chrono::minutes>(kHardTimeout).count(),
                             kZeroEvictThreshold);

    while (m_running) {
        // Check if END is currently held down
        if (GetAsyncKeyState(VK_END) & 0x8000) Stop();

        for (ULONG64 addr : walkOrder) {
            if (!m_running) break;
            if (confirmedPages.contains(addr)) continue;
            if (evictedPages.contains(addr))   continue;

            // VMMDLL_FLAG_ZEROPAD_ON_FAIL: returns zeros for unreadable pages
            // rather than failing, so we can detect and retry them next pass.
            DWORD bytesRead = 0;
            if (!VMMDLL_MemReadEx(m_hVMM, m_pid, addr, pageBuf.data(),
                                  static_cast<DWORD>(kPageSize), &bytesRead,
                                  VMMDLL_FLAG_ZEROPAD_ON_FAIL))
                continue;

            // All-zero reads are most often uncommitted pages or ZEROPAD'd
            // failures. Encrypted pages (all 0xCC) might decrypt later, so
            // they're retried indefinitely — but zero pages are evicted after
            // kZeroEvictThreshold consecutive failures so they stop resetting
            // the stall timer in BuildCommittedPageList's blind spots.
            if (IsBlank(pageBuf)) {
                if (++zeroReadCount[addr] >= kZeroEvictThreshold) {
                    evictedPages.insert(addr);
                    zeroReadCount.erase(addr);
                }
                continue;
            }
            if (IsEncrypted(pageBuf))
                continue; // protector hasn't decrypted yet — keep retrying

            zeroReadCount.erase(addr);

            const uint64_t h = HashPage(pageBuf);
            auto it = pendingHashes.find(addr);

            if (it == pendingHashes.end()) {
                // First successful read — write what we have so the file is never
                // worse than "best-so-far", but don't confirm until a second read agrees.
                outf.seekp(static_cast<std::streamoff>(addr - m_base));
                outf.write(reinterpret_cast<const char*>(pageBuf.data()), kPageSize);
                pendingHashes.emplace(addr, h);
                lastProgress = std::chrono::steady_clock::now();
            } else if (it->second == h) {
                // Two consecutive identical reads — page is stable, accept it.
                confirmedPages.insert(addr);
                pendingHashes.erase(it);
                lastProgress = std::chrono::steady_clock::now();
                std::cout << std::format("  [p] 0x{:016X}  ({}/{})\n",
                                         addr, confirmedPages.size(), totalPages);
            } else {
                // Content changed since last read — page is decrypting in place.
                // Overwrite with the newer version and keep refining.
                outf.seekp(static_cast<std::streamoff>(addr - m_base));
                outf.write(reinterpret_cast<const char*>(pageBuf.data()), kPageSize);
                it->second = h;
                lastProgress = std::chrono::steady_clock::now();
            }
        }

        // Flush once per pass rather than per page
        outf.flush();

        const auto now = std::chrono::steady_clock::now();
        if (now - lastProgress > kStallTimeout) {
            const auto stallSecs = std::chrono::duration_cast<std::chrono::seconds>(
                                       now - lastProgress).count();
            const double coverage = static_cast<double>(confirmedPages.size()) /
                                    static_cast<double>(candidatePages);
            std::cout << std::format("[!] Stalled — no new pages for {}s. "
                                     "{} confirmed, {} pending, {} evicted "
                                     "({:.1f}% of candidates confirmed).\n",
                                     stallSecs, confirmedPages.size(),
                                     pendingHashes.size(), evictedPages.size(),
                                     coverage * 100.0);
            break;
        }

        if (now - startTime > kHardTimeout) {
            const double coverage = static_cast<double>(confirmedPages.size()) /
                                    static_cast<double>(candidatePages);
            std::cout << std::format("[!] Hard timeout reached — {} confirmed, "
                                     "{} pending, {} evicted "
                                     "({:.1f}% of candidates confirmed).\n",
                                     confirmedPages.size(), pendingHashes.size(),
                                     evictedPages.size(), coverage * 100.0);
            break;
        }

        // Brief sleep before the next retry pass to avoid hammering the DMA bus
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    outf.close();
    std::cout << std::format("[+] Page walk done — {} confirmed pages written to {} "
                             "({} pending kept best-so-far, {} unreadable pages evicted)\n",
                             confirmedPages.size(), m_outFile,
                             pendingHashes.size(), evictedPages.size());
}
