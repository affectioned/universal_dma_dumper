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

void PageWalker::Run() {
    Preallocate();

    std::fstream outf(m_outFile, std::ios::in | std::ios::out | std::ios::binary);
    if (!outf) {
        std::cerr << std::format("[!] Cannot open output file: {}\n", m_outFile);
        return;
    }

    std::vector<uint8_t>        pageBuf(kPageSize);
    std::unordered_set<ULONG64> dumpedPages;

    const size_t totalPages = (m_imageSize + kPageSize - 1) / kPageSize;
    const auto   startTime  = std::chrono::steady_clock::now();

    std::cout << std::format("[*] Starting page walk — {} pages total\n", totalPages);

    while (m_running) {
        // Check if END is currently held down
        if (GetAsyncKeyState(VK_END) & 0x8000) Stop();

        for (ULONG64 addr = m_base; addr < m_base + m_imageSize; addr += kPageSize) {
            if (!m_running) break;
            if (dumpedPages.contains(addr)) continue;

            // VMMDLL_FLAG_ZEROPAD_ON_FAIL: returns zeros for unreadable pages
            // rather than failing, so we can detect and retry them next pass.
            DWORD bytesRead = 0;
            if (!VMMDLL_MemReadEx(m_hVMM, m_pid, addr, pageBuf.data(),
                                  static_cast<DWORD>(kPageSize), &bytesRead,
                                  VMMDLL_FLAG_ZEROPAD_ON_FAIL))
                continue;

            if (IsBlank(pageBuf) || IsEncrypted(pageBuf))
                continue; // not yet executed or not yet decrypted — retry next pass

            outf.seekp(static_cast<std::streamoff>(addr - m_base));
            outf.write(reinterpret_cast<const char*>(pageBuf.data()), kPageSize);
            dumpedPages.insert(addr);

            std::cout << std::format("  [p] 0x{:016X}  ({}/{})\n",
                                     addr, dumpedPages.size(), totalPages);
        }

        // Flush once per pass rather than per page
        outf.flush();

        const double coverage = static_cast<double>(dumpedPages.size()) /
                                static_cast<double>(totalPages);

        if (coverage >= 0.90) {
            std::cout << std::format("[+] 90%% coverage reached — stopping walk "
                                     "({} pages, {:.1f}%).\n",
                                     dumpedPages.size(), coverage * 100.0);
            break;
        }

        if (std::chrono::steady_clock::now() - startTime > std::chrono::minutes(15)) {
            std::cout << std::format("[!] 15-minute timeout reached ({} pages, {:.1f}%).\n",
                                     dumpedPages.size(), coverage * 100.0);
            break;
        }

        // Brief sleep before the next retry pass to avoid hammering the DMA bus
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    outf.close();
    std::cout << std::format("[+] Page walk done — {} pages written to {}\n",
                             dumpedPages.size(), m_outFile);
}
