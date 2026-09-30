#include "pch.h"
#include "Process.h"
#include "PageWalker.h"
#include "PEFixer.h"
#include <ctime>

DWORD Process::FindPidByName(VMM_HANDLE hVMM, const std::string& name) {
    DWORD pid = 0;
    if (!VMMDLL_PidGetFromName(hVMM, name.c_str(), &pid)) {
        std::cerr << std::format("[!] Process not found: {}\n", name);
        return 0;
    }
    std::cout << std::format("[+] Found: {} (PID {})\n", name, pid);
    return pid;
}

bool Process::GetModuleInfo(VMM_HANDLE hVMM, DWORD pid, const std::string& moduleName,
                            ULONG64& outBase, DWORD& outSize) {
    // Use MultiByteToWideChar for correct UTF-8 -> UTF-16 conversion
    const int wLen = MultiByteToWideChar(CP_UTF8, 0, moduleName.c_str(), -1, nullptr, 0);
    if (wLen <= 0) return false;
    std::wstring wName(wLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, moduleName.c_str(), -1, wName.data(), wLen);

    PVMMDLL_MAP_MODULEENTRY entry = nullptr;
    // wName owns a non-const buffer — no const_cast needed
    if (!VMMDLL_Map_GetModuleFromNameW(hVMM, pid, wName.data(), &entry, VMMDLL_MODULE_FLAG_NORMAL))
        return false;

    outBase   = entry->vaBase;
    outSize   = entry->cbImageSize;
    VMMDLL_MemFree(entry);
    return true;
}

namespace {
    // UTF-16 wchar_t* -> UTF-8 std::string. Returns empty on null/failure.
    std::string wtou8(const wchar_t* w) {
        if (!w || !*w) return {};
        const int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
        if (len <= 1) return {};
        std::string out(static_cast<size_t>(len) - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), len, nullptr, nullptr);
        return out;
    }

    // Truncate a UTF-8 string to `width` display columns (naive: byte count).
    // Good enough for the ASCII-heavy CompanyName / path strings we render.
    std::string clip(std::string s, size_t width) {
        if (s.size() > width) {
            s.resize(width);
            if (width >= 3) s.replace(width - 3, 3, "...");
        }
        return s;
    }
}

void Process::ListModules(VMM_HANDLE hVMM, DWORD pid) {
    PVMMDLL_MAP_MODULE pMap = nullptr;
    if (!VMMDLL_Map_GetModuleW(hVMM, pid, &pMap, VMMDLL_MODULE_FLAG_VERSIONINFO)) {
        std::cerr << "[!] ListModules: VMMDLL_Map_GetModuleW failed\n";
        return;
    }

    struct Row {
        ULONG64 vaBase;
        DWORD   cbImageSize;
        DWORD   cIAT;
        VMMDLL_MODULE_TP tp;
        std::string name;
        std::string company;
        std::string fullName;
    };
    std::vector<Row> rows;
    rows.reserve(pMap->cMap);
    for (DWORD i = 0; i < pMap->cMap; ++i) {
        const auto& e = pMap->pMap[i];
        Row r{
            .vaBase       = e.vaBase,
            .cbImageSize  = e.cbImageSize,
            .cIAT         = e.cIAT,
            .tp           = e.tp,
            .name         = wtou8(e.wszText),
            .company      = e.pExVersionInfo ? wtou8(e.pExVersionInfo->wszCompanyName) : std::string{},
            .fullName     = wtou8(e.wszFullName),
        };
        rows.push_back(std::move(r));
    }
    VMMDLL_MemFree(pMap);

    // Human-readable TP tag. NOTLINKED/INJECTED are what we care about: MemProcFS
    // detected a PE image in a VAD but the entry is missing from the loader
    // lists (or the loader entry is fake). See VMMDLL_MODULE_TP in vmmdll.h.
    auto tpStr = [](VMMDLL_MODULE_TP t) -> const char* {
        switch (t) {
            case VMMDLL_MODULE_TP_NORMAL:    return "NORMAL";
            case VMMDLL_MODULE_TP_DATA:      return "DATA";
            case VMMDLL_MODULE_TP_NOTLINKED: return "NOTLINK";
            case VMMDLL_MODULE_TP_INJECTED:  return "INJECT";
            default:                         return "?";
        }
    };

    // Alphabetical by name (case-insensitive, ASCII-only fold — good enough for module names).
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        return std::lexicographical_compare(
            a.name.begin(), a.name.end(),
            b.name.begin(), b.name.end(),
            [](char x, char y) {
                return std::tolower(static_cast<unsigned char>(x)) <
                       std::tolower(static_cast<unsigned char>(y));
            });
    });

    // ------------------- render -------------------
    constexpr size_t kNameCol    = 40;
    constexpr size_t kCompanyCol = 34;
    constexpr size_t kPathCol    = 60;
    constexpr size_t kTpCol      = 7;

    std::cout << std::format("\n[+] {} modules in PID {}:\n\n", rows.size(), pid);
    std::cout << std::format("  {:<18}  {:>9}  {:>5}  {:<{}}  {:<{}}  {:<{}}  {}\n",
                             "BASE", "SIZE", "IAT",
                             "TP",      kTpCol,
                             "NAME",    kNameCol,
                             "COMPANY", kCompanyCol,
                             "PATH");
    std::cout << "  " << std::string(18 + 2 + 9 + 2 + 5 + 2 + kTpCol + 2 + kNameCol + 2 + kCompanyCol + 2 + kPathCol, '-') << '\n';

    for (const auto& r : rows) {
        std::cout << std::format("  0x{:016X}  {:>9}  {:>5}  {:<{}}  {:<{}}  {:<{}}  {}\n",
                                 r.vaBase,
                                 std::format("0x{:07X}", r.cbImageSize),
                                 r.cIAT,
                                 tpStr(r.tp),                  kTpCol,
                                 clip(r.name,    kNameCol),    kNameCol,
                                 clip(r.company, kCompanyCol), kCompanyCol,
                                 clip(r.fullName, kPathCol));
    }
    std::cout << '\n';
}

void Process::ListUnloadedModules(VMM_HANDLE hVMM, DWORD pid) {
    PVMMDLL_MAP_UNLOADEDMODULE pMap = nullptr;
    if (!VMMDLL_Map_GetUnloadedModuleW(hVMM, pid, &pMap)) {
        std::cerr << "[!] ListUnloadedModules: VMMDLL_Map_GetUnloadedModuleW failed\n";
        return;
    }

    std::cout << std::format("\n[+] {} unloaded modules in PID {}:\n\n", pMap->cMap, pid);
    if (pMap->cMap == 0) {
        VMMDLL_MemFree(pMap);
        std::cout << "  (empty)\n";
        return;
    }

    std::cout << std::format("  {:<18}  {:>9}  {:<40}\n", "BASE", "SIZE", "NAME");
    std::cout << "  " << std::string(18 + 2 + 9 + 2 + 40, '-') << '\n';
    for (DWORD i = 0; i < pMap->cMap; ++i) {
        const auto& e = pMap->pMap[i];
        std::cout << std::format("  0x{:016X}  {:>9}  {}\n",
                                 e.vaBase,
                                 std::format("0x{:07X}", e.cbImageSize),
                                 clip(wtou8(e.wszText), 40));
    }
    std::cout << '\n';
    VMMDLL_MemFree(pMap);
}

// VAD Protection is a 5-bit MM_PROTECTION_MASK value. Low three bits encode
// the base protection (0=noaccess, 1=RO, 2=X, 3=XR, 4=RW, 5=WCOPY,
// 6=XRW, 7=XWCOPY); bits 3-4 flag guard/nocache/writecombine. Bit 1 of the
// low three bits is the execute bit, so `(p & 2) != 0` covers every X state.
static bool VadIsExecutable(DWORD prot) { return (prot & 2) != 0; }

// One-line human-readable protection string. Uses the same short form as
// x64dbg / Process Hacker so it matches what a UC reader expects to see.
static const char* VadProtStr(DWORD prot) {
    switch (prot & 7) {
        case 0: return "----";
        case 1: return "R---";
        case 2: return "--X-";
        case 3: return "R-X-";
        case 4: return "RW--";
        case 5: return "RWC-";
        case 6: return "RWX-";
        case 7: return "RWXC";
    }
    return "?";
}

DWORD Process::ProbePEImageSize(VMM_HANDLE hVMM, DWORD pid, ULONG64 base) {
    uint8_t buf[0x400] = {};
    DWORD   cbRead = 0;
    // ZEROPAD_ON_FAIL so an unreadable page returns zeros instead of failing —
    // matches the page walker's philosophy and lets us handle partial reads.
    VMMDLL_MemReadEx(hVMM, pid, base, buf, sizeof(buf), &cbRead,
                     VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOCACHE);
    if (cbRead < sizeof(IMAGE_DOS_HEADER)) return 0;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (dos->e_lfanew <= 0 || static_cast<DWORD>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > sizeof(buf))
        return 0;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        return reinterpret_cast<IMAGE_NT_HEADERS64*>(nt)->OptionalHeader.SizeOfImage;
    if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        return reinterpret_cast<IMAGE_NT_HEADERS32*>(nt)->OptionalHeader.SizeOfImage;
    return 0;
}

std::vector<HiddenRegion> Process::ScanHiddenRegions(VMM_HANDLE hVMM, DWORD pid, bool* outOk) {
    std::vector<HiddenRegion> out;
    if (outOk) *outOk = false;

    // Build a sorted [base, end) list of every module the loader knows about so
    // we can quickly reject VAD ranges that are already covered. NOTLINKED /
    // INJECTED modules that MemProcFS identified are included here too — those
    // are already surfaced by -list-modules, so no need to duplicate them.
    PVMMDLL_MAP_MODULE pModMap = nullptr;
    struct ModRange { ULONG64 base; ULONG64 end; };
    std::vector<ModRange> modRanges;
    if (VMMDLL_Map_GetModuleW(hVMM, pid, &pModMap, VMMDLL_MODULE_FLAG_NORMAL)) {
        modRanges.reserve(pModMap->cMap);
        for (DWORD i = 0; i < pModMap->cMap; ++i)
            modRanges.push_back({ pModMap->pMap[i].vaBase,
                                  pModMap->pMap[i].vaBase + pModMap->pMap[i].cbImageSize });
        VMMDLL_MemFree(pModMap);
        std::sort(modRanges.begin(), modRanges.end(),
                  [](const ModRange& a, const ModRange& b) { return a.base < b.base; });
    }
    auto coveredByModule = [&](ULONG64 va) {
        for (const auto& r : modRanges)
            if (va >= r.base && va < r.end) return true;
        return false;
    };

    // fIdentifyModules=TRUE asks MemProcFS to run its PE image identifier over
    // every VAD; when it finds a valid image the entry's wszText is populated
    // with a friendly hint. That hint is what makes truly-hidden PE images
    // pop out of the noise even before we probe for MZ ourselves.
    PVMMDLL_MAP_VAD pVad = nullptr;
    if (!VMMDLL_Map_GetVadW(hVMM, pid, /*fIdentifyModules=*/TRUE, &pVad)) {
        // Silent when caller wants to handle the failure (WatchHidden loops
        // through here every tick; noisy cerr on process death spams the
        // console). One-shot callers still see the error via outOk == nullptr.
        if (!outOk)
            std::cerr << "[!] ScanHiddenRegions: VMMDLL_Map_GetVadW failed\n";
        return out;
    }

    for (DWORD i = 0; i < pVad->cMap; ++i) {
        const auto& v = pVad->pMap[i];

        // We only care about private, executable regions the loader does not
        // know about. Image-backed VADs are file-mapped PEs (already surfaced
        // via the module map), stacks/TEBs/heaps are legit private RX rarely,
        // and non-executable regions can't hold running code.
        if (v.fImage)                    continue;
        if (!v.fPrivateMemory)           continue;
        if (!VadIsExecutable(v.Protection)) continue;
        if (v.fStack || v.fTeb)          continue;
        if (coveredByModule(v.vaStart))  continue;

        HiddenRegion h{
            .vaStart       = v.vaStart,
            // MemProcFS stores vaEnd as the INCLUSIVE last byte address
            // (a page returns vaEnd = vaStart + 0xFFF). Normalize to
            // exclusive-end so (vaEnd - vaStart) is the real byte size.
            .vaEnd         = v.vaEnd + 1,
            .protection    = v.Protection,
            .fImage        = static_cast<bool>(v.fImage),
            .fPrivate      = static_cast<bool>(v.fPrivateMemory),
        };
        h.vadText = wtou8(v.wszText);
        h.peSizeOfImage = ProbePEImageSize(hVMM, pid, v.vaStart);
        h.hasMZ = (h.peSizeOfImage != 0);
        out.push_back(std::move(h));
    }
    VMMDLL_MemFree(pVad);
    if (outOk) *outOk = true;

    // MZ candidates first — those are almost certainly manually-mapped PEs and
    // are the interesting ones. Non-MZ private RX regions are usually JIT/JS
    // engine code, shellcode payloads, or trampoline pools.
    std::sort(out.begin(), out.end(), [](const HiddenRegion& a, const HiddenRegion& b) {
        if (a.hasMZ != b.hasMZ) return a.hasMZ;
        return a.vaStart < b.vaStart;
    });
    return out;
}

void Process::PrintHiddenRegions(const std::vector<HiddenRegion>& regions) {
    std::cout << std::format("\n[+] {} hidden executable regions:\n\n", regions.size());
    if (regions.empty()) {
        std::cout << "  (none — no private RX VADs outside the loader's module map)\n\n";
        return;
    }

    constexpr size_t kHintCol = 40;
    std::cout << std::format("  {:<18}  {:>9}  {:<5}  {:<3}  {:>10}  {:<{}}\n",
                             "BASE", "VADSIZE", "PROT", "MZ ", "PESIZE", "VADHINT", kHintCol);
    std::cout << "  " << std::string(18 + 2 + 9 + 2 + 5 + 2 + 3 + 2 + 10 + 2 + kHintCol, '-') << '\n';

    for (const auto& r : regions) {
        std::cout << std::format("  0x{:016X}  {:>9}  {:<5}  {:<3}  {:>10}  {:<{}}\n",
                                 r.vaStart,
                                 std::format("0x{:07X}", r.vaEnd - r.vaStart),
                                 VadProtStr(r.protection),
                                 r.hasMZ ? "MZ" : "-",
                                 r.peSizeOfImage ? std::format("0x{:07X}", r.peSizeOfImage) : std::string("-"),
                                 clip(r.vadText, kHintCol), kHintCol);
    }

    std::cout << "\n"
                 "  To dump one: universal_dma_dumper.exe -name <proc> -base 0x<VA> [-size 0x<N>]\n"
                 "               (size auto-derived from the PE header when MZ = MZ)\n\n";
}

// ---------------------------------------------------------------------------
//  Watch loop — continuous VAD scan with auto-dump on new MZ candidates.
// ---------------------------------------------------------------------------

namespace {
    // Single mutex serializes every stdout write across the watcher thread and
    // every dump worker thread. PageWalker's own progress lines still bypass
    // this (they call std::cout directly), so worker progress will interleave
    // with watch events — grep for the '+ 0x', '- 0x', '\xE2\x9C\x93 0x' and
    // '! 0x' prefixes to see the structured event stream cleanly.
    std::mutex g_watchOutMutex;

    void watchLog(const std::string& msg) {
        auto now = std::chrono::system_clock::now();
        auto tt  = std::chrono::system_clock::to_time_t(now);
        auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                       now.time_since_epoch()) % 1000;
        std::tm tm{};
        localtime_s(&tm, &tt);

        std::lock_guard lk(g_watchOutMutex);
        std::cout << std::format("[{:02}:{:02}:{:02}.{:03}] {}\n",
                                 tm.tm_hour, tm.tm_min, tm.tm_sec,
                                 static_cast<int>(ms.count()), msg);
    }
}

void Process::WatchHidden(VMM_HANDLE hVMM, DWORD pid, const std::string& outDir,
                          uint32_t intervalMs, size_t maxConcurrent,
                          bool watchAll, size_t minSize) {
    std::filesystem::create_directories(outDir);

    // visible: bases currently in the hidden set. Value counts consecutive
    // "still present" observations — unused right now, kept for future use
    // (e.g. only dump after a region has been visible for N ticks).
    std::unordered_map<ULONG64, int> visible;

    // dumped: bases we've already scheduled a dump for. Prevents re-dumping
    // the same address every tick while the region is still visible, and
    // (usefully) also debounces same-base remaps that flap in and out.
    std::unordered_set<ULONG64> dumped;

    std::atomic<size_t> active{ 0 };
    std::vector<std::thread> workers;

    watchLog(std::format("Watch started (pid={}, interval={} ms, maxConcurrent={}, "
                         "minSize=0x{:X}, watchAll={}, out={})",
                         pid, intervalMs, maxConcurrent, minSize,
                         watchAll ? "true" : "false", outDir));
    watchLog("Press END to stop (waits for outstanding dumps).");

    // ---------------- baseline pass ----------------
    // Every region present at startup is added to both `visible` and `dumped`.
    // This suppresses the wall of '+ 0x...' events for legitimate long-lived
    // private RX regions (Steam runtime, V8, Panorama layout heap, etc.) that
    // are usually noise for a VAC-hunt scenario.
    {
        bool ok = true;
        auto regions = ScanHiddenRegions(hVMM, pid, &ok);
        if (!ok) {
            watchLog("Initial VAD scan failed — target process gone before baseline. Aborting.");
            return;
        }
        size_t mzCount = 0;
        for (const auto& r : regions) {
            visible[r.vaStart] = 0;
            dumped.insert(r.vaStart);
            if (r.hasMZ) ++mzCount;
        }
        watchLog(std::format("Baseline: {} hidden regions ignored ({} with MZ)",
                             regions.size(), mzCount));
    }

    // Consecutive failed scans before declaring the target dead. A single
    // failure could be transient (DMA hiccup, VMM cache reload); three in a
    // row across ~750 ms is a solid signal that the process exited.
    static constexpr int kMaxConsecutiveFailures = 3;
    int failStreak = 0;

    // ---------------- watch loop ----------------
    while (true) {
        if (GetAsyncKeyState(VK_END) & 0x8000) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));

        bool ok = true;
        auto regions = ScanHiddenRegions(hVMM, pid, &ok);
        if (!ok) {
            if (++failStreak >= kMaxConsecutiveFailures) {
                watchLog(std::format("Target process (PID {}) gone — {} consecutive VAD scan failures. Exiting.",
                                     pid, failStreak));
                break;
            }
            continue;
        }
        failStreak = 0;

        // Track only bases that pass the log filter so disappearances of
        // below-threshold noise don't fire '-' events for things we never
        // announced a '+' for.
        std::unordered_set<ULONG64> loggedThisTick;
        loggedThisTick.reserve(regions.size());

        // 1) Appearances — regions in current scan but not previously visible.
        for (const auto& r : regions) {
            const ULONG64 regionSize = r.vaEnd - r.vaStart;

            // Log filter: skip small non-MZ noise (JIT trampoline pool pages,
            // 4-16 KB private-RX pages that appear/disappear constantly under
            // active JavaScript/Panorama load). MZ candidates always logged
            // regardless of size — a 4 KB MZ region is a stub loader worth
            // seeing.
            const bool worthLogging = r.hasMZ || regionSize >= minSize;
            if (!worthLogging) continue;
            loggedThisTick.insert(r.vaStart);

            if (visible.contains(r.vaStart)) continue;
            visible[r.vaStart] = 0;

            watchLog(std::format("+ 0x{:016X}  size=0x{:X}  {}  vad='{}'",
                                 r.vaStart, regionSize,
                                 r.hasMZ ? "MZ" : "--",
                                 r.vadText.empty() ? std::string("(none)") : r.vadText));

            // Dump selection:
            //   - MZ candidates: always dumped, per-page-size or SizeOfImage.
            //   - non-MZ:        only when watchAll==true. Use for modules
            //                    that wipe their PE header post-load — the
            //                    fixer will fail (no MZ/PE at base), but the
            //                    raw .bin is preserved for manual header
            //                    reconstruction.
            const bool shouldDump = r.hasMZ || watchAll;
            if (!shouldDump)                       continue;
            if (dumped.contains(r.vaStart))        continue;

            if (active.load() >= maxConcurrent) {
                watchLog(std::format("! 0x{:016X}  skipped: at concurrent-dump cap ({})",
                                     r.vaStart, maxConcurrent));
                continue;
            }

            dumped.insert(r.vaStart);
            ++active;

            const ULONG64 base = r.vaStart;
            const DWORD   size = r.peSizeOfImage
                                 ? r.peSizeOfImage
                                 : static_cast<DWORD>(regionSize);

            workers.emplace_back([hVMM, pid, base, size, outDir, &active]() {
                const std::string rawFile   = std::format("{}/hidden_{:016X}_raw.bin",   outDir, base);
                const std::string fixedFile = std::format("{}/hidden_{:016X}_fixed.dll", outDir, base);
                try {
                    PageWalker w(hVMM, pid, base, size, rawFile);
                    w.Run();
                    // No MemProcFS layout for a hidden region — PEFixer's
                    // fallback path reads sections/directories from the dump's
                    // own headers, which manual-map loaders usually keep intact.
                    ModuleLayout empty;
                    PEFixer::Fix(rawFile, fixedFile, empty, hVMM, pid, base);
                    watchLog(std::format("v 0x{:016X}  dumped: {}", base, fixedFile));
                } catch (const std::exception& e) {
                    watchLog(std::format("! 0x{:016X}  dump threw: {}", base, e.what()));
                } catch (...) {
                    watchLog(std::format("! 0x{:016X}  dump threw (unknown)", base));
                }
                --active;
            });
        }

        // 2) Disappearances — bases we were tracking but are no longer in the
        //    filtered current-tick set. Kept in `dumped` so a flap doesn't
        //    retrigger a walk on the same VA. (currentSet is built from all
        //    scanned regions and used only for erase-vs-keep bookkeeping on
        //    `dumped`; visible-set tracking uses the filtered loggedThisTick.)
        for (auto it = visible.begin(); it != visible.end(); ) {
            if (loggedThisTick.contains(it->first)) { ++it; continue; }
            watchLog(std::format("- 0x{:016X}  vanished", it->first));
            it = visible.erase(it);
        }
    }

    watchLog(std::format("Watch stopping — {} outstanding dump(s), waiting...",
                         active.load()));
    for (auto& t : workers) if (t.joinable()) t.join();
    watchLog("Watch stopped.");
}

std::string Process::ResolveModuleName(VMM_HANDLE hVMM, DWORD pid,
                                       const std::string& pattern) {
    // Fast path: if the pattern is already an exact module name, skip enumeration.
    {
        ULONG64 base = 0; DWORD size = 0;
        if (GetModuleInfo(hVMM, pid, pattern, base, size))
            return pattern;
    }

    PVMMDLL_MAP_MODULE pMap = nullptr;
    if (!VMMDLL_Map_GetModuleW(hVMM, pid, &pMap, 0)) {
        std::cerr << "[!] ResolveModuleName: VMMDLL_Map_GetModuleW failed\n";
        return {};
    }

    std::regex re;
    try {
        re.assign(pattern, std::regex_constants::icase | std::regex_constants::ECMAScript);
    } catch (const std::regex_error& e) {
        std::cerr << std::format("[!] Invalid regex pattern '{}': {}\n", pattern, e.what());
        VMMDLL_MemFree(pMap);
        return {};
    }

    std::vector<std::string> matches;
    for (DWORD i = 0; i < pMap->cMap; ++i) {
        std::string name = wtou8(pMap->pMap[i].wszText);
        if (std::regex_search(name, re))
            matches.push_back(std::move(name));
    }
    VMMDLL_MemFree(pMap);

    if (matches.empty()) {
        std::cerr << std::format("[!] No module matching '{}'\n", pattern);
        return {};
    }
    if (matches.size() == 1) {
        std::cout << std::format("[+] Resolved '{}' -> {}\n", pattern, matches[0]);
        return matches[0];
    }

    std::cerr << std::format("[!] Pattern '{}' matched {} modules (be more specific):\n",
                             pattern, matches.size());
    for (const auto& m : matches)
        std::cerr << std::format("      {}\n", m);
    return {};
}

ModuleLayout Process::GetModuleLayout(VMM_HANDLE hVMM, DWORD pid, const std::string& moduleName) {
    ModuleLayout layout;

    const int wLen = MultiByteToWideChar(CP_UTF8, 0, moduleName.c_str(), -1, nullptr, 0);
    if (wLen <= 0) return layout;
    std::wstring wName(wLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, moduleName.c_str(), -1, wName.data(), wLen);

    // Fetch fWoW64 from the module map entry
    PVMMDLL_MAP_MODULEENTRY entry = nullptr;
    if (VMMDLL_Map_GetModuleFromNameW(hVMM, pid, wName.data(), &entry, VMMDLL_MODULE_FLAG_NORMAL)) {
        layout.fWoW64 = entry->fWoW64;
        VMMDLL_MemFree(entry);
    }

    // Two-call pattern: first call with null buffer to get section count
    DWORD cSections = 0;
    VMMDLL_ProcessGetSectionsW(hVMM, pid, wName.data(), nullptr, 0, &cSections);
    if (cSections == 0) {
        std::cerr << "[!] GetModuleLayout: no sections returned by MemProcFS\n";
        return layout;
    }

    layout.sections.resize(cSections);
    if (!VMMDLL_ProcessGetSectionsW(hVMM, pid, wName.data(),
                                    layout.sections.data(), cSections, &cSections)) {
        std::cerr << "[!] GetModuleLayout: VMMDLL_ProcessGetSections failed\n";
        return layout;
    }

    // Fetch all 16 data directory entries
    if (!VMMDLL_ProcessGetDirectoriesW(hVMM, pid, wName.data(), layout.directories.data())) {
        std::cerr << "[!] GetModuleLayout: VMMDLL_ProcessGetDirectories failed\n";
        return layout;
    }

    layout.valid = true;
    std::cout << std::format("[+] MemProcFS module layout: {} sections, fWoW64={}\n",
                             cSections, layout.fWoW64);
    return layout;
}
