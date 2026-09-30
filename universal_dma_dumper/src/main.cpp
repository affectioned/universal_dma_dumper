#include "pch.h"
#include "Process.h"
#include "PageWalker.h"
#include "PEFixer.h"

// based off https://www.unknowncheats.me/forum/4595235-post1774.html
// original logic credit goes to them

// Streambuf that fans every write out to two underlying buffers — used to
// mirror std::cout/std::cerr to both the console and a log file.
class TeeStreambuf : public std::streambuf {
public:
    TeeStreambuf(std::streambuf* a, std::streambuf* b) : m_a(a), m_b(b) {}
protected:
    int overflow(int c) override {
        if (c == EOF) return 0;
        const auto ch = static_cast<char>(c);
        const int  ra = m_a ? m_a->sputc(ch) : ch;
        const int  rb = m_b ? m_b->sputc(ch) : ch;
        return (ra == EOF || rb == EOF) ? EOF : c;
    }
    int sync() override {
        const int ra = m_a ? m_a->pubsync() : 0;
        const int rb = m_b ? m_b->pubsync() : 0;
        return (ra == 0 && rb == 0) ? 0 : -1;
    }
private:
    std::streambuf* m_a;
    std::streambuf* m_b;
};

int main(int argc, char* argv[]) {
    // --------------------------------------------------------
    //  Open log file next to the running exe and tee cout/cerr to it
    //  so the full session output is preserved after the console closes.
    // --------------------------------------------------------
    std::ofstream logFile;
    {
        char exePath[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::filesystem::path logPath = std::filesystem::path(exePath).replace_extension(".log");
        logFile.open(logPath, std::ios::out | std::ios::trunc);
    }
    TeeStreambuf coutTee(std::cout.rdbuf(), logFile.rdbuf());
    TeeStreambuf cerrTee(std::cerr.rdbuf(), logFile.rdbuf());
    std::streambuf* const origCout = std::cout.rdbuf(&coutTee);
    std::streambuf* const origCerr = std::cerr.rdbuf(&cerrTee);
    // Restore the original buffers before main() returns so the static
    // stream destructors don't touch our stack-allocated tee buffers.
    struct RestoreStreams {
        std::streambuf* coutBuf;
        std::streambuf* cerrBuf;
        ~RestoreStreams() {
            std::cout.flush();
            std::cerr.flush();
            std::cout.rdbuf(coutBuf);
            std::cerr.rdbuf(cerrBuf);
        }
    } restoreStreams{ origCout, origCerr };

    std::cout << "=== Process Dumper (MemProcFS) ===\n";

    // --------------------------------------------------------
    //  Parse listing flags (mutually exclusive with each other, and
    //  short-circuit the dump path when set).
    // --------------------------------------------------------
    const bool listDrivers   = std::find(argv + 1, argv + argc, std::string_view("-list-drivers"))   != argv + argc;
    const bool listModules   = std::find(argv + 1, argv + argc, std::string_view("-list-modules"))   != argv + argc;
    const bool listUnloaded  = std::find(argv + 1, argv + argc, std::string_view("-list-unloaded"))  != argv + argc;
    const bool scanHidden    = std::find(argv + 1, argv + argc, std::string_view("-scan-hidden"))    != argv + argc;
    const bool watchHidden   = std::find(argv + 1, argv + argc, std::string_view("-watch-hidden"))   != argv + argc;
    if (static_cast<int>(listDrivers) + static_cast<int>(listModules) +
        static_cast<int>(listUnloaded) + static_cast<int>(scanHidden) +
        static_cast<int>(watchHidden) > 1) {
        std::cerr << "[!] -list-drivers, -list-modules, -list-unloaded, -scan-hidden and -watch-hidden are mutually exclusive.\n";
        return 1;
    }

    // --------------------------------------------------------
    //  Parse -name. Required for dump / -list-modules / -list-unloaded /
    //  -scan-hidden; defaults to "System" for -list-drivers since kernel
    //  drivers live under PID 4.
    // --------------------------------------------------------
    std::string nameArg;
    {
        auto it = std::find(argv + 1, argv + argc, std::string_view("-name"));
        if (it != argv + argc && std::next(it) != argv + argc) {
            nameArg = *std::next(it);
        } else if (listDrivers) {
            nameArg = "System";
        } else {
            std::cout << "Usage:\n"
                << "  dumper.exe -name <ProcessName>\n"
                << "  dumper.exe -name <ProcessName> -module <ModuleName>\n"
                << "  dumper.exe -name <ProcessName> -base 0x<VA> [-size 0x<N>]\n"
                << "  dumper.exe -name <ProcessName> -module <ModuleName> -out <dir>\n"
                << "  dumper.exe -list-drivers                       (enumerate PID 4 modules)\n"
                << "  dumper.exe -name <ProcessName> -list-modules   (enumerate a process's modules, incl. NOTLINKED/INJECTED)\n"
                << "  dumper.exe -name <ProcessName> -list-unloaded  (dump the process's unloaded-module list)\n"
                << "  dumper.exe -name <ProcessName> -scan-hidden    (VAD scan for private RX regions outside the module map)\n"
                << "  dumper.exe -name <ProcessName> -watch-hidden [-watch-interval <ms>] [-max-concurrent <N>]\n"
                << "                                               [-watch-all] [-min-size <bytes>] [-dump-baseline] [-out <dir>]\n"
                << "                                                 (continuous -scan-hidden; auto-dumps new MZ regions\n"
                << "                                                  and, with -watch-all, non-MZ regions >= -min-size;\n"
                << "                                                  -dump-baseline also dumps everything present at startup)\n";
            return 1;
        }
    }
    auto it = argv + argc;  // sentinel — reused by subsequent optional-arg lookups below

    // --------------------------------------------------------
    //  Parse -module (optional, defaults to process name)
    // --------------------------------------------------------
    std::string moduleArg = nameArg;
    it = std::find(argv + 1, argv + argc, std::string_view("-module"));
    if (it != argv + argc && std::next(it) != argv + argc)
        moduleArg = *std::next(it);

    // --------------------------------------------------------
    //  Parse -out (optional)
    // --------------------------------------------------------
    std::string outDir = "./dumps";
    it = std::find(argv + 1, argv + argc, std::string_view("-out"));
    if (it != argv + argc && std::next(it) != argv + argc)
        outDir = *std::next(it);

    // --------------------------------------------------------
    //  Parse -base / -size (optional, alternative to -module).
    //  Enables dumping an arbitrary VA range — e.g. a manually-mapped
    //  module surfaced by -scan-hidden.  Size is optional and auto-
    //  derived from the PE header at the base address when omitted.
    //  Values accept hex (0x-prefixed) or decimal.
    // --------------------------------------------------------
    auto parseNum = [](const char* s, ULONG64& out) -> bool {
        try {
            std::string_view sv{ s };
            const int base = (sv.starts_with("0x") || sv.starts_with("0X")) ? 16 : 10;
            out = std::stoull(sv.data() + (base == 16 ? 2 : 0), nullptr, base);
            return true;
        } catch (...) { return false; }
    };
    ULONG64 baseArg = 0;
    ULONG64 sizeArg = 0;
    it = std::find(argv + 1, argv + argc, std::string_view("-base"));
    if (it != argv + argc && std::next(it) != argv + argc && !parseNum(*std::next(it), baseArg)) {
        std::cerr << std::format("[!] Invalid -base value: {}\n", *std::next(it));
        return 1;
    }
    it = std::find(argv + 1, argv + argc, std::string_view("-size"));
    if (it != argv + argc && std::next(it) != argv + argc && !parseNum(*std::next(it), sizeArg)) {
        std::cerr << std::format("[!] Invalid -size value: {}\n", *std::next(it));
        return 1;
    }

    // --------------------------------------------------------
    //  Parse -watch-interval (ms) and -max-concurrent for -watch-hidden.
    //  Defaults chosen for a VAC-hunt profile: ~4 Hz scan cadence, four
    //  concurrent walkers so a burst of appearances all get captured.
    // --------------------------------------------------------
    ULONG64 watchIntervalMs = 250;
    ULONG64 maxConcurrent   = 4;
    // Default noise floor: 256 KB. Below that is almost always JIT
    // trampoline pool pages / hook stubs / per-object micro-allocations —
    // not what a manual-map hunt is looking for.
    ULONG64 minRegionSize   = 0x40000;
    const bool watchAll      = std::find(argv + 1, argv + argc, std::string_view("-watch-all"))     != argv + argc;
    const bool dumpBaseline  = std::find(argv + 1, argv + argc, std::string_view("-dump-baseline")) != argv + argc;
    it = std::find(argv + 1, argv + argc, std::string_view("-watch-interval"));
    if (it != argv + argc && std::next(it) != argv + argc && !parseNum(*std::next(it), watchIntervalMs)) {
        std::cerr << std::format("[!] Invalid -watch-interval value: {}\n", *std::next(it));
        return 1;
    }
    it = std::find(argv + 1, argv + argc, std::string_view("-max-concurrent"));
    if (it != argv + argc && std::next(it) != argv + argc && !parseNum(*std::next(it), maxConcurrent)) {
        std::cerr << std::format("[!] Invalid -max-concurrent value: {}\n", *std::next(it));
        return 1;
    }
    it = std::find(argv + 1, argv + argc, std::string_view("-min-size"));
    if (it != argv + argc && std::next(it) != argv + argc && !parseNum(*std::next(it), minRegionSize)) {
        std::cerr << std::format("[!] Invalid -min-size value: {}\n", *std::next(it));
        return 1;
    }

    // --------------------------------------------------------
    //  Init MemProcFS
    // --------------------------------------------------------
    LPCSTR vmmArgs[] = { (LPSTR)"", (LPSTR)"-device", (LPSTR)"FPGA" };
    std::cout << "[*] Initializing MemProcFS...\n";
    VMM_HANDLE hVMM = VMMDLL_Initialize(3, vmmArgs);
    if (!hVMM) {
        std::cerr << "[!] VMMDLL_Initialize failed.\n";
        return 1;
    }
    std::cout << "[+] Initialized\n";

    // --------------------------------------------------------
    //  Find process
    // --------------------------------------------------------
    const DWORD pid = Process::FindPidByName(hVMM, nameArg);
    if (pid == 0) {
        VMMDLL_Close(hVMM);
        return 1;
    }

    // --------------------------------------------------------
    //  Listing / scan modes: enumerate and exit before the dump path.
    //  -list-drivers walks PID 4 (kernel), -list-modules walks any PID.
    //  -list-unloaded walks the unloaded-module ring for either kind.
    //  -scan-hidden walks the VAD tree and prints private RX regions
    //  that are not covered by any module in the loader lists.
    // --------------------------------------------------------
    if (listDrivers || listModules) {
        Process::ListModules(hVMM, pid);
        if (listModules)
            std::cout << "[~] Note: modules that erase their PE header AND unlink from\n"
                         "         both the PEB and VadIdentifyModule's PE probe will\n"
                         "         not appear here — try -scan-hidden for a VAD-based\n"
                         "         search that catches those.\n";
        VMMDLL_Close(hVMM);
        return 0;
    }
    if (listUnloaded) {
        Process::ListUnloadedModules(hVMM, pid);
        VMMDLL_Close(hVMM);
        return 0;
    }
    if (scanHidden) {
        Process::PrintHiddenRegions(Process::ScanHiddenRegions(hVMM, pid));
        VMMDLL_Close(hVMM);
        return 0;
    }
    if (watchHidden) {
        Process::WatchHidden(hVMM, pid, outDir,
                             static_cast<uint32_t>(watchIntervalMs),
                             static_cast<size_t>(maxConcurrent),
                             watchAll,
                             static_cast<size_t>(minRegionSize),
                             dumpBaseline);
        VMMDLL_Close(hVMM);
        return 0;
    }

    // --------------------------------------------------------
    //  Dump target resolution — either -base (direct VA) or -module (name).
    //  Direct VA is required for manually-mapped modules that have no name
    //  in the module map.
    // --------------------------------------------------------
    ULONG64 modBase = 0;
    DWORD   modSize = 0;
    ModuleLayout layout;
    bool baseMode = (baseArg != 0);

    if (baseMode) {
        modBase = baseArg;

        // Size derivation: use -size when given, otherwise probe the PE header
        // at the base for OptionalHeader.SizeOfImage. Falling through with a
        // zero size is fatal because the walker needs to know how many pages
        // to touch.
        if (sizeArg != 0) {
            modSize = static_cast<DWORD>(sizeArg);
        } else {
            modSize = Process::ProbePEImageSize(hVMM, pid, modBase);
            if (modSize == 0) {
                std::cerr << std::format(
                    "[!] No PE header at 0x{:016X} and no -size given. Rerun with an explicit -size.\n",
                    modBase);
                VMMDLL_Close(hVMM);
                return 1;
            }
            std::cout << std::format("[*] Auto-derived size from PE header: 0x{:X}\n", modSize);
        }

        // Give the output file a base-derived name so multiple hidden regions
        // don't clobber each other. Kept as a .exe extension by convention
        // even when the target might be a driver — user can rename after.
        moduleArg = std::format("hidden_{:016X}.dll", modBase);
        std::cout << std::format("[*] Direct VA dump : 0x{:016X}  size=0x{:08X}\n", modBase, modSize);
        std::cout << "[~] Layout unavailable for direct-VA dumps — PE fix will rely on dump headers\n";
    } else {
        // --------------------------------------------------------
        //  Module-name path (unchanged from previous behavior).
        // --------------------------------------------------------
        moduleArg = Process::ResolveModuleName(hVMM, pid, moduleArg);
        if (moduleArg.empty()) {
            VMMDLL_Close(hVMM);
            return 1;
        }
        if (!Process::GetModuleInfo(hVMM, pid, moduleArg, modBase, modSize)) {
            std::cerr << std::format("[!] Could not find module: {}\n", moduleArg);
            VMMDLL_Close(hVMM);
            return 1;
        }

        std::cout << std::format("[*] Module : {}\n", moduleArg);
        std::cout << std::format("[*] Base   : 0x{:016X}\n", modBase);
        std::cout << std::format("[*] Size   : 0x{:08X} ({} KB)\n", modSize, modSize / 1024);

        // MemProcFS caches the section table and data directories independently
        // of the process's live virtual memory, so this remains valid even when
        // the game has zeroed or corrupted its own in-memory PE headers.
        layout = Process::GetModuleLayout(hVMM, pid, moduleArg);
        if (!layout.valid)
            std::cout << "[~] MemProcFS module layout unavailable — PE fix will rely on dump headers\n";
    }

    // --------------------------------------------------------
    //  Set up output paths
    // --------------------------------------------------------
    std::filesystem::create_directories(outDir);

    std::string baseName = moduleArg;
    std::string fixedExt = ".exe";
    if (const size_t dot = baseName.rfind('.'); dot != std::string::npos) {
        std::string ext = baseName.substr(dot);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (ext == ".dll" || ext == ".sys") fixedExt = ext;
        baseName = baseName.substr(0, dot);
    }

    const std::string rawFile   = std::format("{}/{}_raw.bin",  outDir, baseName);
    const std::string fixedFile = std::format("{}/{}_fixed{}", outDir, baseName, fixedExt);

    // --------------------------------------------------------
    //  Page walk
    // --------------------------------------------------------
    std::cout << "[*] Starting page walker...\n";
    PageWalker walker(hVMM, pid, modBase, modSize, rawFile, layout);
    walker.Run();

    if (walker.WasInterrupted())
        std::cout << "\n[!] Interrupted by user.\n";

    // --------------------------------------------------------
    //  Fix PE layout
    // --------------------------------------------------------
    std::cout << "\n[*] Fixing PE layout...\n";
    if (!PEFixer::Fix(rawFile, fixedFile, layout, hVMM, pid, modBase)) {
        std::cerr << std::format("[!] FixPE failed — raw dump is still at: {}\n", rawFile);
        VMMDLL_Close(hVMM);
        return 1;
    }

    std::cout << std::format("\n[+] Done.\n    Raw dump : {}\n    Fixed PE : {}\n",
                             rawFile, fixedFile);

    VMMDLL_Close(hVMM);
    return 0;
}
