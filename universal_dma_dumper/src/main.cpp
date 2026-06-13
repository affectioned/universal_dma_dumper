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
    //  Parse -name (required)
    // --------------------------------------------------------
    auto it = std::find(argv + 1, argv + argc, std::string_view("-name"));
    if (it == argv + argc || std::next(it) == argv + argc) {
        std::cout << "Usage:\n"
            << "  dumper.exe -name <ProcessName>\n"
            << "  dumper.exe -name <ProcessName> -module <ModuleName>\n"
            << "  dumper.exe -name <ProcessName> -module <ModuleName> -out <dir>\n";
        return 1;
    }
    const std::string nameArg = *std::next(it);

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
    //  Get module base + size
    // --------------------------------------------------------
    ULONG64 modBase = 0;
    DWORD   modSize = 0;
    if (!Process::GetModuleInfo(hVMM, pid, moduleArg, modBase, modSize)) {
        std::cerr << std::format("[!] Could not find module: {}\n", moduleArg);
        VMMDLL_Close(hVMM);
        return 1;
    }

    std::cout << std::format("[*] Module : {}\n", moduleArg);
    std::cout << std::format("[*] Base   : 0x{:016X}\n", modBase);
    std::cout << std::format("[*] Size   : 0x{:08X} ({} KB)\n", modSize, modSize / 1024);

    // --------------------------------------------------------
    //  Fetch PE metadata from MemProcFS.
    //  MemProcFS caches the section table and data directories independently
    //  of the process's live virtual memory, so this remains valid even when
    //  the game has zeroed or corrupted its own in-memory PE headers.
    // --------------------------------------------------------
    const ModuleLayout layout = Process::GetModuleLayout(hVMM, pid, moduleArg);
    if (!layout.valid)
        std::cout << "[~] MemProcFS module layout unavailable — PE fix will rely on dump headers\n";

    // --------------------------------------------------------
    //  Set up output paths
    // --------------------------------------------------------
    std::filesystem::create_directories(outDir);

    std::string baseName = moduleArg;
    std::string fixedExt = ".exe";
    if (const size_t dot = baseName.rfind('.'); dot != std::string::npos) {
        std::string ext = baseName.substr(dot);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (ext == ".dll") fixedExt = ".dll";
        baseName = baseName.substr(0, dot);
    }

    const std::string rawFile   = std::format("{}/{}_raw.bin",  outDir, baseName);
    const std::string fixedFile = std::format("{}/{}_fixed{}", outDir, baseName, fixedExt);

    // --------------------------------------------------------
    //  Page walk
    // --------------------------------------------------------
    std::cout << "[*] Starting page walker...\n";
    PageWalker walker(hVMM, pid, modBase, modSize, rawFile);
    walker.Run();

    if (walker.WasInterrupted())
        std::cout << "\n[!] Interrupted by user.\n";

    // --------------------------------------------------------
    //  Fix PE layout
    // --------------------------------------------------------
    std::cout << "\n[*] Fixing PE layout...\n";
    if (!PEFixer::Fix(rawFile, fixedFile, layout)) {
        std::cerr << std::format("[!] FixPE failed — raw dump is still at: {}\n", rawFile);
        VMMDLL_Close(hVMM);
        return 1;
    }

    std::cout << std::format("\n[+] Done.\n    Raw dump : {}\n    Fixed PE : {}\n",
                             rawFile, fixedFile);

    VMMDLL_Close(hVMM);
    return 0;
}
