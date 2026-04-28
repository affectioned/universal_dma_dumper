#pragma once

// VMM_HANDLE  g_hVMM = nullptr;
#include <iostream>

// std::string g_outDir = "./dumps";
#include <string>

// std::span<const uint8_t> buf
#include <span>

// return std::ranges::all_of(buf, [](uint8_t b) { return b == 0xCC; });
#include <algorithm>

// std::cerr << std::format("[!] Process not found: {}\n", processName);
#include <format>

// std::vector<uint8_t> pageBuf(PAGE);
#include <vector>

// std::unordered_set<ULONG64> dumpedPages;
#include <unordered_set>

// const auto   startTime = std::chrono::steady_clock::now();
#include <chrono>

// std::ofstream ostrm(outFile, std::ios::binary);
#include <fstream>

// std::this_thread::sleep_for(std::chrono::milliseconds(10));
#include <thread>

// std::filesystem::create_directories(g_outDir);
#include <filesystem>

#define NOMINMAX
#include "..\libs\vmmdll.h"
#pragma comment(lib, "leechcore.lib")
#pragma comment(lib, "vmm.lib")