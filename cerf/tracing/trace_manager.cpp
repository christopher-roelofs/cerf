#include "trace_manager.h"
#include "../cpu/mem.h"
#include "../log.h"
#include <algorithm>
#include <fstream>

std::string TraceManager::NormalizeName(const std::string& name) {
    std::string s = name;
    size_t slash = s.find_last_of("\\/");
    if (slash != std::string::npos) s = s.substr(slash + 1);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

/* CRC32 — standard polynomial 0xEDB88320 (same as zlib.crc32) */
uint32_t TraceManager::ComputeFileCRC32(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return 0;

    uint32_t crc = 0xFFFFFFFF;
    char buf[8192];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0) {
        size_t n = (size_t)f.gcount();
        for (size_t i = 0; i < n; i++) {
            crc ^= (uint8_t)buf[i];
            for (int j = 0; j < 8; j++)
                crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return crc ^ 0xFFFFFFFF;
}

void TraceManager::SetCRC32(const std::string& dll_name, uint32_t crc32) {
    pending_[NormalizeName(dll_name)].expected_crc32 = crc32;
}

void TraceManager::SetIdaBase(const std::string& dll_name, uint32_t ida_base) {
    pending_[NormalizeName(dll_name)].ida_base = ida_base;
}

void TraceManager::Add(const std::string& dll_name, uint32_t ida_addr, TraceFunc handler) {
    pending_[NormalizeName(dll_name)].traces.push_back({ida_addr, std::move(handler)});
}

void TraceManager::OnDllLoad(const std::string& dll_name, const std::string& dll_path,
                             uint32_t runtime_base) {
    std::string key = NormalizeName(dll_name);
    auto it = pending_.find(key);
    if (it == pending_.end()) return;

    DllInfo& info = it->second;

    /* CRC32 verification against actual file content */
    if (info.expected_crc32 != 0) {
        uint32_t actual_crc = ComputeFileCRC32(dll_path);
        if (actual_crc != info.expected_crc32) {
            LOG(TRACE, "[TRACE] SKIP %s: CRC32 mismatch (expected 0x%08X, got 0x%08X from %s)\n",
                key.c_str(), info.expected_crc32, actual_crc, dll_path.c_str());
            return;
        }
    }

    uint32_t rebase = runtime_base - info.ida_base;
    LOG(TRACE, "[TRACE] Activating %zu traces for %s (runtime=0x%08X, rebase=+0x%06X)\n",
        info.traces.size(), key.c_str(), runtime_base, rebase);

    for (auto& pt : info.traces) {
        uint32_t runtime_pc = pt.ida_addr + rebase;
        active_[runtime_pc] = pt.handler;
    }
}

bool TraceManager::Check(uint32_t pc, const uint32_t* regs, EmulatedMemory* mem) const {
    auto it = active_.find(pc);
    if (it == active_.end()) return false;
    it->second(pc, regs, mem);
    return true;
}
