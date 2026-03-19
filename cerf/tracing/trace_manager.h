#pragma once
/* ARM Trace Point Manager
   Per-DLL C++ trace handlers, auto-rebased at DLL load time.

   Build verification: each trace file sets an expected CRC32 of the DLL file
   content. At DLL load time, the actual CRC32 is computed and compared.
   Mismatch = wrong build = traces skipped (stale addresses would crash).

   In ArmCpu::Step(), one hash lookup per instruction: traces.Check(pc, regs, mem). */

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

class EmulatedMemory;

class TraceManager {
public:
    using TraceFunc = std::function<void(uint32_t pc, const uint32_t* regs,
                                         EmulatedMemory* mem)>;

    /* Register a trace point for a DLL.
       ida_addr: address as seen in IDA (before rebase).
       handler:  C++ function to call when PC hits this address. */
    void Add(const std::string& dll_name, uint32_t ida_addr, TraceFunc handler);

    /* Set expected CRC32 of the DLL file content.  If 0, skip verification.
       Compute with: python3 -c "import zlib; print(hex(zlib.crc32(open('x.dll','rb').read()) & 0xFFFFFFFF))" */
    void SetCRC32(const std::string& dll_name, uint32_t crc32);

    /* Set IDA base for a DLL (default 0x10000000 for DLLs, 0x00010000 for EXEs). */
    void SetIdaBase(const std::string& dll_name, uint32_t ida_base);

    /* Called by LoadArmDll after a DLL is loaded.  Computes CRC32 of the file,
       verifies against expected, computes rebase, and activates trace points. */
    void OnDllLoad(const std::string& dll_name, const std::string& dll_path,
                   uint32_t runtime_base);

    /* Fast check — called from ArmCpu::Step() every instruction. */
    bool Check(uint32_t pc, const uint32_t* regs, EmulatedMemory* mem) const;

    bool HasTraces() const { return !active_.empty(); }

private:
    struct PendingTrace {
        uint32_t ida_addr;
        TraceFunc handler;
    };

    struct DllInfo {
        uint32_t expected_crc32 = 0;    /* 0 = skip check */
        uint32_t ida_base = 0x10000000; /* default for DLLs */
        std::vector<PendingTrace> traces;
    };

    /* Pending traces grouped by lowercase DLL name */
    std::unordered_map<std::string, DllInfo> pending_;

    /* Active: runtime_pc → handler */
    std::unordered_map<uint32_t, TraceFunc> active_;

    static std::string NormalizeName(const std::string& name);
    static uint32_t ComputeFileCRC32(const std::string& path);
};
