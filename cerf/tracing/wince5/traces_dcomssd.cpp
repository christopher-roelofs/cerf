#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* dcomssd.dll (WinCE 5.0 ARM build) — DCOM Service Startup Daemon.
   IDA base: 0x10000000. CRC32: 0x3CD6AB39 */

void register_traces_dcomssd(TraceManager& tm) {
    const char* DLL = "dcomssd.dll";
    tm.SetIdaBase(DLL, 0x10000000);
    tm.SetCRC32(DLL, 0x3CD6AB39);

    tm.Add(DLL, 0x10007B6C, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] dcomssd::rpcss_start: thread entry\n");
    });
    tm.Add(DLL, 0x1000DABC, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] dcomssd::StartObjectExporter\n");
    });
    tm.Add(DLL, 0x1001E108, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] dcomssd::InitializeSCM\n");
    });
    tm.Add(DLL, 0x1001E474, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] dcomssd::InitializeSCMAfterListen\n");
    });
}
