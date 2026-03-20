#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* ole32.dll (WinCE 5.0 ARM build) — COM server registration chain.
   IDA base: 0x10000000. */

void RegisterOle32Traces(TraceManager& tm) {
    const char* DLL = "ole32.dll";
    tm.SetIdaBase(DLL, 0x10000000);
    tm.SetCRC32(DLL, 0x5CB72562);

    /* StartListen — initiates COM RPC server */
    tm.Add(DLL, 0x1006BE74, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ole32::StartListen called\n");
    });

    /* RegisterLrpc — registers ncalrpc protocol with endpoint */
    tm.Add(DLL, 0x1006B3E4, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ole32::RegisterLrpc called\n");
    });

    /* CoGetCurrentProcess — returns process ID used for endpoint */
    tm.Add(DLL, 0x1001D700, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ole32::CoGetCurrentProcess\n");
    });

    /* GetLocalEndpoint — calls StartListen, returns "OLE<pid>" string */
    tm.Add(DLL, 0x1006B5B4, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ole32::GetLocalEndpoint called\n");
    });

    /* CStdMarshal::MarshalObjRef — marshals a COM interface for IPC */
    tm.Add(DLL, 0x10056A00, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ole32::CStdMarshal::MarshalObjRef this=0x%08X\n", r[0]);
    });

    /* FillLocalOXIDInfo — fills OXID_INFO, calls GetStringBindings */
    tm.Add(DLL, 0x10057108, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ole32::FillLocalOXIDInfo\n");
    });

    /* GetStringBindings — calls StartListen to start RPC server */
    tm.Add(DLL, 0x1006C154, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ole32::GetStringBindings\n");
    });
}
