#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* browser.dll (WinCE 5.0 ARM build) — CViewerSite activation.
   IDA base: 0x10000000.  PE checksum: 0 (not yet captured). */

void RegisterBrowserTraces(TraceManager& tm) {
    const char* DLL = "browser.dll";
    tm.SetIdaBase(DLL, 0x10000000);
    tm.SetCRC32(DLL, 0x77919328);

    /* CViewerSite::Activate */
    tm.Add(DLL, 0x1002D1C0, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t m_lpdisp = mem->Read32(r[0] + 0xC0);
        LOG(TRACE, "[TRACE] Activate: m_lpdisp=0x%08X\n", m_lpdisp);
    });
    /* After QI(IOleObject) in Activate */
    tm.Add(DLL, 0x1002D284, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t lpOleObject = mem->Read32(r[13] + 0x0C);
        uint32_t vtbl = lpOleObject ? mem->Read32(lpOleObject) : 0;
        LOG(TRACE, "[TRACE] QI(IOleObject): hr=0x%08X lpOleObject=0x%08X vtbl=0x%08X\n",
            r[0], lpOleObject, vtbl);
    });
}
