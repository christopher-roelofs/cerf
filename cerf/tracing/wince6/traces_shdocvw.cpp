#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* shdocvw.dll (WinCE 6.0 ARM build) — navigation, PIDL resolution.
   IDA base: 0x10000000. */

void RegisterWinCE6ShdocvwTraces(TraceManager& tm) {
    const char* DLL = "shdocvw.dll";
    tm.SetIdaBase(DLL, 0x10000000);
    tm.SetCRC32(DLL, 0x44BF506C);

    /* CIEFrameAuto::_NavigateHelper — main entry for URL navigation */
    tm.Add(DLL, 0x10044BE4, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[120] = {};
        if (r[1]) { for (int i = 0; i < 119; i++) { uint16_t c = mem->Read16(r[1] + i * 2); if (!c) break; url[i] = (char)c; } }
        LOG(TRACE, "[TRACE] shdocvw::_NavigateHelper: this=0x%08X url='%s'\n", r[0], url);
    });
    /* CIEFrameAuto::Navigate */
    tm.Add(DLL, 0x10044AC4, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[80] = {};
        if (r[1]) { for (int i = 0; i < 79; i++) { uint16_t c = mem->Read16(r[1] + i * 2); if (!c) break; url[i] = (char)c; } }
        LOG(TRACE, "[TRACE] shdocvw::Navigate: this=0x%08X url='%s'\n", r[0], url);
    });
    /* CIEFrameAuto::Navigate2 */
    tm.Add(DLL, 0x10045D34, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] shdocvw::Navigate2: this=0x%08X\n", r[0]);
    });
    /* IECreateFromPathCPWithBCW — creates PIDL from URL path */
    tm.Add(DLL, 0x10056364, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[80] = {};
        if (r[1]) { for (int i = 0; i < 79; i++) { uint16_t c = mem->Read16(r[1] + i * 2); if (!c) break; url[i] = (char)c; } }
        LOG(TRACE, "[TRACE] IECreateFromPathCPWithBCW(cp=%u, '%s')\n", r[0], url);
    });
    /* _ValidateURL — checks if URL is valid for navigation */
    tm.Add(DLL, 0x100523E8, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[80] = {};
        if (r[0]) { for (int i = 0; i < 79; i++) { uint16_t c = mem->Read16(r[0] + i * 2); if (!c) break; url[i] = (char)c; } }
        LOG(TRACE, "[TRACE] _ValidateURL('%s', flags=0x%X)\n", url, r[1]);
    });
    /* _GetInternetRoot — gets Internet shell folder for URL PIDL */
    tm.Add(DLL, 0x10055264, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] _GetInternetRoot: ppsfRoot=0x%08X\n", r[0]);
    });
    /* After _GetInternetRoot returns inside IECreateFromPathCPWithBCW */
    tm.Add(DLL, 0x100565C0, [](uint32_t pc, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] IECreateFromPath: _GetInternetRoot returned hr=0x%08X\n", r[0]);
    });
    /* CBaseBrowser2::NavigateToPidl */
    tm.Add(DLL, 0x1006D838, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CBaseBrowser2::NavigateToPidl: pidl=0x%08X flags=0x%X\n", r[1], r[2]);
    });
    /* CBaseBrowser2::_NavigateToPidl */
    tm.Add(DLL, 0x100767B0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CBaseBrowser2::_NavigateToPidl: pidl=0x%08X flags=0x%X\n", r[1], r[2]);
    });
    /* FireEvent_NavigateError */
    tm.Add(DLL, 0x10049C78, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] FireEvent_NavigateError!\n");
    });
    /* FireEvent_NavigateComplete */
    tm.Add(DLL, 0x10048EB0, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] FireEvent_NavigateComplete\n");
    });
    /* HlinkFrameNavigate */
    tm.Add(DLL, 0x1004BF6C, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] shdocvw::HlinkFrameNavigate\n");
    });
    /* DOH::_NavigateDocument */
    tm.Add(DLL, 0x100AC724, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[60] = {};
        if (r[1]) { for (int i = 0; i < 59; i++) { uint16_t c = mem->Read16(r[1] + i * 2); if (!c) break; url[i] = (char)c; } }
        LOG(TRACE, "[TRACE] DOH::_NavigateDocument: pdoh=0x%08X url='%s'\n", r[0], url);
    });
    /* IEBindToObjectForNavigate — PIDL chain resolution */
    tm.Add(DLL, 0x100561DC, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t pidl_addr = r[0];
        uint16_t cb1 = pidl_addr ? mem->Read16(pidl_addr) : 0;
        LOG(TRACE, "[TRACE] IEBindToObjectForNavigate: pidl=0x%08X cb1=%d\n", pidl_addr, cb1);
    });
    /* COmWindow::navigate — JavaScript/address bar URL navigation */
    tm.Add(DLL, 0x100DADA4, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[80] = {};
        if (r[1]) { for (int i = 0; i < 79; i++) { uint16_t c = mem->Read16(r[1] + i * 2); if (!c) break; url[i] = (char)c; } }
        LOG(TRACE, "[TRACE] COmWindow::navigate('%s')\n", url);
    });
    /* COmLocation::DoNavigate — location bar navigation trigger */
    tm.Add(DLL, 0x100DFF78, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] COmLocation::DoNavigate: this=0x%08X\n", r[0]);
    });
}
