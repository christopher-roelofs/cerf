#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* explorer.exe (WinCE 5.0 ARM build) — browser window creation.
   IDA base: 0x00010000 (EXE).  PE checksum: 0 (not yet captured). */

void RegisterExplorerTraces(TraceManager& tm) {
    const char* EXE = "explorer.exe";
    tm.SetIdaBase(EXE, 0x00010000);
    tm.SetCRC32(EXE, 0xC6D0C4CC);

    /* CMainWnd::CreateBrowser */
    tm.Add(EXE, 0x0001E5AC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CMainWnd::CreateBrowser: this=0x%08X\n", r[0]);
    });
    /* CMainWnd::Close */
    tm.Add(EXE, 0x0001E77C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CMainWnd::Close: this=0x%08X\n", r[0]);
    });
    /* ExplorerList_t::RemoveExplorerWnd */
    tm.Add(EXE, 0x00017194, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] RemoveExplorerWnd: hwnd=0x%08X\n", r[0]);
    });
    /* ExplorerList_t::FindExplorerWnd */
    tm.Add(EXE, 0x00016E80, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char buf[40] = {};
        if (r[0]) { for (int i=0; i<39; i++) { uint16_t c = mem->Read16(r[0]+i*2); if (!c) break; buf[i]=(char)c; } }
        LOG(TRACE, "[TRACE] FindExplorerWnd: path='%s'\n", buf);
    });
    /* CBrowseObj::Close (base class — does NOT call RemoveExplorerWnd!) */
    tm.Add(EXE, 0x00025D24, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CBrowseObj::Close (BASE): this=0x%08X — NO RemoveExplorerWnd!\n", r[0]);
    });
    /* BX R3 at 0x21678 — the virtual Close() dispatch. R3 has the target address. */
    tm.Add(EXE, 0x00021678, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] BrowseWndProc->Close() virtual dispatch: target=0x%08X this=0x%08X\n",
            r[3], r[0]);
    });
    /* GetParsingName — converts path to shell namespace CLSID */
    tm.Add(EXE, 0x000192A0, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[60] = {};
        if (r[0]) { for (int i=0;i<59;i++) { uint16_t c=mem->Read16(r[0]+i*2); if(!c)break; url[i]=(char)c; } }
        LOG(TRACE, "[TRACE] GetParsingName: input='%s' outBuf=0x%08X\n", url, r[1]);
    });
    /* SHCreateExplorerInstance */
    tm.Add(EXE, 0x0001A120, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char buf[40] = {};
        if (r[0]) { for (int i=0; i<39; i++) { uint16_t c = mem->Read16(r[0]+i*2); if (!c) break; buf[i]=(char)c; } }
        LOG(TRACE, "[TRACE] SHCreateExplorerInstance: path='%s' flags=%u\n", buf, r[1]);
    });
}
