#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* mshtml.dll (WinCE 5.0 ARM build) — notify, layout tasks, view activation.
   IDA base: 0x10000000.  Continuation of traces_mshtml.cpp. */

void RegisterMshtmlNotifyTraces(TraceManager& tm) {
    const char* DLL = "mshtml.dll";
    tm.SetIdaBase(DLL, 0x10000000);
    tm.SetCRC32(DLL, 0x848887A1);

    /* Layout/notify traces */
    tm.Add(DLL, 0x1058340C, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CFlowLayout::Notify calling PostLayoutRequest!\n");
    });
    tm.Add(DLL, 0x104470EC, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t type = mem->Read32(r[1]);
        LOG(TRACE, "[TRACE] CMarkup::Notify: type=%u\n", type);
    });
    tm.Add(DLL, 0x10582EAC, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CFlowLayout::Notify calling DirtyLayout!\n");
    });
    tm.Add(DLL, 0x1031DE10, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] AddLayoutTask: view=0x%08X layout=0x%08X flags=0x%X\n", r[0], r[1], r[2]);
    });
    tm.Add(DLL, 0x1058437C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DoLayout: this=0x%08X flags=0x%X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x10585180, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CalcSizeVirtual: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10410CA0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ForceRelayout: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x103188B0, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t cv = r[0];
        LOG(TRACE, "[TRACE] CView::Activate: this=0x%08X _pLayout=0x%08X _pDispRoot=0x%08X\n",
            cv, mem->Read32(cv + 0xFC), mem->Read32(cv + 0x24));
    });
    tm.Add(DLL, 0x10318D10, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] Deactivate: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x103185CC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ViewInit: this=0x%08X doc=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x10190050, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ComputeFormats: elem=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x104A7B80, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CreateLayout: elem=0x%08X ctx=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x102E8350, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] OnLoadStatus: markup=0x%08X status=%u\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x102E86C4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] OnLoadStatusInteractive: markup=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x102E8A5C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] OnLoadStatusParseDone: markup=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10328954, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] SetOffscreenBuffer: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10438804, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t host = r[0];
        LOG(TRACE, "[TRACE] SuspendRecalc: host=0x%08X arg=%d ulSuspend=%u fRecalcReq=%u LR=0x%08X\n",
            host, (int16_t)r[1], mem->Read32(host + 0x20), mem->Read32(host + 0x18), r[14]);
    });
    tm.Add(DLL, 0x103287FC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] SetRenderSurface: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x104785C4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CLayout::Notify: layout=0x%08X notif=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x10582294, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t notif = r[1];
        uint32_t type = mem->Read32(notif);
        uint32_t data = mem->Read32(notif + 4);
        uint32_t flags = mem->Read32(notif + 0xC);
        uint32_t received = mem->Read32(notif + 0x10);
        LOG(TRACE, "[TRACE] CFlowLayout::Notify: layout=0x%08X type=%u elem=0x%08X flags=0x%08X rcvd=0x%08X\n",
            r[0], type, data, flags, received);
    });
    tm.Add(DLL, 0x1019AF8C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] PostLayoutRequest: layout=0x%08X flags=0x%X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x10193384, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DoLayoutRelatedWork: elem=0x%08X a2=%d\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x10249144, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] SendNotif: elem=0x%08X notif=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x10131364, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] BroadcastNotify: doc=0x%08X notif=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x104A26E4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] SyncLoop-IsDone: post=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x104A2704, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t pre = r[0];
        uint32_t bd = mem->Read32(pre + 0x138);
        uint32_t stm = (bd >= 0x200000 && bd <= 0x300000) ? mem->Read32(bd + 0x64) : 0;
        uint32_t wp = (stm >= 0x200000 && stm <= 0x300000) ? mem->Read32(stm + 0x44) : 0;
        uint32_t rp = (stm >= 0x200000 && stm <= 0x300000) ? mem->Read32(stm + 0x40) : 0;
        LOG(TRACE, "[TRACE] SyncLoop-Exec: pre=0x%08X bd=0x%08X stm=0x%08X r=%u w=%u\n", pre, bd, stm, rp, wp);
    });
    tm.Add(DLL, 0x104A27C8, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] SuspendPath: pre=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x104A27DC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] AsyncPath-PostManEnqueue: post=0x%08X\n", r[0]);
    });
}
