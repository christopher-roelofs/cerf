#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* mshtml.dll (WinCE 5.0 ARM build) — document loading, CCodeLoad, data binding.
   IDA base: 0x10000000.  Continuation of traces_mshtml.cpp. */

void RegisterMshtmlLoadTraces(TraceManager& tm) {
    const char* DLL = "mshtml.dll";
    tm.SetIdaBase(DLL, 0x10000000);
    tm.SetCRC32(DLL, 0x848887A1);

    /* Document loading */
    tm.Add(DLL, 0x1027F714, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CDocument::Load(mk): doc=0x%08X mk=0x%08X bc=0x%08X fl=0x%X\n", r[0], r[1], r[2], r[3]);
    });
    tm.Add(DLL, 0x10309C44, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CDoc::Load(url): doc=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1014C388, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CDoc::Load(stm): doc=0x%08X stm=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x1030A330, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t cdoc = r[0];
        uint32_t flags_1184 = mem->Read32(cdoc + 1184);
        LOG(TRACE, "[TRACE] CDoc::Load(IPersistMoniker): this=0x%08X fullyAvail=%d moniker=0x%08X flags_1184=0x%08X shell=%d\n",
            cdoc, r[1], r[2], flags_1184, (flags_1184 >> 29) & 1);
    });
    tm.Add(DLL, 0x1030CA7C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CDoc::InitNew: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x104105F0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CDoc::SetObjectRects: this=0x%08X posRect=0x%08X clipRect=0x%08X\n", r[0], r[1], r[2]);
    });
    tm.Add(DLL, 0x103220AC, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        int cx = (int)mem->Read32(r[1]);
        int cy = (int)mem->Read32(r[1] + 4);
        LOG(TRACE, "[TRACE] CView::SetViewSize: this=0x%08X size=%dx%d\n", r[0], cx, cy);
    });
    tm.Add(DLL, 0x105AB814, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t pinfo = r[3];
        LOG(TRACE, "[TRACE] CreateObjectNow: site=0x%08X pUnk=0x%08X pinfo=0x%08X\n", r[0], r[2], pinfo);
    });
    tm.Add(DLL, 0x105C69AC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CHtmPre::Init: this=0x%08X load=0x%08X\n", r[0], r[1]);
    });

    /* CMarkup::Load variants */
    tm.Add(DLL, 0x102E7418, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] CMarkup::Load: markup=0x%08X hli=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x102E3A0C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CMarkup::Load(moniker): markup=0x%08X moniker=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x102E38E0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CMarkup::Load(stream): markup=0x%08X stream=0x%08X\n", r[0], r[1]);
    });

    /* CCodeLoad */
    tm.Add(DLL, 0x102D2170, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CCodeLoad::Init: this=0x%08X site=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x102D34C4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CCodeLoad::OnObjectAvailable: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x102D41F4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CCodeLoad::BindToObject: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x102D291C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CCodeLoad::OnDwnChan: this=0x%08X\n", r[0]);
    });

    /* Download context */
    tm.Add(DLL, 0x1030F3FC, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[40] = {};
        if (r[2]) {
            for (int i = 0; i < 20; i++) {
                uint16_t c = mem->Read16(r[2] + i*2);
                if (!c) break;
                url[i] = (c < 128) ? (char)c : '?';
            }
        }
        LOG(TRACE, "[TRACE] NewDwnCtx: doc=0x%08X type=%u url='%s' elem=0x%08X\n", r[0], r[1], url, r[3]);
    });

    /* Data binding / buffering */
    tm.Add(DLL, 0x10220FEC, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t bd = r[0];
        uint32_t stm = mem->Read32(bd + 0x64);
        uint32_t wp = 0, rp = 0;
        if (stm >= 0x200000 && stm <= 0x300000) {
            wp = mem->Read32(stm + 0x44);
            rp = mem->Read32(stm + 0x40);
        }
        LOG(TRACE, "[TRACE] BufferData: bd=0x%08X stm=0x%08X r=%u w=%u\n", bd, stm, rp, wp);
    });
    tm.Add(DLL, 0x102227D4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] SignalData: bd=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1022534C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] OnDataAvailable: bd=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1021F32C, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t bd = r[0], li = r[1];
        uint32_t pchUrl = mem->Read32(li + 16);
        char url[40] = {};
        if (pchUrl >= 0x200000 && pchUrl < 0x1200000) {
            for (int i = 0; i < 30; i++) {
                uint16_t c = mem->Read16(pchUrl + i*2);
                if (!c) break;
                url[i] = (c < 128) ? (char)c : '?';
            }
        }
        LOG(TRACE, "[TRACE] Bind: bd=0x%08X url='%s'\n", bd, url);
    });

    /* Channel signaling */
    tm.Add(DLL, 0x101EB8FC, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] SetCallback: chan=0x%08X pfn=0x%08X pv=0x%08X fSig=%u\n",
            r[0], r[1], r[2], mem->Read32(r[0] + 0x18));
    });
    tm.Add(DLL, 0x101EBBA8, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] Signal: chan=0x%08X fSig=%u pfn=0x%08X\n",
            r[0], mem->Read32(r[0] + 0x18), mem->Read32(r[0] + 0x1C));
    });
}
