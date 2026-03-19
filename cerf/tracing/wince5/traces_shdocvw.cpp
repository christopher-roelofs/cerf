#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* shdocvw.dll (WinCE 5.0 ARM build) — navigation, PIDL resolution.
   IDA base: 0x10000000.  PE checksum: 0 (not yet captured). */

void RegisterShdocvwTraces(TraceManager& tm) {
    const char* DLL = "shdocvw.dll";
    tm.SetIdaBase(DLL, 0x10000000);
    tm.SetCRC32(DLL, 0x74C56DDE);

    /* IEBindToObjectInternal — PIDL chain dump (the trace that found Bug 4) */
    tm.Add(DLL, 0x10051194, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        if (r[0] != 0) return; /* only log fStrict=0 (the Navigate path) */
        uint32_t pidl_addr = r[1];
        uint16_t cb1 = mem->Read16(pidl_addr);
        LOG(TRACE, "[TRACE] IEBindToObjectInternal(fStrict=0): pidl=0x%08X cb1=%d\n", pidl_addr, cb1);
        /* Dump terminator area */
        LOG(TRACE, "[TRACE]   PIDL bytes [%d..%d]: ", cb1, cb1 + 8);
        for (uint32_t i = cb1; i < cb1 + 8 && i < cb1 + 20; i++)
            LOG_RAW("%02X ", mem->Read8(pidl_addr + i));
        LOG_RAW("\n");
        /* Check if PIDL chain continues */
        uint16_t cb2 = mem->Read16(pidl_addr + cb1);
        if (cb2 != 0) {
            LOG(TRACE, "[TRACE]   SECOND SHITEMID at pidl+%d: cb=%d\n", cb1, cb2);
            uint32_t p2 = pidl_addr + cb1;
            char buf[80]; int bi = 0;
            for (; bi < 79; bi++) {
                uint16_t ch = mem->Read16(p2 + 8 + bi*2);
                if (!ch) break;
                buf[bi] = (char)ch;
            }
            buf[bi] = 0;
            LOG(TRACE, "[TRACE]   ILParsingName(second) = '%s'\n", buf);
        } else {
            LOG(TRACE, "[TRACE]   Proper terminator at pidl+%d (cb=0)\n", cb1);
        }
    });

    /* FireEvent_NavigateError */
    tm.Add(DLL, 0x10046B94, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] FireEvent_NavigateError!\n");
    });

    /* shdocvw navigation traces */
    tm.Add(DLL, 0x100419B8, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] shdocvw::_NavigateHelper: this=0x%08X url=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x100418A0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] shdocvw::Navigate: this=0x%08X url=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x10042A84, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] shdocvw::Navigate2: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10048E68, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] shdocvw::HlinkFrameNavigate\n");
    });
    tm.Add(DLL, 0x10048E94, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] shdocvw::HlinkFrameNavigateNHL\n");
    });
    tm.Add(DLL, 0x1009B6A0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] shdocvw::DOH_OnDataAvailable: this=0x%08X flags=0x%X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x10099698, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] shdocvw::DOH_OnStartBinding: this=0x%08X\n", r[0]);
    });

    /* Bug 8 investigation: DOH::OnObjectAvailable — document activation path.
       The bsc is embedded inside CDocObjectHost. pdoh = bsc - bsc_offset.
       From decompilation: pdoh is CONTAINING_RECORD(this, CDocObjectHost, _bsc).
       We can read _pole from the pdoh structure to check if it's already set. */
    tm.Add(DLL, 0x1009BAA8, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        /* pdoh = CONTAINING_RECORD(this, CDocObjectHost, _bsc)
           From the decompiled code, the function reads pdoh->_pole.
           _bsc offset in CDocObjectHost: need to find from constructor.
           For now, try reading at multiple offsets from this to find _pole. */
        uint32_t bsc = r[0];
        /* The bsc->pdoh relationship: pdoh is at a NEGATIVE offset from bsc.
           From the code: pdoh->_punkPending at pdoh+48*4=pdoh+192 (0xC0)
           and pdoh->_pole at some offset. Let's check common offsets. */
        /* pdoh = bsc - 0x154 (from ASM: SUB R3, R3, #0x154)
           _pole = pdoh + 0x110 = bsc - 0x44 */
        constexpr uint32_t BSC_TO_PDOH_OFFSET = 0x154;
        constexpr uint32_t PDOH_POLE_OFFSET = 0x110;
        uint32_t pdoh = bsc - BSC_TO_PDOH_OFFSET;
        uint32_t pole = mem->Read32(pdoh + PDOH_POLE_OFFSET);
        LOG(TRACE, "[TRACE] DOH::OnObjectAvailable: bsc=0x%08X pdoh=0x%08X punk=0x%08X _pole=0x%08X%s\n",
            bsc, pdoh, r[2], pole, pole ? " [SKIP — _pole already set!]" : "");
    });

    /* _OnBound — called after IOleObject QI succeeds */
    tm.Add(DLL, 0x100A568C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DOH::_OnBound: pdoh=0x%08X\n", r[0]);
    });

    /* _ActivateOleObject — activates non-DocObject documents */
    tm.Add(DLL, 0x100A3898, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DOH::_ActivateOleObject: pdoh=0x%08X\n", r[0]);
    });

    /* _SetUpTransitionCapability — called for DocObject documents (correct address!) */
    tm.Add(DLL, 0x100B49F4, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        constexpr uint32_t PDOH_POLE_OFFSET = 0x110;
        uint32_t pole = mem->Read32(r[0] + PDOH_POLE_OFFSET);
        LOG(TRACE, "[TRACE] DOH::_SetUpTransitionCapability: pdoh=0x%08X fHaveDoc=%d _pole=0x%08X\n",
            r[0], r[1], pole);
    });

    /* Trace IDispatch QI result inside _SetUpTransitionCapability.
       At 0x100B4A6C (after QI BX call): R0 = HRESULT from _pole->QI(IDispatch) */
    tm.Add(DLL, 0x100B4A6C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] _SetUpTransition: QI(IDispatch) hr=0x%08X\n", r[0]);
    });

    /* Trace Invoke(DISPID_READYSTATE) result + readyState value.
       At 0x100B4ADC (after Invoke BX call): R0 = HRESULT.
       va is on stack — we read vt and lVal from the VARIANT structure. */
    tm.Add(DLL, 0x100B4ADC, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        /* va is at SP + some offset. Read from r[13] relative positions.
           The va struct starts at SP+0xB0-0x6C = SP+0x44 based on var naming */
        uint32_t sp = r[13];
        uint16_t vt = mem->Read16(sp + 0x44);
        int32_t lVal = (int32_t)mem->Read32(sp + 0x44 + 8);
        LOG(TRACE, "[TRACE] _SetUpTransition: Invoke(READYSTATE) hr=0x%08X vt=%d lVal=%d\n",
            r[0], vt, lVal);
    });

    /* _Navigate (no-arg) — sends SHDVID command to browser to activate document.
       Checks _pmsoctBrowser at this+0x13C (approximate — from IDA decompilation). */
    tm.Add(DLL, 0x100B4EF8, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        /* Find _pmsoctBrowser offset. From decompilation, it's accessed via 'thisa->_pmsoctBrowser'.
           Let's scan likely offsets around the DOH structure. */
        uint32_t pdoh = r[0];
        /* Try several offsets to find the IOleCommandTarget pointer */
        for (uint32_t off = 0x120; off <= 0x160; off += 4) {
            uint32_t val = mem->Read32(pdoh + off);
            if (val > 0x10000 && val < 0x20000000) {
                /* Check if it looks like a COM vtable ptr */
                uint32_t vtbl = mem->Read32(val);
                if (vtbl > 0x10000000 && vtbl < 0x20000000) {
                    LOG(TRACE, "[TRACE] _Navigate: pdoh=0x%08X offset=0x%X ptr=0x%08X (vtbl=0x%08X)\n",
                        pdoh, off, val, vtbl);
                }
            }
        }
        /* Also just log the basic call */
        LOG(TRACE, "[TRACE] DOH::_Navigate: pdoh=0x%08X\n", pdoh);
    });

    /* ActivatePendingView — should switch from current to pending document */
    tm.Add(DLL, 0x10067F08, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CBaseBrowser2::ActivatePendingView: this=0x%08X\n", r[0]);
    });
    /* _ActivatePendingViewAsync — async activation trigger */
    tm.Add(DLL, 0x1006C4D4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CBaseBrowser2::_ActivatePendingViewAsync: this=0x%08X\n", r[0]);
    });
    /* CreateViewWindow — creates a new shell view window */
    tm.Add(DLL, 0x10065A1C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CBaseBrowser2::CreateViewWindow: this=0x%08X psvNew=0x%08X psvOld=0x%08X\n",
            r[0], r[1], r[2]);
    });

    /* _NavigateDocument — triggers the actual document navigation */
    tm.Add(DLL, 0x100A2824, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[60] = {};
        if (r[1]) { for (int i=0;i<59;i++) { uint16_t c=mem->Read16(r[1]+i*2); if(!c)break; url[i]=(char)c; } }
        LOG(TRACE, "[TRACE] DOH::_NavigateDocument: pdoh=0x%08X url='%s'\n", r[0], url);
    });

    /* _CancelPendingNavigation — called in non-DocObject path */
    tm.Add(DLL, 0x100A7B04, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DOH::_CancelPendingNavigation: pdoh=0x%08X\n", r[0]);
    });

    /* _OnReadyState — the trigger for NavigateComplete when state reaches 4.
       Reads _psb at pdoh+0x24 and flags at pdoh+0xC0 to check prerequisites. */
    tm.Add(DLL, 0x100B4474, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        constexpr uint32_t PSB_OFFSET = 0x24;
        constexpr uint32_t FLAGS_OFFSET = 0xC0;
        constexpr uint32_t PSV_OFFSET = 0x28; /* _psv is typically near _psb */
        uint32_t psb = mem->Read32(r[0] + PSB_OFFSET);
        uint32_t flags = mem->Read32(r[0] + FLAGS_OFFSET);
        uint32_t psv = mem->Read32(r[0] + PSV_OFFSET);
        LOG(TRACE, "[TRACE] DOH::_OnReadyState: pdoh=0x%08X rs=%d hist=%d _psb=0x%08X _psv=0x%08X flags=0x%08X (bit5=%d)\n",
            r[0], (int)r[1], (int)r[2], psb, psv, flags, (flags >> 5) & 1);
    });
}
