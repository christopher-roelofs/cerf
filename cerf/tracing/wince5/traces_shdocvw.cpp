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
    tm.Add(DLL, 0x100419B8, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[120] = {};
        if (r[1]) { for (int i=0;i<119;i++) { uint16_t c=mem->Read16(r[1]+i*2); if(!c)break; url[i]=(char)c; } }
        LOG(TRACE, "[TRACE] shdocvw::_NavigateHelper: this=0x%08X url='%s'\n", r[0], url);
    });
    tm.Add(DLL, 0x100418A0, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[80] = {};
        if (r[1]) { for (int i=0;i<79;i++) { uint16_t c=mem->Read16(r[1]+i*2); if(!c)break; url[i]=(char)c; } }
        LOG(TRACE, "[TRACE] shdocvw::Navigate: this=0x%08X url='%s'\n", r[0], url);
    });
    tm.Add(DLL, 0x10042A84, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] shdocvw::Navigate2: this=0x%08X\n", r[0]);
    });
    /* _BrowseObject — shell namespace navigation via PIDL */
    tm.Add(DLL, 0x1004885C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] shdocvw::_BrowseObject: pidl=0x%08X flags=0x%X\n", r[1], r[2]);
    });
    /* InitPSFInternet — creates Internet URL shell folder */
    tm.Add(DLL, 0x100505F0, [](uint32_t pc, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] shdocvw::InitPSFInternet called\n");
        /* Dump the QI table (qit_2) at IDA 0x100084D4 */
        constexpr uint32_t IDA_BASE = 0x10000000;
        constexpr uint32_t INIT_IDA = 0x100505F0;
        uint32_t base = pc - (INIT_IDA - IDA_BASE);
        uint32_t qit = base + (0x100084D4 - IDA_BASE);
        LOG(TRACE, "[TRACE]   QI table at 0x%08X:\n", qit);
        for (int i = 0; i < 4; i++) {
            uint32_t iid_ptr = mem->Read32(qit + i * 8);
            uint32_t offset = mem->Read32(qit + i * 8 + 4);
            LOG(TRACE, "[TRACE]     [%d] iid_ptr=0x%08X offset=%u\n", i, iid_ptr, offset);
        }
    });
    /* _GetInternetRoot — gets Internet shell folder for URL PIDL creation */
    tm.Add(DLL, 0x1005075C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] _GetInternetRoot: ppsfRoot=0x%08X\n", r[0]);
    });
    /* After _GetInternetRoot returns inside IECreateFromPathCPWithBCW: R0 = HRESULT.
       Also dump the g_psfInternet vtable to see which ParseDisplayName is called. */
    tm.Add(DLL, 0x10051AD8, [](uint32_t pc, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] IECreateFromPath: _GetInternetRoot returned hr=0x%08X\n", r[0]);
        /* Read g_psfInternet from shdocvw .data (IDA 0x100DFA94) */
        constexpr uint32_t IDA_BASE = 0x10000000;
        constexpr uint32_t CALL_IDA = 0x10051AD8;
        uint32_t rt_base = pc - (CALL_IDA - IDA_BASE);
        uint32_t g_psf_addr = rt_base + (0x100DFA94 - IDA_BASE);
        uint32_t g_psf = mem->Read32(g_psf_addr);
        if (g_psf) {
            uint32_t vtbl = mem->Read32(g_psf);
            uint32_t pdn = mem->Read32(vtbl + 12); /* ParseDisplayName = vtable[3] */
            LOG(TRACE, "[TRACE]   g_psfInternet=0x%08X vtbl=0x%08X ParseDisplayName=0x%08X\n",
                g_psf, vtbl, pdn);
        } else {
            LOG(TRACE, "[TRACE]   g_psfInternet=NULL!\n");
        }
    });
    /* IECreateFromPathCPWithBCW — the main PIDL-from-URL function */
    tm.Add(DLL, 0x10051880, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[80] = {};
        if (r[1]) { for (int i=0;i<79;i++) { uint16_t c=mem->Read16(r[1]+i*2); if(!c)break; url[i]=(char)c; } }
        LOG(TRACE, "[TRACE] IECreateFromPathCPWithBCW(cp=%u, '%s')\n", r[0], url);
    });
    /* _ValidateURL — checks if URL is valid for navigation */
    tm.Add(DLL, 0x1004D9F4, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[80] = {};
        if (r[0]) { for (int i=0;i<79;i++) { uint16_t c=mem->Read16(r[0]+i*2); if(!c)break; url[i]=(char)c; } }
        LOG(TRACE, "[TRACE] _ValidateURL('%s', flags=0x%X)\n", url, r[1]);
    });
    /* UrlToPidl — creates simple PIDL from URL string */
    tm.Add(DLL, 0x1004DEB4, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[80] = {};
        if (r[1]) { for (int i=0;i<79;i++) { uint16_t c=mem->Read16(r[1]+i*2); if(!c)break; url[i]=(char)c; } }
        LOG(TRACE, "[TRACE] UrlToPidl(cp=%u, '%s')\n", r[0], url);
    });
    /* _PidlFromUrlEtc — creates PIDL from URL string */
    tm.Add(DLL, 0x10080E24, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[80] = {};
        uint32_t urlp = r[2]; /* 3rd arg: pszUrl */
        if (urlp) { for (int i=0;i<79;i++) { uint16_t c=mem->Read16(urlp+i*2); if(!c)break; url[i]=(char)c; } }
        LOG(TRACE, "[TRACE] shdocvw::_PidlFromUrlEtc: url='%s' ppidl=0x%08X\n", url, r[3]);
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

    /* _Navigate (no-arg) — sends SHDVID command to browser to activate document */
    tm.Add(DLL, 0x100B4EF8, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DOH::_Navigate: pdoh=0x%08X\n", r[0]);
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

    /* _OnReadyState — the trigger for NavigateComplete when state reaches 4. */
    tm.Add(DLL, 0x100B4474, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        constexpr uint32_t PSB_OFFSET = 0x24;
        constexpr uint32_t FLAGS_OFFSET = 0xC0;
        constexpr uint32_t PSV_OFFSET = 0x28;
        uint32_t psb = mem->Read32(r[0] + PSB_OFFSET);
        uint32_t flags = mem->Read32(r[0] + FLAGS_OFFSET);
        uint32_t psv = mem->Read32(r[0] + PSV_OFFSET);
        LOG(TRACE, "[TRACE] DOH::_OnReadyState: pdoh=0x%08X rs=%d hist=%d "
            "_psb=0x%08X _psv=0x%08X flags=0x%08X (bit5=%d)\n",
            r[0], (int)r[1], (int)r[2], psb, psv, flags, (flags >> 5) & 1);
    });

    /* === VIEW ACTIVATION CHAIN traces === */

    /* CDocObjectHost field offsets (verified from IDA disassembly):
       _hwnd    = 0x3C    _uState  = 0xA8    _pole    = 0x110
       _pmsov   = 0x134   _rcView  = 0x144   flags    = 0xC0 */
    constexpr uint32_t DOH_HWND = 0x3C, DOH_USTATE = 0xA8, DOH_FLAGS = 0xC0;
    constexpr uint32_t DOH_POLE = 0x110, DOH_PMSOV = 0x134;

    tm.Add(DLL, 0x100A176C, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] DOH::UIActivate: pdoh=0x%08X uState=%u uStatePrev=%u "
            "_pole=0x%08X _pmsov=0x%08X _hwnd=0x%08X\n",
            r[0], r[1], mem->Read32(r[0] + DOH_USTATE),
            mem->Read32(r[0] + DOH_POLE), mem->Read32(r[0] + DOH_PMSOV),
            mem->Read32(r[0] + DOH_HWND));
    });
    tm.Add(DLL, 0x100A3068, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] DOH::_EnsureActivateMsoView: pdoh=0x%08X _pole=0x%08X "
            "_pmsov=0x%08X\n", r[0], mem->Read32(r[0]+DOH_POLE), mem->Read32(r[0]+DOH_PMSOV));
    });
    tm.Add(DLL, 0x100B980C, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t flags = mem->Read32(r[0] + DOH_FLAGS);
        LOG(TRACE, "[TRACE] DOH::DocCanHandleNavigation: pdoh=0x%08X flags=0x%08X "
            "result=%d (0x1000000=%d 0x800000=%d)\n",
            r[0], flags, (flags&0x1000000)&&(flags&0x800000), (flags>>24)&1, (flags>>23)&1);
    });
    tm.Add(DLL, 0x100A1F4C, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] DOH::_ShowMsoView: pdoh=0x%08X _pmsov=0x%08X _hwnd=0x%08X\n",
            r[0], mem->Read32(r[0] + DOH_PMSOV), mem->Read32(r[0] + DOH_HWND));
    });

    /* DOH::_ActivateMsoView — creates the IOleDocumentView */
    tm.Add(DLL, 0x100A2304, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DOH::_ActivateMsoView: pdoh=0x%08X\n", r[0]);
    });

    /* CBaseBrowser2::_UIActivateView — calls _bbd._psv->UIActivate(uState) */
    tm.Add(DLL, 0x1006498C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CBaseBrowser2::_UIActivateView: this=0x%08X uState=%u\n",
            r[0], r[1]);
    });
}
