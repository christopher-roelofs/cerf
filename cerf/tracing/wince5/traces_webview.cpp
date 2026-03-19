#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* webview.dll (WinCE 5.0 ARM build) — HTML rendering pipeline traces.
   IDA base: 0x10000000.  PE checksum: 0 (not yet captured). */

void RegisterWebviewTraces(TraceManager& tm) {
    const char* DLL = "webview.dll";
    tm.SetIdaBase(DLL, 0x10000000);
    tm.SetCRC32(DLL, 0x8A50813A); /* WinCE 5.0 sysgen ARM build */

    /* Navigation lifecycle traces for Bug 8 investigation */
    tm.Add(DLL, 0x10078CA0, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        /* CBrowserBase::Navigate: r0=this, r1=pszURL */
        char url[60] = {};
        if (r[1]) { for (int i = 0; i < 59; i++) { uint16_t c = mem->Read16(r[1]+i*2); if (!c) break; url[i]=(char)c; } }
        LOG(TRACE, "[TRACE] CBrowserBase::Navigate: this=0x%08X url='%s'\n", r[0], url);
    });
    tm.Add(DLL, 0x10078828, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        /* CBrowserBase::IntraDocumentNavigate: r0=this, r1=currentURL, r2=newURL */
        char cur[40] = {}, nxt[40] = {};
        if (r[1]) { for (int i=0;i<39;i++) { uint16_t c=mem->Read16(r[1]+i*2); if(!c)break; cur[i]=(char)c; } }
        if (r[2]) { for (int i=0;i<39;i++) { uint16_t c=mem->Read16(r[2]+i*2); if(!c)break; nxt[i]=(char)c; } }
        LOG(TRACE, "[TRACE] IntraDocumentNavigate: cur='%s' new='%s'\n", cur, nxt);
    });
    tm.Add(DLL, 0x100786AC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        /* CBrowserBase::PostNavigate */
        LOG(TRACE, "[TRACE] PostNavigate: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1007DC2C, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        /* CBrowserBase::BeforeNavigate: r0=this, r1=url */
        char url[40] = {};
        if (r[1]) { for (int i=0;i<39;i++) { uint16_t c=mem->Read16(r[1]+i*2); if(!c)break; url[i]=(char)c; } }
        LOG(TRACE, "[TRACE] BeforeNavigate: url='%s'\n", url);
    });
    tm.Add(DLL, 0x1007DD9C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        /* CBrowserBase::NavigateComplete */
        LOG(TRACE, "[TRACE] NavigateComplete: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1007CB00, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        /* CHTMLControlBase::SetAbort */
        LOG(TRACE, "[TRACE] CHTMLControlBase::SetAbort: this=0x%08X abort=%d\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x1007CA5C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        /* CBrowserBase::SetAbort */
        LOG(TRACE, "[TRACE] CBrowserBase::SetAbort: this=0x%08X abort=%d\n", r[0], r[1]);
    });

    tm.Add(DLL, 0x10081314, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] InitializeParser: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10085840, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ParseContent: this=0x%08X pReq=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x100CDE90, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t pHeadBox = mem->Read32(r[0] + 0x38);
        uint32_t htmlBase = mem->Read32(r[0] + 0x88);
        int32_t pl = (int32_t)mem->Read32(r[2]);
        int32_t pt = (int32_t)mem->Read32(r[2]+4);
        int32_t pr = (int32_t)mem->Read32(r[2]+8);
        int32_t pb = (int32_t)mem->Read32(r[2]+12);
        int32_t vpOrgX = htmlBase ? (int32_t)mem->Read32(htmlBase + 0x20) : 0;
        int32_t vpOrgY = htmlBase ? (int32_t)mem->Read32(htmlBase + 0x24) : 0;
        int32_t hScroll = htmlBase ? (int32_t)mem->Read32(htmlBase + 0x2C) : 0;
        int32_t vScroll = htmlBase ? (int32_t)mem->Read32(htmlBase + 0x30) : 0;
        LOG(TRACE, "[TRACE] CLayoutEngine::Render: this=0x%08X hdc=0x%08X headBox=0x%08X prcInvalid={%d,%d,%d,%d} vpOrg=(%d,%d) scroll=(%d,%d)\n",
            r[0], r[1], pHeadBox, pl, pt, pr, pb, vpOrgX, vpOrgY, hScroll, vScroll);
        if (pHeadBox) {
            uint32_t box = pHeadBox;
            for (int i = 0; i < 30 && box; i++) {
                uint32_t bf = mem->Read32(box + 0x3C);
                if ((bf >> 1) & 1) {
                    int32_t l = (int32_t)mem->Read32(box + 0x74);
                    int32_t t = (int32_t)mem->Read32(box + 0x78);
                    int32_t rr = (int32_t)mem->Read32(box + 0x7C);
                    int32_t b = (int32_t)mem->Read32(box + 0x80);
                    LOG(TRACE, "[TRACE]   topBlock=0x%08X blockRect={%d,%d,%d,%d} flags=0x%08X\n",
                        box, l, t, rr, b, bf);
                    break;
                }
                box = mem->Read32(box + 0x0C);
            }
        }
    });
    tm.Add(DLL, 0x1006F788, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DoTidy: this=0x%08X hwnd=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x100495C0, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] GetViewportOrgY: this=0x%08X val=0x%08X (%d)\n",
            r[0], mem->Read32(r[0] + 0x24), (int32_t)mem->Read32(r[0] + 0x24));
    });
    tm.Add(DLL, 0x10049590, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] GetViewportOrgX: this=0x%08X val=0x%08X (%d)\n",
            r[0], mem->Read32(r[0] + 0x28), (int32_t)mem->Read32(r[0] + 0x28));
    });
    tm.Add(DLL, 0x10048FA8, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint16_t feat = mem->Read16(r[0] + 0x1C0);
        LOG(TRACE, "[TRACE] ShowImages: this=0x%08X m_fFeatures=0x%04X (showImg=%d)\n",
            r[0], feat, (feat & 2) ? 1 : 0);
    });
    tm.Add(DLL, 0x100C7A54, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DrawContainer: this=0x%08X props=0x%08X hdc=0x%08X\n", r[0], r[1], r[2]);
    });
    /* NotifyContentAvailable — triggers ReportNodes on the main thread */
    tm.Add(DLL, 0x1006FE8C, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t flags = mem->Read32(r[0] + 0x20); /* m_dwFlags offset (approximate) */
        LOG(TRACE, "[TRACE] NotifyContentAvailable: this=0x%08X flags=0x%08X\n", r[0], flags);
    });
    /* NotifyContentComplete — triggers ContentComplete on the main thread.
       m_pFactory is at this+0x2C, m_hwndNotify at this+0x30 (from ASM). */
    tm.Add(DLL, 0x10070124, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        constexpr uint32_t PFACTORY_OFF = 0x2C;
        constexpr uint32_t HWND_NOTIFY_OFF = 0x30;
        uint32_t pFactory = mem->Read32(r[0] + PFACTORY_OFF);
        uint32_t hwndNotify = mem->Read32(r[0] + HWND_NOTIFY_OFF);
        LOG(TRACE, "[TRACE] NotifyContentComplete: this=0x%08X pFactory=0x%08X hwnd=0x%08X %s\n",
            r[0], pFactory, hwndNotify, pFactory == 0 ? "*** SKIPPED (pFactory=NULL) ***" : "");
    });
    tm.Add(DLL, 0x1003DB64, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        int code = (int)r[1];
        uint32_t szTarget = r[2];
        wchar_t tbuf[64] = {};
        for (int i = 0; i < 60 && szTarget; i++) {
            uint16_t c = mem->Read16(szTarget + i * 2);
            if (!c) break;
            tbuf[i] = (wchar_t)c;
        }
        /* m_hwndLegacyNotify at this+0x140, m_hWnd at this+0x4C (from ASM) */
        constexpr uint32_t HWND_LEGACY_NOTIFY_OFFSET = 0x140;
        constexpr uint32_t HWND_SELF_OFFSET = 0x4C;
        uint32_t legacy_hwnd = mem->Read32(r[0] + HWND_LEGACY_NOTIFY_OFFSET);
        uint32_t own_hwnd = mem->Read32(r[0] + HWND_SELF_OFFSET);
        LOG(TRACE, "[TRACE] SendNotify: this=0x%08X code=%d target='%ls' legacyHwnd=0x%08X selfHwnd=0x%08X\n",
            r[0], code, tbuf, legacy_hwnd, own_hwnd);
    });
    /* SendNotify decision traces — Bug 10 investigation */
    tm.Add(DLL, 0x1003DE2C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        /* At this point: R3 = bDoDefault (loaded by preceding LDR) */
        LOG(TRACE, "[TRACE] SendNotify bDoDefault=%d (0=drop, 1=fallback to m_hWnd)\n", r[3]);
    });
    tm.Add(DLL, 0x1003DE4C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        /* BL SendMessageW: R0=hWnd, R1=msg(0x4E), R2=wParam, R3=lParam */
        LOG(TRACE, "[TRACE] SendNotify FALLBACK: SendMessageW(hwnd=0x%08X, WM_NOTIFY, wp=%d, lp=0x%08X)\n",
            r[0], (int32_t)r[2], r[3]);
    });
    tm.Add(DLL, 0x1003DE50, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        /* After SendMessageW returns: R0 = result */
        LOG(TRACE, "[TRACE] SendNotify FALLBACK result=%d (0x%08X)\n", (int32_t)r[0], r[0]);
    });
    /* put_NotificationHwnd — trace to confirm if ever called */
    tm.Add(DLL, 0x100420B8, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] put_NotificationHwnd: this=0x%08X hwnd=0x%08X\n", r[0], r[1]);
    });
    /* GetURL vtable call debug — at the ADD LR, R0, #0x14 in GetURL
       R0 = vtable_ptr (just loaded from *m_pReqMgr), R4 = m_pReqMgr */
    tm.Add(DLL, 0x10079F04, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t vtable_ptr = r[0];
        uint32_t reqmgr = r[4];
        uint32_t func = mem->IsValid(vtable_ptr + 0x14) ? mem->Read32(vtable_ptr + 0x14) : 0xDEAD;
        LOG(TRACE, "[TRACE] CreateRequest vtable: reqmgr=0x%08X vtbl=0x%08X func=0x%08X\n",
            reqmgr, vtable_ptr, func);
        if (mem->IsValid(vtable_ptr)) {
            LOG(TRACE, "[TRACE]   [0]=0x%08X [1]=0x%08X [2]=0x%08X [3]=0x%08X [4]=0x%08X [5]=0x%08X\n",
                mem->Read32(vtable_ptr), mem->Read32(vtable_ptr+4), mem->Read32(vtable_ptr+8),
                mem->Read32(vtable_ptr+12), mem->Read32(vtable_ptr+16), mem->Read32(vtable_ptr+20));
            /* Compare emulated vs host direct read to detect address translation bug */
            uint8_t* host_p = mem->Translate(vtable_ptr + 0x14);
            uint32_t host_val = host_p ? *(volatile uint32_t*)host_p : 0xDEAD;
            MEMORY_BASIC_INFORMATION mbi = {};
            VirtualQuery(host_p, &mbi, sizeof(mbi));
            LOG(TRACE, "[TRACE]   host_ptr=%p host_val=0x%08X (emu=0x%08X) state=0x%lX protect=0x%lX allocBase=%p %s\n",
                host_p, host_val, func, mbi.State, mbi.Protect, mbi.AllocationBase,
                host_val != func ? "*** MISMATCH ***" : "match");
        }
    });
    /* GetCurrentBaseURL — check the base URL for relative image resolution */
    tm.Add(DLL, 0x10048F18, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        /* Returns LPCWSTR at some offset in the object */
        LOG(TRACE, "[TRACE] GetCurrentBaseURL: this=0x%08X\n", r[0]);
    });
    /* CBrowserBase::GetURL — initiates download for images */
    tm.Add(DLL, 0x10079A3C, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[80] = {};
        if (r[1]) { for (int i = 0; i < 79; i++) { uint16_t c = mem->Read16(r[1]+i*2); if (!c) break; url[i]=(char)c; } }
        LOG(TRACE, "[TRACE] CBrowserBase::GetURL: this=0x%08X url='%s' type=%d callback=0x%08X\n",
            r[0], url, r[2], r[3]);
    });
    /* ImageFail — called when image download fails */
    tm.Add(DLL, 0x10042558, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ImageFail: this=0x%08X cookie=0x%08X bForced=%d\n", r[0], r[1], r[2]);
    });
    /* OnWindowMessage entry — trace to check if WM_NOTIFY reaches the handler */
    tm.Add(DLL, 0x1003C190, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        if (r[1] == 0x4E) { /* Only log WM_NOTIFY */
            LOG(TRACE, "[TRACE] OnWindowMessage WM_NOTIFY: this=0x%08X wP=0x%08X lP=0x%08X\n",
                r[0], r[2], r[3]);
        }
    });
    /* Html_InlineImage — the actual image download handler */
    tm.Add(DLL, 0x1003DF08, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char target[60] = {};
        if (r[1]) { for (int i = 0; i < 59; i++) { uint16_t c = mem->Read16(r[1]+i*2); if (!c) break; target[i]=(char)c; } }
        LOG(TRACE, "[TRACE] Html_InlineImage: this=0x%08X target='%s' cookie=0x%08X\n",
            r[0], target, r[2]);
    });
    tm.Add(DLL, 0x1013C338, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] RenderChildren: this=0x%08X renderer=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x1010F3A0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CTextBox::Render: this=0x%08X renderer=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x1010FA78, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CTextBox::DrawTextW: this=0x%08X hdc=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x1008A754, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CXHTMLParser::CreateNode: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x100C9650, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CLayoutEngine::BeginElement: this=0x%08X elem=0x%08X\n", r[0], r[1]);
    });
    /* CBrowserBase traces */
    tm.Add(DLL, 0x10041D90, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] CBrowserBase::Load: this=0x%08X vtbl=0x%08X\n", r[0], mem->Read32(r[0]));
    });
    tm.Add(DLL, 0x1003B628, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] pProvider->Attach hr=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1003B694, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] DoVerbInPlace hr check: R3=0x%08X\n", mem->Read32(r[11] + 0x08));
    });
    tm.Add(DLL, 0x1003B708, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t base = mem->Read32(r[11]);
        uint32_t pInit = mem->Read32(base + 0x14C);
        uint16_t vt = pInit ? mem->Read16(pInit) : 0xFFFF;
        uint32_t val = pInit ? mem->Read32(pInit + 8) : 0;
        LOG(TRACE, "[TRACE] DoVerbInPlace m_pInitParams: base=0x%08X pInit=0x%08X vt=%u val=0x%08X\n",
            base, pInit, vt, val);
    });
    tm.Add(DLL, 0x1003B27C, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t vtbl = mem->Read32(r[0]);
        uint32_t base = r[0] - 0x84;
        LOG(TRACE, "[TRACE] DoVerbInPlace: this=0x%08X vtbl=0x%08X base=0x%08X\n", r[0], vtbl, base);
        LOG(TRACE, "[TRACE]   DoVerb reads from 0x%08X = 0x%08X\n", base + 0x148, mem->Read32(base + 0x148));
    });
    tm.Add(DLL, 0x100786AC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CBrowserBase::PostNavigate: this=0x%08X url=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x10078CA0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CBrowserBase::Navigate: this=0x%08X\n", r[0]);
    });
}
