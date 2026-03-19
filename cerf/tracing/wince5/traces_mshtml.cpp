#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* mshtml.dll (WinCE 5.0 ARM build) — tokenizer, tree builder, layout, paint.
   IDA base: 0x10000000.  PE checksum: 0 (not yet captured). */

void RegisterMshtmlTraces(TraceManager& tm) {
    const char* DLL = "mshtml.dll";
    tm.SetIdaBase(DLL, 0x10000000);
    tm.SetCRC32(DLL, 0x848887A1);

    /* SetupDwnBindInfoAndBindCtx */
    tm.Add(DLL, 0x103C5B1C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] SetupDwnBindInfoAndBindCtx: doc=0x%08X url=0x%08X\n", r[0], r[1]);
    });
    /* CPluginSite::CreateObject */
    tm.Add(DLL, 0x107E2DCC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CPluginSite::CreateObject: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x107E35F4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CPluginSite fUsePlugin check: R3=%d (0=skip plugin path)\n", r[3]);
    });
    tm.Add(DLL, 0x107E35FC, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CPluginSite: PLUGIN path (ActiveXPlugin)\n");
    });
    tm.Add(DLL, 0x107E35B8, [](uint32_t, const uint32_t*, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CPluginSite: ACTIVEX path (TryAsActiveXControl=TRUE)\n");
    });

    /* Stage 2: Tokenizer */
    tm.Add(DLL, 0x107E91AC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] Tokenize: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x105CC51C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] OutputEof: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x105DEDC4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] WriteTagBeg: tagstm=0x%08X tag=%u\n", r[0], r[1]);
    });

    /* Stage 3: Tree building */
    tm.Add(DLL, 0x101D36BC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CHtmPost::Exec: this=0x%08X flags=0x%X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x101D4AAC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ProcessTokens: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x105DBE40, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] BeginElement: this=0x%08X elem=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x105D7CE0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ParseText: this=0x%08X text=0x%08X len=%u\n", r[0], r[1], r[2]);
    });
    tm.Add(DLL, 0x105D81D4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ParseEof: this=0x%08X\n", r[0]);
    });

    /* Stage 4: Layout */
    tm.Add(DLL, 0x10319424, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t cv = r[0];
        uint32_t layout = mem->Read32(cv + 0xFC);
        uint32_t disproot = mem->Read32(cv + 0x24);
        if (r[1] == 0x8500) /* only log OnPaint calls */
            LOG(TRACE, "[TRACE] EnsureView: this=0x%08X flags=0x%X _pLayout=0x%08X _pDispRoot=0x%08X\n",
                cv, r[1], layout, disproot);
    });
    tm.Add(DLL, 0x1031E50C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] RequestRecalc: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1059019C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CalcTextSize: this=0x%08X\n", r[0]);
    });

    /* Stage 5: Paint */
    tm.Add(DLL, 0x103F370C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CDoc::OnPaint: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1031C2F8, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] RenderView: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x106E39F0, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t dr = r[0];
        LOG(TRACE, "[TRACE] DrawRoot: this=0x%08X child=0x%08X\n", dr, mem->Read32(dr + 0x2C));
        for (int off = 0; off < 0x60; off += 4) {
            int32_t v = (int32_t)mem->Read32(dr + off);
            if (v != 0)
                LOG(TRACE, "[TRACE]   dr+%02X = 0x%08X (%d)\n", off, (uint32_t)v, v);
        }
    });
    tm.Add(DLL, 0x106EAE60, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t dr = r[0];
        LOG(TRACE, "[TRACE] RecalcRoot: this=0x%08X +3C=%d +40=%d +44=%d +48=%d +4C=%d +50=%d +54=%d +58=%d\n",
            dr,
            (int)mem->Read32(dr+0x3C), (int)mem->Read32(dr+0x40),
            (int)mem->Read32(dr+0x44), (int)mem->Read32(dr+0x48),
            (int)mem->Read32(dr+0x4C), (int)mem->Read32(dr+0x50),
            (int)mem->Read32(dr+0x54), (int)mem->Read32(dr+0x58));
    });
    tm.Add(DLL, 0x106E3D70, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t v7_addr = r[0], v18_addr = r[1];
        LOG(TRACE, "[TRACE] DrawRoot::Intersects:\n");
        LOG(TRACE, "[TRACE]   v7(redraw): ");
        for (int i = 0; i < 12; i++) LOG(API, "%08X ", mem->Read32(v7_addr + i*4));
        LOG(API, "\n");
        LOG(TRACE, "[TRACE]   v18(bounds): ");
        for (int i = 0; i < 12; i++) LOG(API, "%08X ", mem->Read32(v18_addr + i*4));
        LOG(API, "\n");
    });
    tm.Add(DLL, 0x106E46E8, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DrawEntire: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x106E4BD0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DrawBands: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x106E5030, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DrawBand: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x106E5690, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] DrawNode: this=0x%08X node=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x106E5B8C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] RecalcRoot: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10325178, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] ExecuteLayoutTasks: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10322C84, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CView::EnsureSize: this=0x%08X flags=0x%X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x10488CA4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CLayout::Dirty: this=0x%08X LR=0x%08X\n", r[0], r[14]);
    });
    tm.Add(DLL, 0x10461434, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CLayout::CalcSize: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x105884D0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CalcSizeCoreCompat: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x105821AC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CFlowLayout::Listen: this=0x%08X fListen=%d\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x107C586C, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t meas = r[1];
        LOG(TRACE, "[TRACE] MeasureLine: recalc=0x%08X meas=0x%08X\n", r[0], meas);
        if (meas >= 0x01000000 && meas < 0x02000000) {
            for (int off = 0; off <= 80; off += 4) {
                int32_t v = (int32_t)mem->Read32(meas + off);
                if (v > 0 && v < 200)
                    LOG(TRACE, "[TRACE]   meas+%02X = %d (cp-like)\n", off, v);
            }
        }
    });
    tm.Add(DLL, 0x1055A440, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CDisplay::RecalcView: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x105528E8, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] CDisplay::RecalcLines: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10552B88, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t disp = r[0], meas = r[1];
        uint32_t meas71 = meas ? mem->Read32(meas + 71*4) : 0;
        uint32_t meas_cp = meas ? mem->Read32(meas + 4) : 0;
        uint32_t meas_lastcp = meas ? mem->Read32(meas + 8) : 0;
        LOG(TRACE, "[TRACE] RecalcLinesWithMeasurer: disp=0x%08X meas=0x%08X meas[71]=0x%X cp=%d lastCp=%d\n",
            disp, meas, meas71, (int)meas_cp, (int)meas_lastcp);
    });
}
