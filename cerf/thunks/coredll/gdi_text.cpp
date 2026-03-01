/* GDI thunks: fonts, text metrics, DrawTextW, ExtTextOutW */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterGdiTextHandlers() {
    Thunk("CreateFontIndirectW", 895, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOGFONTW lf = {};
        lf.lfHeight = (LONG)mem.Read32(regs[0]); lf.lfWidth = (LONG)mem.Read32(regs[0]+4);
        lf.lfWeight = (LONG)mem.Read32(regs[0]+16); lf.lfCharSet = mem.Read8(regs[0]+23);
        for (int i = 0; i < 32; i++) { lf.lfFaceName[i] = mem.Read16(regs[0]+28+i*2); if (!lf.lfFaceName[i]) break; }
        regs[0] = (uint32_t)(uintptr_t)CreateFontIndirectW(&lf); return true;
    });
    Thunk("GetTextMetricsW", 898, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        TEXTMETRICW tm; BOOL ret = GetTextMetricsW((HDC)(intptr_t)(int32_t)regs[0], &tm);
        if (ret && regs[1]) {
            mem.Write32(regs[1]+0, tm.tmHeight); mem.Write32(regs[1]+4, tm.tmAscent);
            mem.Write32(regs[1]+8, tm.tmDescent); mem.Write32(regs[1]+12, tm.tmInternalLeading);
            mem.Write32(regs[1]+16, tm.tmExternalLeading); mem.Write32(regs[1]+20, tm.tmAveCharWidth);
            mem.Write32(regs[1]+24, tm.tmMaxCharWidth); mem.Write32(regs[1]+28, tm.tmWeight);
            mem.Write32(regs[1]+32, tm.tmOverhang); mem.Write32(regs[1]+36, tm.tmDigitizedAspectX);
            mem.Write32(regs[1]+40, tm.tmDigitizedAspectY);
            mem.Write16(regs[1]+44, tm.tmFirstChar); mem.Write16(regs[1]+46, tm.tmLastChar);
            mem.Write16(regs[1]+48, tm.tmDefaultChar); mem.Write16(regs[1]+50, tm.tmBreakChar);
            mem.Write8(regs[1]+52, tm.tmItalic); mem.Write8(regs[1]+53, tm.tmUnderlined);
            mem.Write8(regs[1]+54, tm.tmStruckOut); mem.Write8(regs[1]+55, tm.tmPitchAndFamily);
            mem.Write8(regs[1]+56, tm.tmCharSet);
        }
        regs[0] = ret; return true;
    });
    Thunk("DrawTextW", 945, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        std::wstring text = ReadWStringFromEmu(mem, regs[1]);
        int count = (int32_t)regs[2]; uint32_t rect_addr = regs[3];
        uint32_t format = ReadStackArg(regs, mem, 0);
        RECT rc; rc.left = (int32_t)mem.Read32(rect_addr); rc.top = (int32_t)mem.Read32(rect_addr+4);
        rc.right = (int32_t)mem.Read32(rect_addr+8); rc.bottom = (int32_t)mem.Read32(rect_addr+12);
        int ret = ::DrawTextW(hdc, text.c_str(), count, &rc, format);
        mem.Write32(rect_addr, (uint32_t)rc.left); mem.Write32(rect_addr+4, (uint32_t)rc.top);
        mem.Write32(rect_addr+8, (uint32_t)rc.right); mem.Write32(rect_addr+12, (uint32_t)rc.bottom);
        regs[0] = (uint32_t)ret; return true;
    });
    Thunk("SetTextAlign", 1654, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetTextAlign((HDC)(intptr_t)(int32_t)regs[0], regs[1]); return true; });
    Thunk("GetTextAlign", 1655, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetTextAlign((HDC)(intptr_t)(int32_t)regs[0]); return true; });
    Thunk("ExtTextOutW", 896, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    Thunk("GetTextExtentExPointW", 897, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    Thunk("EnumFontFamiliesW", 965, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t arm_callback = regs[2];
        uint32_t arm_lparam = regs[3];
        LOG(THUNK, "[THUNK] EnumFontFamiliesW(hdc=0x%08X, proc=0x%08X)\n", regs[0], arm_callback);
        if (!callback_executor || !arm_callback) { regs[0] = 1; return true; }

        /* Scratch area for LOGFONT (92 bytes) + TEXTMETRIC (60 bytes) in ARM memory */
        static uint32_t scratch = 0x3F004000;
        if (!mem.IsValid(scratch)) mem.Alloc(scratch, 0x1000);
        uint32_t lf_addr = scratch;
        uint32_t tm_addr = scratch + 96;

        /* Provide a hardcoded Tahoma font — avoids native GDI calls that may
           fail in deeply nested callback context. WinCE apps just need to know
           at least one font exists. */
        static const wchar_t* font_names[] = { L"Tahoma", L"Arial", L"Courier New" };
        int result = 1;
        for (int f = 0; f < 3 && result != 0; f++) {
            /* Zero-fill both structures */
            for (uint32_t i = 0; i < 92; i++) mem.Write8(lf_addr + i, 0);
            for (uint32_t i = 0; i < 60; i++) mem.Write8(tm_addr + i, 0);
            /* LOGFONTW: height=-13, weight=400, charset=1(DEFAULT), face name */
            mem.Write32(lf_addr + 0, (uint32_t)-13);  /* lfHeight */
            mem.Write32(lf_addr + 16, 400);            /* lfWeight (FW_NORMAL) */
            mem.Write8(lf_addr + 23, 1);               /* lfCharSet (DEFAULT_CHARSET) */
            mem.Write8(lf_addr + 27, 0x22);            /* lfPitchAndFamily (VARIABLE_PITCH | FF_SWISS) */
            const wchar_t* name = font_names[f];
            for (int i = 0; name[i] && i < 31; i++) mem.Write16(lf_addr + 28 + i * 2, name[i]);
            /* TEXTMETRICW: reasonable defaults */
            mem.Write32(tm_addr + 0, 16);   /* tmHeight */
            mem.Write32(tm_addr + 4, 13);   /* tmAscent */
            mem.Write32(tm_addr + 8, 3);    /* tmDescent */
            mem.Write32(tm_addr + 20, 7);   /* tmAveCharWidth */
            mem.Write32(tm_addr + 24, 14);  /* tmMaxCharWidth */
            mem.Write32(tm_addr + 28, 400); /* tmWeight */
            mem.Write16(tm_addr + 44, 0x20); /* tmFirstChar */
            mem.Write16(tm_addr + 46, 0xFFFD); /* tmLastChar */
            mem.Write8(tm_addr + 55, 0x22); /* tmPitchAndFamily */
            mem.Write8(tm_addr + 56, 1);    /* tmCharSet (DEFAULT_CHARSET) */

            uint32_t args[4] = { lf_addr, tm_addr, 4 /* TRUETYPE_FONTTYPE */, arm_lparam };
            LOG(THUNK, "[THUNK] EnumFontFamiliesW: callback for '%ls'\n", name);
            result = (int)callback_executor(arm_callback, args, 4);
            LOG(THUNK, "[THUNK] EnumFontFamiliesW: callback returned %d\n", result);
        }
        regs[0] = (uint32_t)result;
        return true;
    });
    Thunk("GetTextFaceW", 967, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] GetTextFaceW(hdc=0x%08X, nCount=%d, lpFaceName=0x%08X) -> 0 (stub)\n",
               regs[0], regs[1], regs[2]);
        regs[0] = 0; return true;
    });
}
