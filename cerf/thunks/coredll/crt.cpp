/* CRT thunks: memcpy, memset, qsort, rand, math */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <cstring>
#include <cmath>

void Win32Thunks::RegisterCrtHandlers() {
    Thunk("memcpy", 1044, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], len = regs[2];
        if (len > 0x100000) {
            LOG(API, "[API] memcpy(0x%08X, 0x%08X, 0x%X) -> HUGE len, capping\n", dst, src, len);
            len = 0x100000;
        }
        uint8_t* dst_p = mem.Translate(dst);
        uint8_t* src_p = mem.Translate(src);
        if (dst_p && src_p && len > 0) {
            /* Verify host pointers are contiguous (same region) for both src and dst.
               Fallback regions are NOT identity-mapped, so two adjacent emulated pages
               may have non-adjacent host addresses. Native memcpy would overrun. */
            uint8_t* dst_end = mem.Translate(dst + len - 1);
            uint8_t* src_end = mem.Translate(src + len - 1);
            bool dst_contiguous = dst_end && (dst_end == dst_p + len - 1);
            bool src_contiguous = src_end && (src_end == src_p + len - 1);
            if (dst_contiguous && src_contiguous) {
                memcpy(dst_p, src_p, len);
            } else {
                /* Cross-region copy: do byte-by-byte via emulated memory */
                for (uint32_t i = 0; i < len; i++)
                    mem.Write8(dst + i, mem.Read8(src + i));
            }
        }
        regs[0] = dst; return true;
    });
    Thunk("memmove", 1046, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], len = regs[2];
        uint8_t* dst_p = mem.Translate(dst);
        uint8_t* src_p = mem.Translate(src);
        if (dst_p && src_p && len > 0) {
            uint8_t* dst_end = mem.Translate(dst + len - 1);
            uint8_t* src_end = mem.Translate(src + len - 1);
            bool dst_ok = dst_end && (dst_end == dst_p + len - 1);
            bool src_ok = src_end && (src_end == src_p + len - 1);
            if (dst_ok && src_ok) {
                memmove(dst_p, src_p, len);
            } else {
                if (dst <= src) {
                    for (uint32_t i = 0; i < len; i++)
                        mem.Write8(dst + i, mem.Read8(src + i));
                } else {
                    for (uint32_t i = len; i > 0; i--)
                        mem.Write8(dst + i - 1, mem.Read8(src + i - 1));
                }
            }
        }
        regs[0] = dst; return true;
    });
    Thunk("memset", 1047, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], val = regs[1] & 0xFF, len = regs[2];
        uint8_t* p = mem.Translate(dst);
        if (p && len > 0) {
            uint8_t* p_end = mem.Translate(dst + len - 1);
            if (p_end && (p_end == p + len - 1)) {
                memset(p, val, len);
            } else {
                for (uint32_t i = 0; i < len; i++)
                    mem.Write8(dst + i, (uint8_t)val);
            }
        }
        regs[0] = dst; return true;
    });
    Thunk("memcmp", 1043, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint8_t* ap = mem.Translate(regs[0]);
        uint8_t* bp = mem.Translate(regs[1]);
        regs[0] = (ap && bp) ? (uint32_t)memcmp(ap, bp, regs[2]) : 0;
        return true;
    });
    Thunk("_memicmp", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint8_t* ap = mem.Translate(regs[0]);
        uint8_t* bp = mem.Translate(regs[1]);
        regs[0] = (ap && bp) ? (uint32_t)_memicmp(ap, bp, regs[2]) : 0;
        return true;
    });
    Thunk("qsort", 1052, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] WARNING: qsort called - stubbed\n"); return true;
    });
    Thunk("rand", 1053, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)rand(); return true;
    });
    Thunk("Random", 80, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(rand() % 0xFFFF); return true;
    });
    Thunk("srand", 1061, [](uint32_t* regs, EmulatedMemory&) -> bool {
        srand(regs[0]); return true;
    });
    Thunk("pow", 1051, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t ba = ((uint64_t)regs[1] << 32) | regs[0];
        uint64_t bb = ((uint64_t)regs[3] << 32) | regs[2];
        double a, b; memcpy(&a, &ba, 8); memcpy(&b, &bb, 8);
        double r = pow(a, b); uint64_t rb; memcpy(&rb, &r, 8);
        regs[0] = (uint32_t)rb; regs[1] = (uint32_t)(rb >> 32);
        return true;
    });
    Thunk("sqrt", 1060, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t bits = ((uint64_t)regs[1] << 32) | regs[0];
        double d; memcpy(&d, &bits, 8); d = sqrt(d); memcpy(&bits, &d, 8);
        regs[0] = (uint32_t)bits; regs[1] = (uint32_t)(bits >> 32);
        return true;
    });
    Thunk("floor", 1013, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t bits = ((uint64_t)regs[1] << 32) | regs[0];
        double d; memcpy(&d, &bits, 8); d = floor(d); memcpy(&bits, &d, 8);
        regs[0] = (uint32_t)bits; regs[1] = (uint32_t)(bits >> 32);
        return true;
    });
    Thunk("strncpy", 1071, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], src = regs[1], count = regs[2];
        uint8_t* dst_p = mem.Translate(dst);
        uint8_t* src_p = mem.Translate(src);
        if (dst_p && src_p) strncpy((char*)dst_p, (char*)src_p, count);
        regs[0] = dst;
        return true;
    });
    Thunk("_wfopen", 1145, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring filename = ReadWStringFromEmu(mem, regs[0]);
        std::wstring mode = ReadWStringFromEmu(mem, regs[1]);
        std::wstring host_path = MapWinCEPath(filename);
        LOG(API, "[API] _wfopen('%ls' -> '%ls', '%ls')\n", filename.c_str(), host_path.c_str(), mode.c_str());
        FILE* f = _wfopen(host_path.c_str(), mode.c_str());
        regs[0] = f ? WrapHandle(f) : 0;
        return true;
    });
    Thunk("fclose", 1118, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        if (!regs[0]) { regs[0] = (uint32_t)-1; return true; }
        FILE* f = (FILE*)UnwrapHandle(regs[0]);
        RemoveHandle(regs[0]);
        regs[0] = f ? (uint32_t)fclose(f) : (uint32_t)-1;
        return true;
    });
    Thunk("fgetws", 1143, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf_addr = regs[0];
        int count = (int)regs[1];
        FILE* f = (FILE*)UnwrapHandle(regs[2]);
        if (!f || count <= 0) { regs[0] = 0; return true; }
        std::vector<wchar_t> buf(count);
        wchar_t* result = fgetws(buf.data(), count, f);
        if (result) {
            for (int i = 0; i < count; i++) {
                mem.Write16(buf_addr + i * 2, buf[i]);
                if (buf[i] == 0) break;
            }
            regs[0] = buf_addr;
        } else {
            regs[0] = 0;
        }
        return true;
    });
    Thunk("abs", 988, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)abs((int)regs[0]);
        return true;
    });
    Thunk("atof", 995, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        const char* str = (const char*)mem.Translate(regs[0]);
        double result = str ? atof(str) : 0.0;
        uint64_t bits; memcpy(&bits, &result, 8);
        regs[0] = (uint32_t)bits; regs[1] = (uint32_t)(bits >> 32);
        LOG(API, "[API] atof('%s') -> %f\n", str ? str : "(null)", result);
        return true;
    });
    Thunk("atol", 994, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        const char* str = (const char*)mem.Translate(regs[0]);
        regs[0] = str ? (uint32_t)atol(str) : 0;
        return true;
    });
}
