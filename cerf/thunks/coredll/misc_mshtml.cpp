/* Misc thunks needed by mshtml.dll: atoms, processor features, virtual memory,
   accelerator tables, IME, crypto */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <wincrypt.h>

void Win32Thunks::RegisterMiscMshtmlHandlers() {
    /* __CxxFrameHandler — C++ exception handling runtime.
       On ARM WinCE, this is called by the OS SEH mechanism for functions with
       try/catch. In our emulator, ARM exceptions are not supported, so this
       is never actually called. But it must be resolved in the IAT so DLLs
       (browser.dll) that import it can load without unresolved import errors. */
    Thunk("__CxxFrameHandler", 1550, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] __CxxFrameHandler called (should not happen in emulator)\n");
        regs[0] = 0; /* ExceptionContinueSearch */
        return true;
    });
    /* GlobalFindAtomW(lpString) -> ATOM (0 if not found) */
    Thunk("GlobalFindAtomW", 1521, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring name = ReadWStringFromEmu(mem, regs[0]);
        ATOM atom = ::GlobalFindAtomW(name.c_str());
        LOG(API, "[API] GlobalFindAtomW('%ls') -> %u\n", name.c_str(), (uint32_t)atom);
        regs[0] = (uint32_t)atom;
        return true;
    });
    /* GlobalDeleteAtom(nAtom) -> ATOM (0 on success) */
    Thunk("GlobalDeleteAtom", 1520, [](uint32_t* regs, EmulatedMemory&) -> bool {
        ATOM result = ::GlobalDeleteAtom((ATOM)regs[0]);
        LOG(API, "[API] GlobalDeleteAtom(%u) -> %u\n", regs[0], (uint32_t)result);
        regs[0] = (uint32_t)result;
        return true;
    });
    /* IsProcessorFeaturePresent(feature) -> BOOL
       WinCE ARM apps check for ARM-specific features; return FALSE for all. */
    Thunk("IsProcessorFeaturePresent", 1758, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] IsProcessorFeaturePresent(%u) -> 0 (stub)\n", regs[0]);
        regs[0] = 0;
        return true;
    });
    /* VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) -> BOOL
       In our emulator all memory is readable/writable, so this is a no-op. */
    Thunk("VirtualProtect", 526, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr = regs[0], size = regs[1], prot = regs[2], old_ptr = regs[3];
        LOG(API, "[API] VirtualProtect(0x%08X, 0x%X, prot=0x%X) -> 1 (stub)\n",
            addr, size, prot);
        if (old_ptr) mem.Write32(old_ptr, PAGE_READWRITE);
        regs[0] = 1;
        return true;
    });
    /* VirtualQuery(lpAddress, lpBuffer, dwLength) -> SIZE_T
       MEMORY_BASIC_INFORMATION on WinCE is 28 bytes (7 DWORDs):
       BaseAddress, AllocationBase, AllocationProtect, RegionSize,
       State, Protect, Type */
    Thunk("VirtualQuery", 527, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr = regs[0], buf = regs[1], len = regs[2];
        constexpr uint32_t WINCE_MBI_SIZE = 28;
        constexpr uint32_t VQUERY_REGION_SIZE = 0x10000;
        LOG(API, "[API] VirtualQuery(0x%08X, buf=0x%08X, len=%u) -> stub\n",
            addr, buf, len);
        if (buf && len >= WINCE_MBI_SIZE) {
            uint32_t page_base = addr & ~0xFFF;
            mem.Write32(buf + 0, page_base);         /* BaseAddress */
            mem.Write32(buf + 4, page_base);         /* AllocationBase */
            mem.Write32(buf + 8, PAGE_READWRITE);    /* AllocationProtect */
            mem.Write32(buf + 12, VQUERY_REGION_SIZE);/* RegionSize */
            mem.Write32(buf + 16, MEM_COMMIT);       /* State */
            mem.Write32(buf + 20, PAGE_READWRITE);   /* Protect */
            mem.Write32(buf + 24, MEM_PRIVATE);      /* Type */
            regs[0] = WINCE_MBI_SIZE;
        } else {
            regs[0] = 0;
        }
        return true;
    });
    /* DestroyAcceleratorTable(hAccel) -> BOOL */
    Thunk("DestroyAcceleratorTable", 93, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] DestroyAcceleratorTable(0x%08X) -> 1\n", regs[0]);
        regs[0] = 1; return true;
    });
    /* CreateAcceleratorTableW(lpaccel, cAccel) -> HACCEL */
    Thunk("CreateAcceleratorTableW", 92, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[STUB] CreateAcceleratorTableW(count=%u) -> 0xACC10001\n", regs[1]);
        constexpr uint32_t FAKE_HACCEL = 0xACC10001;
        regs[0] = FAKE_HACCEL;
        return true;
    });
    /* ImmSetConversionStatus(hIMC, dwConversion, dwSentence) -> BOOL */
    Thunk("ImmSetConversionStatus", 811, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[STUB] ImmSetConversionStatus(0x%08X, 0x%X, 0x%X) -> 1\n",
            regs[0], regs[1], regs[2]);
        regs[0] = 1;
        return true;
    });
    /* CryptAcquireContextW(phProv, szContainer, szProvider, dwProvType, dwFlags)
       r0=phProv, r1=szContainer, r2=szProvider, r3=dwProvType, stack[0]=dwFlags */
    Thunk("CryptAcquireContextW", 126, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t phProv = regs[0];
        LOG(API, "[STUB] CryptAcquireContextW() -> 1\n");
        constexpr uint32_t FAKE_HCRYPTPROV = 0xC4F70001;
        if (phProv) mem.Write32(phProv, FAKE_HCRYPTPROV);
        regs[0] = 1; /* TRUE = success */
        return true;
    });
    /* CryptGenRandom(hProv, dwLen, pbBuffer) -> BOOL */
    Thunk("CryptGenRandom", 143, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t len = regs[1], buf = regs[2];
        LOG(API, "[STUB] CryptGenRandom(len=%u) -> 1\n", len);
        for (uint32_t i = 0; i < len; i++)
            mem.Write8(buf + i, (uint8_t)(rand() & 0xFF));
        regs[0] = 1;
        return true;
    });
    /* CryptReleaseContext(hProv, dwFlags) -> BOOL */
    Thunk("CryptReleaseContext", 127, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[STUB] CryptReleaseContext(0x%08X) -> 1\n", regs[0]);
        regs[0] = 1;
        return true;
    });
}
