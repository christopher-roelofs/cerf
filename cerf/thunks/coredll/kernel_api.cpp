/* WinCE kernel API thunks — functions normally provided by NK.exe/coredll
   for device drivers and system services. Includes:
   - RegisterDevice/DeregisterDevice (device manager registration)
   - MapPtrToProcWithSize/MapCallerPtr (cross-process pointer mapping)
   - GetCallerProcess (process identification)
   These are distinct from the basic process/sync APIs in other files. */

#include "../win32_thunks.h"
#include "../device_manager.h"
#include "../../log.h"

void Win32Thunks::RegisterKernelApiHandlers() {
    /* RegisterDevice — ordinal 235
       HANDLE RegisterDevice(LPCWSTR prefix, DWORD index, LPCWSTR dll, DWORD context)
       Registers a stream device driver. Returns device handle or 0 on failure. */
    Thunk("RegisterDevice", 235, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t prefix_addr = regs[0];
        uint32_t index = regs[1];
        uint32_t dll_addr = regs[2];
        uint32_t context = regs[3];

        std::wstring prefix = ReadWStringFromEmu(mem, prefix_addr);
        std::wstring dll_w = ReadWStringFromEmu(mem, dll_addr);
        std::string dll_name;
        for (wchar_t wc : dll_w) dll_name += (char)wc;

        LOG(API, "[API] RegisterDevice(prefix='%ls', index=%u, dll='%s', ctx=%u)\n",
            prefix.c_str(), index, dll_name.c_str(), context);

        uint32_t handle = device_mgr.Register(prefix, index, dll_name, context, *this, mem);
        regs[0] = handle;
        return true;
    });

    /* DeregisterDevice — ordinal 236
       BOOL DeregisterDevice(HANDLE hDevice) */
    Thunk("DeregisterDevice", 236, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] DeregisterDevice(0x%08X)\n", regs[0]);
        regs[0] = device_mgr.Deregister(regs[0]) ? 1 : 0;
        return true;
    });

    /* MapPtrToProcWithSize — ordinal 1603
       LPVOID MapPtrToProcWithSize(LPVOID ptr, DWORD size, HANDLE hProcess)
       Maps a pointer from one process's address space to another.
       In our emulator, all ARM memory is globally accessible and ProcessSlot
       handles per-process overlays via the current thread's context, so this
       is an identity function — the pointer is already accessible. */
    Thunk("MapPtrToProcWithSize", 1603, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Return pointer unchanged — ProcessSlot handles translation in Translate() */
        /* regs[0] = ptr (already the return value) */
        return true;
    });

    /* CeGetRandomSeed — returns a random seed value */
    Thunk("CeGetRandomSeed", 1443, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)rand() ^ ((uint32_t)rand() << 16);
        LOG(API, "[API] CeGetRandomSeed -> 0x%08X\n", regs[0]);
        return true;
    });
    /* QueryInstructionSet */
    Thunk("QueryInstructionSet", 1677, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] QueryInstructionSet(set=%u) -> PROCESSOR_ARM\n", regs[0]);
        if (regs[1]) mem.Write32(regs[1], 0x00000004);
        regs[0] = 1; return true;
    });
    /* CeOpenCallerBuffer — kernel marshaling, identity mapping in emulator */
    Thunk("CeOpenCallerBuffer", 2569, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] CeOpenCallerBuffer(ppDest=0x%08X, pSrc=0x%08X) -> stub S_OK\n", regs[0], regs[1]);
        if (regs[0]) mem.Write32(regs[0], regs[1]);
        regs[0] = 0; return true;
    });
    Thunk("CeCloseCallerBuffer", 2570, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] CeCloseCallerBuffer -> stub S_OK\n");
        regs[0] = 0; return true;
    });
    /* GetCurrentFT — get current FILETIME */
    Thunk("GetCurrentFT", 29, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] GetCurrentFT(pFT=0x%08X) -> stub\n", regs[0]);
        FILETIME ft; GetSystemTimeAsFileTime(&ft);
        if (regs[0]) { mem.Write32(regs[0], ft.dwLowDateTime); mem.Write32(regs[0] + 4, ft.dwHighDateTime); }
        regs[0] = 1; return true;
    });
    /* CeGetFileNotificationInfo — no notifications */
    Thunk("CeGetFileNotificationInfo", 1798, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] CeGetFileNotificationInfo -> stub 0\n");
        regs[0] = 0; return true;
    });
    /* CE database stubs */
    Thunk("CeDeleteRecord", 320, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeDeleteRecord -> stub 0\n"); regs[0] = 0; return true; });
    Thunk("CeWriteRecordProps", 322, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeWriteRecordProps -> stub 0\n"); regs[0] = 0; return true; });
    Thunk("CeMountDBVol", 1164, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeMountDBVol -> stub 0\n"); regs[0] = 0; return true; });
    Thunk("CeDeleteDatabaseEx", 1193, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeDeleteDatabaseEx -> stub 0\n"); regs[0] = 0; return true; });
    Thunk("CeReadRecordPropsEx", 1194, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeReadRecordPropsEx -> stub 0\n"); regs[0] = 0; return true; });
    Thunk("CeUnmountDBVol", 1197, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeUnmountDBVol -> stub TRUE\n"); regs[0] = 1; return true; });
    Thunk("CeFlushDBVol", 1217, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeFlushDBVol -> stub TRUE\n"); regs[0] = 1; return true; });
    Thunk("CeCreateDatabaseEx2", 1468, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeCreateDatabaseEx2 -> stub 0\n"); regs[0] = 0; return true; });
    Thunk("CeSeekDatabaseEx", 1470, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeSeekDatabaseEx -> stub 0\n"); regs[0] = 0; return true; });

    /* WinCE 7 CE database + filesystem + registry helpers */
    Thunk("CeSeekDatabase", 319, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeSeekDatabase -> stub 0\n"); regs[0] = 0; return true; });
    Thunk("CeReadRecordProps", 321, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeReadRecordProps -> stub 0\n"); regs[0] = 0; return true; });
    Thunk("CeOpenDatabaseEx", 1192, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeOpenDatabaseEx -> stub 0\n"); regs[0] = 0; return true; });
    Thunk("CeGetVolumeInfoW", 1978, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] CeGetVolumeInfoW -> stub FALSE\n"); regs[0] = 0; return true; });
    Thunk("RegistryGetDWORD", 2615, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] RegistryGetDWORD -> stub E_FAIL\n");
        regs[0] = 0x80004005; /* E_FAIL */
        return true;
    });
    Thunk("RegistryNotifyWindow", 2621, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] RegistryNotifyWindow -> stub 0\n"); regs[0] = 0; return true; });
    Thunk("RegistryCloseNotification", 2624, [](uint32_t* regs, EmulatedMemory&) -> bool { LOG(API, "[API] RegistryCloseNotification -> stub 0\n"); regs[0] = 0; return true; });
}
