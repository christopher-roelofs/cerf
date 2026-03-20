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

}
