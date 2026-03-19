/* DeviceIoControl thunk — handles console IOCTLs and LPC device routing.
   Split from stdio.cpp for file size compliance. */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../lpc_manager.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterDeviceIoHandlers() {
    /* DeviceIoControl — ordinal 179
       Console IOCTLs + LPC device routing for COM marshaling. */
    Thunk("DeviceIoControl", 179, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t handle = regs[0];
        uint32_t ioctl = regs[1];
        uint32_t inbuf = regs[2], insize = regs[3];
        uint32_t outbuf = ReadStackArg(regs, mem, 0);
        uint32_t outsize = ReadStackArg(regs, mem, 1);
        uint32_t bytes_ret = ReadStackArg(regs, mem, 2);

        /* LPC device — route to LpcPortManager */
        if (handle == lpc_device_handle_ && lpc_manager_) {
            regs[0] = (uint32_t)lpc_manager_->HandleIoctl(
                ioctl, inbuf, insize, outbuf, outsize, bytes_ret, mem);
            return true;
        }

        LOG(API, "[API] DeviceIoControl(ioctl=0x%08X)\n", ioctl);

        /* Console IOCTLs */
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        switch (ioctl) {
            case 0x102001C: /* Get console rows */
                if (outbuf && outsize >= 4) {
                    int rows = 25;
                    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
                        rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
                    mem.Write32(outbuf, rows);
                }
                regs[0] = 1; return true;
            case 0x1020024: /* Get console columns */
                if (outbuf && outsize >= 4) {
                    int cols = 80;
                    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
                        cols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
                    mem.Write32(outbuf, cols);
                }
                regs[0] = 1; return true;
            case 0x1020020: /* Set Ctrl-C handler — stub */
                LOG(API, "[API]   Console: set Ctrl-C handler (stub)\n");
                regs[0] = 1; return true;
            case 0x102000C: /* Set console title */
                if (inbuf && insize > 0) {
                    std::string title;
                    uint8_t* p = mem.Translate(inbuf);
                    if (p) title.assign((char*)p, insize);
                    SetConsoleTitleA(title.c_str());
                    LOG(API, "[API]   Console: set title '%s'\n", title.c_str());
                }
                regs[0] = 1; return true;
            default:
                LOG(API, "[API]   DeviceIoControl(0x%08X) -> stub\n", ioctl);
                regs[0] = 0; return true;
        }
    });
}
