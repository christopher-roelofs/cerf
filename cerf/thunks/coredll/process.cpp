#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Process/thread thunks: CreateProcessW, CreateThread stubs, file mapping stubs */
#include "../win32_thunks.h"
#include <cstdio>
#include <vector>

void Win32Thunks::RegisterProcessHandlers() {
    auto stub0 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            printf("[THUNK] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    Thunk("CreateThread", 492, stub0("CreateThread"));
    Thunk("CreateProcessW", 493, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* WinCE CreateProcessW(pszImageName, pszCmdLine, psaProcess, psaThread,
           fInheritHandles, fdwCreate, pvEnvironment, pszCurDir, psiStartInfo, pProcInfo) */
        uint32_t image_ptr = regs[0], cmdline_ptr = regs[1];
        uint32_t fdwCreate = ReadStackArg(regs, mem, 1);
        uint32_t curdir_ptr = ReadStackArg(regs, mem, 3);
        uint32_t procinfo_ptr = ReadStackArg(regs, mem, 5);
        std::wstring image, cmdline, curdir;
        if (image_ptr) image = ReadWStringFromEmu(mem, image_ptr);
        if (cmdline_ptr) cmdline = ReadWStringFromEmu(mem, cmdline_ptr);
        if (curdir_ptr) curdir = ReadWStringFromEmu(mem, curdir_ptr);
        printf("[THUNK] CreateProcessW(image='%ls', cmdline='%ls', curdir='%ls', flags=0x%X)\n",
               image.c_str(), cmdline.c_str(), curdir.c_str(), fdwCreate);
        STARTUPINFOW si = {}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {};
        std::vector<wchar_t> cmdline_buf(cmdline.begin(), cmdline.end());
        cmdline_buf.push_back(0);
        BOOL ret = CreateProcessW(
            image.empty() ? NULL : image.c_str(),
            cmdline_buf.data(),
            NULL, NULL, FALSE, fdwCreate, NULL,
            curdir.empty() ? NULL : curdir.c_str(),
            &si, &pi);
        if (ret && procinfo_ptr) {
            mem.Write32(procinfo_ptr + 0x00, (uint32_t)(uintptr_t)pi.hProcess);
            mem.Write32(procinfo_ptr + 0x04, (uint32_t)(uintptr_t)pi.hThread);
            mem.Write32(procinfo_ptr + 0x08, pi.dwProcessId);
            mem.Write32(procinfo_ptr + 0x0C, pi.dwThreadId);
        }
        printf("[THUNK]   -> %s (pid=%d)\n", ret ? "OK" : "FAILED", ret ? pi.dwProcessId : 0);
        regs[0] = ret;
        return true;
    });
    Thunk("TerminateThread", 491, stub0("TerminateThread"));
    Thunk("SetThreadPriority", 514, stub0("SetThreadPriority"));
    Thunk("GetExitCodeProcess", 519, stub0("GetExitCodeProcess"));
    Thunk("OpenProcess", 509, stub0("OpenProcess"));
    Thunk("WaitForMultipleObjects", 498, stub0("WaitForMultipleObjects"));
    Thunk("CreateFileMappingW", 548, stub0("CreateFileMappingW"));
    Thunk("MapViewOfFile", 549, stub0("MapViewOfFile"));
    Thunk("UnmapViewOfFile", 550, stub0("UnmapViewOfFile"));
}
