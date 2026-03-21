/* File time, copy, and disk space thunks — split from file.cpp */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterFileTimeHandlers() {
    Thunk("GetFileTime", 176, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        FILETIME ct, at, wt;
        BOOL ret = GetFileTime(h, regs[1] ? &ct : NULL, regs[2] ? &at : NULL, regs[3] ? &wt : NULL);
        if (ret) {
            if (regs[1]) { mem.Write32(regs[1], ct.dwLowDateTime); mem.Write32(regs[1]+4, ct.dwHighDateTime); }
            if (regs[2]) { mem.Write32(regs[2], at.dwLowDateTime); mem.Write32(regs[2]+4, at.dwHighDateTime); }
            if (regs[3]) { mem.Write32(regs[3], wt.dwLowDateTime); mem.Write32(regs[3]+4, wt.dwHighDateTime); }
        }
        LOG(API, "[API] GetFileTime(0x%08X) -> %d\n", regs[0], ret);
        regs[0] = ret; return true;
    });
    Thunk("FileTimeToLocalFileTime", 21, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        FILETIME ft_in, ft_out;
        ft_in.dwLowDateTime = mem.Read32(regs[0]);
        ft_in.dwHighDateTime = mem.Read32(regs[0] + 4);
        BOOL ret = FileTimeToLocalFileTime(&ft_in, &ft_out);
        if (ret && regs[1]) {
            mem.Write32(regs[1], ft_out.dwLowDateTime);
            mem.Write32(regs[1] + 4, ft_out.dwHighDateTime);
        }
        regs[0] = ret; return true;
    });
    Thunk("FileTimeToSystemTime", 20, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        FILETIME ft;
        ft.dwLowDateTime = mem.Read32(regs[0]);
        ft.dwHighDateTime = mem.Read32(regs[0] + 4);
        SYSTEMTIME st;
        BOOL ret = FileTimeToSystemTime(&ft, &st);
        if (ret && regs[1]) {
            mem.Write16(regs[1]+0, st.wYear); mem.Write16(regs[1]+2, st.wMonth);
            mem.Write16(regs[1]+4, st.wDayOfWeek); mem.Write16(regs[1]+6, st.wDay);
            mem.Write16(regs[1]+8, st.wHour); mem.Write16(regs[1]+10, st.wMinute);
            mem.Write16(regs[1]+12, st.wSecond); mem.Write16(regs[1]+14, st.wMilliseconds);
        }
        regs[0] = ret; return true;
    });
    Thunk("CopyFileW", 164, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring src = ReadWStringFromEmu(mem, regs[0]);
        std::wstring dst = ReadWStringFromEmu(mem, regs[1]);
        BOOL failIfExists = regs[2];
        std::wstring host_src = MapWinCEPath(src);
        std::wstring host_dst = MapWinCEPath(dst);
        BOOL ret = CopyFileW(host_src.c_str(), host_dst.c_str(), failIfExists);
        LOG(API, "[API] CopyFileW('%ls' -> '%ls', failIfExists=%d) -> %d\n",
            src.c_str(), dst.c_str(), failIfExists, ret);
        regs[0] = ret;
        return true;
    });
    ThunkOrdinal("GetTempPathW", 162); /* Ordinal-only entries */
    Thunk("FlushFileBuffers", 175, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        BOOL ret = ::FlushFileBuffers(h);
        LOG(API, "[API] FlushFileBuffers(0x%08X) -> %d\n", regs[0], ret);
        regs[0] = ret;
        return true;
    });
    ThunkOrdinal("SetFileTime", 177);
    ThunkOrdinal("DeleteAndRenameFile", 183);
    Thunk("GetDiskFreeSpaceExW", 184, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring path = ReadWStringFromEmu(mem, regs[0]);
        std::wstring mapped = MapWinCEPath(path);
        ULARGE_INTEGER freeCaller = {}, totalBytes = {}, totalFree = {};
        BOOL ret = GetDiskFreeSpaceExW(mapped.c_str(),
            regs[1] ? &freeCaller : NULL,
            regs[2] ? &totalBytes : NULL,
            regs[3] ? &totalFree : NULL);
        if (ret) {
            if (regs[1]) { mem.Write32(regs[1], freeCaller.LowPart); mem.Write32(regs[1]+4, freeCaller.HighPart); }
            if (regs[2]) { mem.Write32(regs[2], totalBytes.LowPart); mem.Write32(regs[2]+4, totalBytes.HighPart); }
            if (regs[3]) { mem.Write32(regs[3], totalFree.LowPart); mem.Write32(regs[3]+4, totalFree.HighPart); }
        }
        LOG(API, "[API] GetDiskFreeSpaceExW('%ls') -> %d\n", path.c_str(), ret);
        regs[0] = ret; return true;
    });
    /* CopyFileExW(src, dst, progressRoutine, data, cancel, flags) */
    Thunk("CopyFileExW", 1958, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring src = ReadWStringFromEmu(mem, regs[0]);
        std::wstring dst = ReadWStringFromEmu(mem, regs[1]);
        LOG(API, "[API] CopyFileExW('%ls' -> '%ls') -> stub TRUE\n", src.c_str(), dst.c_str());
        regs[0] = 1; return true;
    });
}
