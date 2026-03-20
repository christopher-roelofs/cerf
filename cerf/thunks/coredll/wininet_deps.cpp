#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Missing coredll thunks required by wininet.dll (and shdocvw/mshtml).
   C runtime string ops, file helpers, time, locale, and misc stubs. */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <cwctype>

void Win32Thunks::RegisterWininetDepsHandlers() {
    /* C runtime string functions operating on ARM memory */
    Thunk("memchr", 31, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf = regs[0]; int c = (int)(uint8_t)regs[1]; uint32_t n = regs[2];
        for (uint32_t i = 0; i < n; i++) {
            if (mem.Read8(buf + i) == (uint8_t)c) { regs[0] = buf + i; return true; }
        }
        regs[0] = 0;
        return true;
    });

    Thunk("strchr", 1064, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t s = regs[0]; int c = (int)(char)regs[1];
        for (uint32_t i = 0; ; i++) {
            char ch = (char)mem.Read8(s + i);
            if (ch == (char)c) { regs[0] = s + i; return true; }
            if (ch == 0) break;
        }
        regs[0] = 0;
        return true;
    });

    Thunk("strrchr", 1407, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t s = regs[0]; int c = (int)(char)regs[1];
        uint32_t last = 0;
        for (uint32_t i = 0; ; i++) {
            char ch = (char)mem.Read8(s + i);
            if (ch == (char)c) last = s + i;
            if (ch == 0) break;
        }
        regs[0] = last;
        return true;
    });

    Thunk("strpbrk", 1406, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t s = regs[0], accept = regs[1];
        std::string acc = ReadStringFromEmu(mem, accept);
        for (uint32_t i = 0; ; i++) {
            char ch = (char)mem.Read8(s + i);
            if (ch == 0) break;
            if (acc.find(ch) != std::string::npos) { regs[0] = s + i; return true; }
        }
        regs[0] = 0;
        return true;
    });

    Thunk("tolower", 1090, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)::tolower((int)regs[0]); return true;
    });
    Thunk("toupper", 1091, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)::toupper((int)regs[0]); return true;
    });

    Thunk("strtoul", 1405, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::string s = ReadStringFromEmu(mem, regs[0]);
        uint32_t endptr_ptr = regs[1]; int base = (int)regs[2];
        char* endp = NULL;
        unsigned long val = ::strtoul(s.c_str(), &endp, base);
        if (endptr_ptr && endp) {
            uint32_t offset = (uint32_t)(endp - s.c_str());
            mem.Write32(endptr_ptr, regs[0] + offset);
        }
        regs[0] = (uint32_t)val;
        return true;
    });

    Thunk("_stricmp", 1410, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::string a = ReadStringFromEmu(mem, regs[0]);
        std::string b = ReadStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)_stricmp(a.c_str(), b.c_str());
        return true;
    });

    Thunk("_strnicmp", 1411, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::string a = ReadStringFromEmu(mem, regs[0]);
        std::string b = ReadStringFromEmu(mem, regs[1]);
        int n = (int)regs[2];
        regs[0] = (uint32_t)_strnicmp(a.c_str(), b.c_str(), n);
        return true;
    });

    Thunk("_strrev", 1413, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t s = regs[0];
        uint32_t len = 0;
        while (mem.Read8(s + len)) len++;
        for (uint32_t i = 0; i < len / 2; i++) {
            uint8_t a = mem.Read8(s + i), b = mem.Read8(s + len - 1 - i);
            mem.Write8(s + i, b); mem.Write8(s + len - 1 - i, a);
        }
        regs[0] = s;
        return true;
    });

    Thunk("_strlwr", 1415, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t s = regs[0];
        for (uint32_t i = 0; ; i++) {
            uint8_t c = mem.Read8(s + i);
            if (!c) break;
            mem.Write8(s + i, (uint8_t)::tolower(c));
        }
        regs[0] = s;
        return true;
    });

    Thunk("_strupr", 1416, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t s = regs[0];
        for (uint32_t i = 0; ; i++) {
            uint8_t c = mem.Read8(s + i);
            if (!c) break;
            mem.Write8(s + i, (uint8_t)::toupper(c));
        }
        regs[0] = s;
        return true;
    });

    Thunk("_isctype", 1417, [](uint32_t* regs, EmulatedMemory&) -> bool {
        int c = (int)regs[0], mask = (int)regs[1];
        regs[0] = (uint32_t)_isctype(c, mask);
        return true;
    });

    Thunk("_wcslwr", 231, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t s = regs[0];
        for (uint32_t i = 0; ; i += 2) {
            uint16_t c = mem.Read16(s + i);
            if (!c) break;
            mem.Write16(s + i, (uint16_t)towlower(c));
        }
        regs[0] = s;
        return true;
    });

    /* _vsnwprintf — uses our existing WprintfFormat engine */
    Thunk("_vsnwprintf", 1132, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0]; int count = (int)regs[1];
        uint32_t fmt_ptr = regs[2]; uint32_t va_ptr = regs[3];
        std::wstring fmt = ReadWStringFromEmu(mem, fmt_ptr);
        /* Read va_list args from emulated memory (up to 32 args) */
        uint32_t args[32];
        for (int i = 0; i < 32; i++) args[i] = mem.Read32(va_ptr + i * 4);
        std::wstring result = WprintfFormat(mem, fmt, args, 32);
        int written = (int)result.size();
        if (written >= count) written = count - 1;
        for (int i = 0; i < written && i < count; i++)
            mem.Write16(dst + i * 2, (uint16_t)result[i]);
        if (count > 0) mem.Write16(dst + written * 2, 0);
        regs[0] = (uint32_t)written;
        return true;
    });

    /* File I/O */
    Thunk("RemoveDirectoryW", 161, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring path = MapWinCEPath(ReadWStringFromEmu(mem, regs[0]));
        BOOL ret = ::RemoveDirectoryW(path.c_str());
        regs[0] = ret;
        return true;
    });

    Thunk("SetEndOfFile", 178, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        regs[0] = ::SetEndOfFile(h);
        return true;
    });

    Thunk("GetFileAttributesExW", 1237, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring path = MapWinCEPath(ReadWStringFromEmu(mem, regs[0]));
        uint32_t level = regs[1], data_ptr = regs[2];
        WIN32_FILE_ATTRIBUTE_DATA fad;
        BOOL ret = ::GetFileAttributesExW(path.c_str(), (GET_FILEEX_INFO_LEVELS)level, &fad);
        if (ret && data_ptr) {
            fad.dwFileAttributes &= ~0x7600u; /* strip NTFS-only attrs (SPARSE/REPARSE/OFFLINE/NCI/ENCRYPTED) */
            mem.Write32(data_ptr + 0, fad.dwFileAttributes);
            mem.Write32(data_ptr + 4, fad.ftCreationTime.dwLowDateTime);
            mem.Write32(data_ptr + 8, fad.ftCreationTime.dwHighDateTime);
            mem.Write32(data_ptr + 12, fad.ftLastAccessTime.dwLowDateTime);
            mem.Write32(data_ptr + 16, fad.ftLastAccessTime.dwHighDateTime);
            mem.Write32(data_ptr + 20, fad.ftLastWriteTime.dwLowDateTime);
            mem.Write32(data_ptr + 24, fad.ftLastWriteTime.dwHighDateTime);
            mem.Write32(data_ptr + 28, fad.nFileSizeHigh);
            mem.Write32(data_ptr + 32, fad.nFileSizeLow);
        }
        regs[0] = ret;
        return true;
    });

    /* Time */
    Thunk("LocalFileTimeToFileTime", 22, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t local_ptr = regs[0], ft_ptr = regs[1];
        FILETIME local, utc;
        local.dwLowDateTime = mem.Read32(local_ptr);
        local.dwHighDateTime = mem.Read32(local_ptr + 4);
        BOOL ret = ::LocalFileTimeToFileTime(&local, &utc);
        if (ret && ft_ptr) {
            mem.Write32(ft_ptr, utc.dwLowDateTime);
            mem.Write32(ft_ptr + 4, utc.dwHighDateTime);
        }
        regs[0] = ret;
        return true;
    });

    Thunk("SetFileTime", 177, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = UnwrapHandle(regs[0]);
        auto readFT = [&](uint32_t ptr, FILETIME* out) -> const FILETIME* {
            if (!ptr) return NULL;
            out->dwLowDateTime = mem.Read32(ptr);
            out->dwHighDateTime = mem.Read32(ptr + 4);
            return out;
        };
        FILETIME ct, at, wt;
        BOOL ret = ::SetFileTime(h, readFT(regs[1], &ct),
                                 readFT(regs[2], &at), readFT(regs[3], &wt));
        regs[0] = ret;
        return true;
    });

    /* Locale */
    Thunk("IsDBCSLeadByteEx", 192, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ::IsDBCSLeadByteEx((UINT)regs[0], (BYTE)regs[1]);
        return true;
    });

    /* Threading */
    Thunk("PostThreadMessageW", 290, [](uint32_t* regs, EmulatedMemory&) -> bool {
        DWORD tid = regs[0]; UINT msg = regs[1];
        WPARAM wp = (WPARAM)regs[2]; LPARAM lp = (LPARAM)(int32_t)regs[3];
        BOOL result = ::PostThreadMessageW(tid, msg, wp, lp);
        DWORD err = result ? 0 : GetLastError();
        LOG(API, "[API] PostThreadMessageW(tid=%u, msg=0x%04X, wP=0x%X, lP=0x%X) -> %d (err=%lu)\n",
            tid, msg, wp, lp, result, err);
        regs[0] = result;
        return true;
    });


    /* Misc stubs */
    Thunk("CeEventHasOccurred", 479, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; return true;
    });

    Thunk("FlushViewOfFile", 551, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* Our file mappings are in emulated memory, nothing to flush */
        regs[0] = 1;
        return true;
    });

    Thunk("GetUserNameExW", 1503, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf = regs[1], size_ptr = regs[2];
        const wchar_t* name = L"User";
        if (buf && size_ptr) {
            uint32_t sz = mem.Read32(size_ptr);
            for (size_t i = 0; name[i] && i < sz - 1; i++)
                mem.Write16(buf + (uint32_t)(i * 2), (uint16_t)name[i]);
            mem.Write16(buf + (uint32_t)(wcslen(name) * 2), 0);
            mem.Write32(size_ptr, (uint32_t)wcslen(name));
        }
        regs[0] = 1;
        return true;
    });

    Thunk("CryptUnprotectData", 1600, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] CryptUnprotectData -> stub failure\n");
        SetLastError(ERROR_NOT_SUPPORTED);
        regs[0] = 0;
        return true;
    });

    Thunk("ReportEventW", 1819, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 1; return true;
    });

    Thunk("_ltoa", 1039, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        long val = (long)(int32_t)regs[0];
        uint32_t buf = regs[1]; int radix = (int)regs[2];
        char tmp[36];
        _ltoa(val, tmp, radix);
        for (size_t i = 0; tmp[i]; i++) mem.Write8(buf + (uint32_t)i, tmp[i]);
        mem.Write8(buf + (uint32_t)strlen(tmp), 0);
        regs[0] = buf;
        return true;
    });
}
