#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* File mapping thunks: CreateFileMappingW, MapViewOfFile, etc. */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterFileMappingHandlers() {
    Thunk("CreateFileMappingW", 548, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t raw_handle = regs[0];
        uint32_t flProtect = regs[2];
        uint32_t sizeHigh = regs[3];
        uint32_t sizeLow = ReadStackArg(regs, mem, 0);
        LOG(API, "[API] CreateFileMappingW(hFile=0x%08X, protect=0x%X, size=%u:%u)\n",
            raw_handle, flProtect, sizeHigh, sizeLow);
        /* hFile=0xFFFFFFFF means anonymous (page-file-backed) mapping */
        bool anonymous = (raw_handle == 0xFFFFFFFF);
        HANDLE hFile = anonymous ? INVALID_HANDLE_VALUE : UnwrapHandle(raw_handle);
        DWORD map_size;
        if (anonymous) {
            map_size = sizeLow ? sizeLow : 0x10000; /* default 64KB for anonymous */
        } else {
            if (hFile == NULL) {
                LOG(API, "[API]   -> FAILED (null file handle)\n");
                regs[0] = 0; return true;
            }
            map_size = GetFileSize(hFile, NULL);
            if (map_size == INVALID_FILE_SIZE || map_size == 0) {
                LOG(API, "[API]   -> FAILED (file size = 0x%X)\n", map_size);
                regs[0] = 0; return true;
            }
        }
        /* Allocate emulated memory */
        static uint32_t next_mmap = 0x50000000;
        uint32_t alloc_size = (map_size + 0xFFF) & ~0xFFF;
        uint8_t* host_ptr = mem.Alloc(next_mmap, alloc_size);
        if (!host_ptr) {
            LOG(API, "[API]   -> FAILED (alloc)\n");
            regs[0] = 0; return true;
        }
        if (!anonymous) {
            /* Read file contents into the mapping */
            DWORD saved_pos = SetFilePointer(hFile, 0, NULL, FILE_CURRENT);
            SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
            DWORD bytes_read = 0;
            ReadFile(hFile, host_ptr, map_size, &bytes_read, NULL);
            SetFilePointer(hFile, saved_pos, NULL, FILE_BEGIN);
        } else {
            memset(host_ptr, 0, alloc_size);
        }
        uint32_t emu_addr = next_mmap;
        next_mmap += alloc_size;
        file_mappings[WrapHandle((HANDLE)(uintptr_t)emu_addr)] = { emu_addr, map_size };
        uint32_t fake_handle = next_fake_handle - 1;
        LOG(API, "[API]   -> handle=0x%08X (%s %u bytes at emu 0x%08X)\n",
            fake_handle, anonymous ? "anon" : "file", map_size, emu_addr);
        regs[0] = fake_handle;
        return true;
    });
    Thunk("MapViewOfFile", 549, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t mapping_handle = regs[0];
        uint32_t offset_high = regs[2], offset_low = regs[3];
        LOG(API, "[API] MapViewOfFile(handle=0x%08X, offset=0x%X:%08X)\n",
            mapping_handle, offset_high, offset_low);
        auto it = file_mappings.find(mapping_handle);
        if (it == file_mappings.end()) {
            LOG(API, "[API]   -> FAILED (unknown mapping)\n");
            regs[0] = 0; return true;
        }
        uint32_t addr = it->second.emu_addr + offset_low;
        LOG(API, "[API]   -> 0x%08X (size=%u)\n", addr, it->second.size);
        regs[0] = addr;
        return true;
    });
    Thunk("UnmapViewOfFile", 550, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] UnmapViewOfFile(0x%08X) -> 1\n", regs[0]);
        regs[0] = 1; return true;
    });
    /* CreateFileForMappingW - same as CreateFileW but used specifically before mapping */
    Thunk("CreateFileForMappingW", 1167, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring wce_path = ReadWStringFromEmu(mem, regs[0]);
        uint32_t access = regs[1], share = regs[2];
        uint32_t creation = ReadStackArg(regs, mem, 0), flags = ReadStackArg(regs, mem, 1);
        std::wstring host_path = MapWinCEPath(wce_path);
        /* WinCE CreateFileForMappingW is a kernel call that opens a file
           for memory mapping.  WinCE has looser sharing semantics than
           desktop Windows — force FILE_SHARE_READ|WRITE to avoid
           ERROR_SHARING_VIOLATION when the file is already open. */
        constexpr DWORD SHARE_RW = FILE_SHARE_READ | FILE_SHARE_WRITE;
        HANDLE h = CreateFileW(host_path.c_str(), access, share | SHARE_RW,
                               NULL, creation, flags, NULL);
        regs[0] = WrapHandle(h);
        if (h == INVALID_HANDLE_VALUE)
            LOG(API, "[API] CreateFileForMappingW('%ls', acc=0x%X, share=0x%X, creat=%u, flags=0x%X) -> FAILED err=%lu\n",
                wce_path.c_str(), access, share, creation, flags, GetLastError());
        else
            LOG(API, "[API] CreateFileForMappingW('%ls') -> handle=0x%08X\n", wce_path.c_str(), regs[0]);
        return true;
    });
}
