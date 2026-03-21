#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "thread_context.h"
#include "../log.h"

/* Write WIN32_FIND_DATAW to emulated memory using WinCE struct layout.
   WinCE CE_FIND_DATA layout (has dwOID, no dwReserved0/1, no cAlternateFileName):
     +0   DWORD  dwFileAttributes
     +4   FILETIME ftCreationTime
     +12  FILETIME ftLastAccessTime
     +20  FILETIME ftLastWriteTime
     +28  DWORD  nFileSizeHigh
     +32  DWORD  nFileSizeLow
     +36  DWORD  dwOID              (WinCE-specific object identifier)
     +40  WCHAR  cFileName[MAX_PATH]  (260 wchars = 520 bytes)
   Total: 560 bytes */
void Win32Thunks::WriteFindDataToEmu(EmulatedMemory& mem, uint32_t addr, const WIN32_FIND_DATAW& fd) {
    /* Strip NTFS attribute bits that collide with WinCE CE_FIND_DATA meanings:
       0x0200 SPARSE_FILE      — not in WinCE
       0x0400 REPARSE_POINT    — not in WinCE
       0x1000 OFFLINE          — WinCE: FILE_ATTRIBUTE_ROMSTATICREF
       0x2000 NOT_CONTENT_INDEXED — WinCE: FILE_ATTRIBUTE_ROMMODULE (hides files!)
       0x4000 ENCRYPTED        — not standard in WinCE */
    uint32_t attrs = fd.dwFileAttributes & ~0x7600u;
    mem.Write32(addr + 0, attrs);
    mem.Write32(addr + 4, fd.ftCreationTime.dwLowDateTime);
    mem.Write32(addr + 8, fd.ftCreationTime.dwHighDateTime);
    mem.Write32(addr + 12, fd.ftLastAccessTime.dwLowDateTime);
    mem.Write32(addr + 16, fd.ftLastAccessTime.dwHighDateTime);
    mem.Write32(addr + 20, fd.ftLastWriteTime.dwLowDateTime);
    mem.Write32(addr + 24, fd.ftLastWriteTime.dwHighDateTime);
    mem.Write32(addr + 28, fd.nFileSizeHigh);
    mem.Write32(addr + 32, fd.nFileSizeLow);
    mem.Write32(addr + 36, 0); /* dwOID — no real OID, just zero */
    /* cFileName at offset 40 */
    for (int i = 0; i < MAX_PATH && fd.cFileName[i]; i++) {
        mem.Write16(addr + 40 + i * 2, fd.cFileName[i]);
    }
    /* Null terminator */
    int len = (int)wcslen(fd.cFileName);
    if (len < MAX_PATH) mem.Write16(addr + 40 + len * 2, 0);
}

uint32_t Win32Thunks::FindResourceInPE(uint32_t module_base, uint32_t rsrc_rva, uint32_t rsrc_size,
                                       uint32_t type_id, uint32_t name_id,
                                       uint32_t& out_data_rva, uint32_t& out_data_size) {
    if (rsrc_rva == 0 || rsrc_size == 0) return 0;

    uint32_t rsrc_base = module_base + rsrc_rva;

    /* Helper: match a resource directory entry against an ID that may be either
       an integer (≤0xFFFF) or a pointer to a wide string in ARM memory (>0xFFFF).
       PE named entries have bit 31 set in the entry ID, with the lower bits
       pointing to a length-prefixed Unicode string relative to rsrc_base. */
    auto matchEntry = [&](uint32_t entry_id, uint32_t search_id) -> bool {
        if (search_id <= 0xFFFF) {
            /* Integer ID — entry must also be integer (bit 31 clear) */
            return !(entry_id & 0x80000000) && entry_id == search_id;
        }
        /* String ID — search_id is a pointer to a wide string in ARM memory.
           entry_id must be a named entry (bit 31 set), pointing to the string. */
        if (!(entry_id & 0x80000000)) return false;
        uint32_t str_offset = entry_id & 0x7FFFFFFF;
        uint32_t str_addr = rsrc_base + str_offset;
        uint16_t str_len = mem.Read16(str_addr);
        /* Read the search string from ARM memory */
        std::wstring search = ReadWStringFromEmu(mem, search_id);
        if (str_len != search.size()) return false;
        for (uint16_t j = 0; j < str_len; j++) {
            wchar_t c1 = (wchar_t)mem.Read16(str_addr + 2 + j * 2);
            wchar_t c2 = search[j];
            if (towupper(c1) != towupper(c2)) return false;
        }
        return true;
    };

    /* Level 1: Type directory — search ALL entries (named + ID) */
    uint16_t num_named = mem.Read16(rsrc_base + 12);
    uint16_t num_id = mem.Read16(rsrc_base + 14);
    uint16_t total_entries = num_named + num_id;
    uint32_t entry_addr = rsrc_base + 16;

    uint32_t type_offset = 0;
    for (uint16_t i = 0; i < total_entries; i++) {
        uint32_t id = mem.Read32(entry_addr + i * 8);
        uint32_t off = mem.Read32(entry_addr + i * 8 + 4);
        if (matchEntry(id, type_id) && (off & 0x80000000)) {
            type_offset = off & 0x7FFFFFFF;
            break;
        }
    }
    if (type_offset == 0) return 0;

    /* Level 2: Name/ID directory — search ALL entries */
    uint32_t name_dir = rsrc_base + type_offset;
    num_named = mem.Read16(name_dir + 12);
    num_id = mem.Read16(name_dir + 14);
    total_entries = num_named + num_id;
    entry_addr = name_dir + 16;

    uint32_t name_offset = 0;
    for (uint16_t i = 0; i < total_entries; i++) {
        uint32_t id = mem.Read32(entry_addr + i * 8);
        uint32_t off = mem.Read32(entry_addr + i * 8 + 4);
        if (matchEntry(id, name_id)) {
            if (off & 0x80000000) {
                name_offset = off & 0x7FFFFFFF;
            } else {
                /* Direct data entry */
                uint32_t data_entry = rsrc_base + off;
                out_data_rva = mem.Read32(data_entry);
                out_data_size = mem.Read32(data_entry + 4);
                return 1;
            }
            break;
        }
    }
    if (name_offset == 0) return 0;

    /* Level 3: Language directory - just take the first entry */
    uint32_t lang_dir = rsrc_base + name_offset;
    num_named = mem.Read16(lang_dir + 12);
    num_id = mem.Read16(lang_dir + 14);
    uint32_t total = num_named + num_id;
    if (total == 0) return 0;

    entry_addr = lang_dir + 16;
    uint32_t off = mem.Read32(entry_addr + 4);
    if (off & 0x80000000) return 0; /* Should be a leaf */

    uint32_t data_entry = rsrc_base + off;
    out_data_rva = mem.Read32(data_entry);
    out_data_size = mem.Read32(data_entry + 4);
    return 1;
}

HMODULE Win32Thunks::GetNativeModuleForResources(uint32_t emu_handle) {
    /* Check loaded ARM DLLs */
    for (auto& pair : loaded_dlls) {
        if (pair.second.base_addr == emu_handle) {
            if (!pair.second.native_rsrc_handle) {
                pair.second.native_rsrc_handle = LoadLibraryExA(
                    pair.second.path.c_str(), NULL,
                    LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            }
            return pair.second.native_rsrc_handle;
        }
    }
    /* Check main exe (or child process exe if running in a ProcessSlot) */
    if (emu_handle == GetEmuHInstance()) {
        /* Child process threads have their own exe_path in ThreadContext.
           Use a per-thread cached HMODULE so each child loads its own resources. */
        if (t_ctx && t_ctx->exe_path[0] != '\0') {
            static thread_local HMODULE child_exe_rsrc = NULL;
            if (!child_exe_rsrc) {
                child_exe_rsrc = LoadLibraryExA(t_ctx->exe_path, NULL,
                    LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            }
            return child_exe_rsrc;
        }
        static HMODULE exe_rsrc = NULL;
        if (!exe_rsrc) {
            std::string narrow_exe;
            for (auto c : exe_path) narrow_exe += (char)c;
            exe_rsrc = LoadLibraryExA(narrow_exe.c_str(), NULL,
                LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        }
        return exe_rsrc;
    }
    return NULL;
}
