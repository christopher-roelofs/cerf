#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "../cpu/mem.h"

struct ImportEntry {
    std::string dll_name;
    std::string func_name;
    uint16_t    ordinal;
    bool        by_ordinal;
    uint32_t    iat_addr;  /* Address in emulated memory where the IAT entry lives */
};

struct PEInfo {
    uint16_t machine;          /* IMAGE_FILE_MACHINE_ARM = 0x1C0, THUMB = 0x1C2 */
    uint32_t image_base;
    uint32_t entry_point_rva;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint16_t subsystem;
    uint16_t num_sections;
    bool     is_dll;

    std::vector<IMAGE_SECTION_HEADER> sections;
    std::vector<ImportEntry> imports;

    /* Relocation info */
    uint32_t reloc_rva;
    uint32_t reloc_size;

    /* Resource directory */
    uint32_t rsrc_rva;
    uint32_t rsrc_size;

    /* Export directory */
    uint32_t export_rva;
    uint32_t export_size;
};

class PELoader {
public:
    /* Load an ARM PE file into emulated memory.
       Returns the entry point address in emulated space, or 0 on failure. */
    static uint32_t Load(const char* path, EmulatedMemory& mem, PEInfo& info);

    /* Load a DLL dependency into emulated memory */
    static uint32_t LoadDll(const char* path, EmulatedMemory& mem, PEInfo& info);

    /* Load a PE into a ProcessSlot overlay (for child EXEs at conflicting addresses).
       Sets EmulatedMemory::process_slot for the calling thread, loads sections into
       the slot buffer, processes relocations and imports. Returns entry point or 0. */
    static uint32_t LoadIntoSlot(const char* path, EmulatedMemory& mem,
                                  PEInfo& info, ProcessSlot& slot);

    /* Resolve an export ordinal from a loaded PE's export directory.
       Returns the virtual address (base + RVA) of the exported function, or 0 if not found. */
    static uint32_t ResolveExportOrdinal(EmulatedMemory& mem, const PEInfo& info, uint16_t ordinal);

    /* Resolve an export by name from a loaded PE's export directory.
       Returns the virtual address (base + RVA) of the exported function, or 0 if not found. */
    static uint32_t ResolveExportName(EmulatedMemory& mem, const PEInfo& info, const std::string& name);

private:
    static bool ParseHeaders(const uint8_t* data, size_t size, PEInfo& info);
    static bool LoadSections(const uint8_t* data, size_t size, EmulatedMemory& mem, const PEInfo& info);
    static bool ProcessRelocations(EmulatedMemory& mem, const PEInfo& info, uint32_t actual_base);
    static bool ResolveImports(const uint8_t* data, size_t size, EmulatedMemory& mem, PEInfo& info);
};
