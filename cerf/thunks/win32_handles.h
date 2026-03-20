#pragma once
/* Handle mapping and DIB tracking declarations — split from win32_thunks.h.
   Included by win32_thunks.h; do not include directly.

   These are PRIVATE members of Win32Thunks declared in the handle-mapping
   section of the class body. */

    /* Handle mapping (64-bit HANDLE <-> 32-bit fake handle for ARM round-trip).
       Global map used by orchestrator (process_slot==nullptr).
       Per-process maps in per_process_handles_ for child processes. */
    std::map<uint32_t, HANDLE> handle_map;
    uint32_t next_fake_handle = 0x00100000;
    struct FileMappingInfo { uint32_t emu_addr; uint32_t size; };
    std::map<uint32_t, FileMappingInfo> file_mappings;

    /* Per-process handle state (D10) */
    struct PerProcessHandleState {
        std::map<uint32_t, HANDLE> handle_map;
        uint32_t next_fake = 0x00100000;
    };
    std::map<ProcessSlot*, PerProcessHandleState> per_process_handles_;
    std::mutex handle_map_mutex_;

    /* DIB section tracking */
    uint32_t next_dib_addr = 0x04000000;
    std::map<uint32_t, uint32_t> hbitmap_to_emu_pvbits; /* HBITMAP -> emu pvBits addr */
    uint32_t WrapHandle(HANDLE h);
    HANDLE UnwrapHandle(uint32_t fake);
    void RemoveHandle(uint32_t fake);
public:
    void EraseProcessHandles(ProcessSlot* slot);
private:
