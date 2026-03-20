/* WinCE Stream Device Manager implementation.
   See device_manager.h for architecture overview.

   On real WinCE, device drivers run in device.exe's process — separate from
   the calling process. MapPtrToProcWithSize translates caller pointers into
   the driver's address space. In our emulator, drivers run in the caller's
   thread but need to see GLOBAL memory (not the caller's ProcessSlot overlay),
   because driver objects (heaps, port tables) were allocated during boot in
   global context. We achieve this by temporarily clearing process_slot when
   calling into driver ARM code. */

#include "device_manager.h"
#include "win32_thunks.h"
#include "../cpu/mem.h"
#include "../log.h"
#include "../loader/pe_loader.h"
#include <algorithm>
#include <cwctype>

DriverContextGuard::DriverContextGuard() : saved(EmulatedMemory::process_slot) {
    EmulatedMemory::process_slot = nullptr;
}
DriverContextGuard::~DriverContextGuard() {
    EmulatedMemory::process_slot = saved;
}

uint32_t DeviceManager::Register(const std::wstring& prefix, uint32_t index,
                                  const std::string& dll_name, uint32_t reg_context,
                                  Win32Thunks& thunks, EmulatedMemory& mem)
{
    /* Build device name key: prefix + index, e.g. "LPC1" */
    std::wstring dev_name = prefix;
    dev_name += std::to_wstring(index);

    /* Lowercase for case-insensitive lookup */
    std::wstring dev_key = dev_name;
    for (auto& c : dev_key) c = towlower(c);

    std::lock_guard<std::mutex> lock(mutex_);

    if (devices_.count(dev_key)) {
        LOG(API, "[DEVMGR] RegisterDevice '%ls' already registered\n", dev_name.c_str());
        return 0;
    }

    /* Find the loaded ARM DLL */
    std::wstring wide_dll;
    for (char c : dll_name) wide_dll += (wchar_t)towlower(c);

    auto* loaded = thunks.FindLoadedDll(wide_dll);
    if (!loaded) {
        LOG(API, "[DEVMGR] RegisterDevice: DLL '%s' not loaded\n", dll_name.c_str());
        return 0;
    }

    auto* dev = new RegisteredDevice();
    dev->prefix = prefix;
    dev->index = index;
    dev->dll_name = dll_name;
    dev->init_context = 0;
    std::fill(std::begin(dev->exports), std::end(dev->exports), 0u);

    /* Derive the stream export prefix from the DLL name.
       Convention: "lpcd.dll" → prefix "LPC", so exports are LPC_Init, LPC_Open, etc.
       We use the RegisterDevice prefix argument. */
    std::string export_prefix;
    for (wchar_t wc : prefix) export_prefix += (char)wc;

    /* Resolve all XXX_ exports */
    for (int i = 0; i < STRM_EXPORT_COUNT; i++) {
        std::string export_name = export_prefix + kStreamExportSuffixes[i];
        dev->exports[i] = PELoader::ResolveExportName(mem, loaded->pe_info, export_name);
        if (dev->exports[i])
            LOG(API, "[DEVMGR]   %s at 0x%08X\n", export_name.c_str(), dev->exports[i]);
    }

    /* Call XXX_Init(dwContext) — reg_context is the registry path DWORD from RegisterDevice */
    if (dev->exports[STRM_INIT] && executor_) {
        uint32_t args[] = { reg_context };
        dev->init_context = executor_(dev->exports[STRM_INIT], args, 1);
        LOG(API, "[DEVMGR] %s_Init(%u) returned 0x%08X\n",
            export_prefix.c_str(), reg_context, dev->init_context);
    }

    uint32_t reg_handle = next_reg_handle_++;
    devices_[dev_key] = dev;

    LOG(API, "[DEVMGR] Registered device '%ls:' (dll=%s, handle=0x%08X)\n",
        dev_name.c_str(), dll_name.c_str(), reg_handle);
    return reg_handle;
}

bool DeviceManager::Deregister(uint32_t device_handle) {
    /* TODO: implement if needed — find device by reg handle, call XXX_Deinit */
    LOG(API, "[DEVMGR] DeregisterDevice(0x%08X) — not yet needed\n", device_handle);
    return false;
}

RegisteredDevice* DeviceManager::FindDeviceByName(const std::wstring& filename) {
    /* Parse device name: "LPC1:" → key "lpc1" */
    std::wstring key = filename;

    /* Strip trailing colon */
    if (!key.empty() && key.back() == L':')
        key.pop_back();

    /* Lowercase */
    for (auto& c : key) c = towlower(c);

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = devices_.find(key);
    return it != devices_.end() ? it->second : nullptr;
}

uint32_t DeviceManager::Open(RegisteredDevice* dev, uint32_t access, uint32_t share_mode) {
    if (!dev) return 0;

    uint32_t open_ctx = 0;
    if (dev->exports[STRM_OPEN] && executor_) {
        uint32_t args[] = { dev->init_context, access, share_mode };
        open_ctx = executor_(dev->exports[STRM_OPEN], args, 3);
        LOG(API, "[DEVMGR] %ls_Open(ctx=0x%08X) returned 0x%08X\n",
            dev->prefix.c_str(), dev->init_context, open_ctx);
    }

    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t handle = next_open_handle_++;
    open_handles_[handle] = { dev, open_ctx };

    LOG(API, "[DEVMGR] Opened device '%ls%u:' → handle=0x%08X\n",
        dev->prefix.c_str(), dev->index, handle);
    return handle;
}

int32_t DeviceManager::IOControl(uint32_t handle, uint32_t ioctl,
                                  uint32_t buf_in, uint32_t len_in,
                                  uint32_t buf_out, uint32_t len_out,
                                  uint32_t actual_out)
{
    RegisteredDevice* dev;
    uint32_t open_ctx;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = open_handles_.find(handle);
        if (it == open_handles_.end()) return -1;
        dev = it->second.device;
        open_ctx = it->second.open_context;
    }

    if (!dev->exports[STRM_IOCONTROL] || !executor_) return -1;

    LOG(API, "[DEVMGR] IOControl(%ls%u: ioctl=%u in=0x%08X out=0x%08X)\n",
        dev->prefix.c_str(), dev->index, ioctl, buf_in, buf_out);

    /* WinCE DeviceIoControl → XXX_IOControl(dwOpenData, dwCode, pBufIn, dwLenIn,
       pBufOut, dwLenOut, pdwActualOut) — 7 args */
    uint32_t args[] = { open_ctx, ioctl, buf_in, len_in, buf_out, len_out, actual_out };
    int32_t result = (int32_t)executor_(dev->exports[STRM_IOCONTROL], args, 7);
    LOG(API, "[DEVMGR] IOControl result=0x%08X\n", (uint32_t)result);
    return result;
}

bool DeviceManager::Close(uint32_t handle) {
    RegisteredDevice* dev;
    uint32_t open_ctx;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = open_handles_.find(handle);
        if (it == open_handles_.end()) return false;
        dev = it->second.device;
        open_ctx = it->second.open_context;
        open_handles_.erase(it);
    }

    if (dev->exports[STRM_CLOSE] && executor_) {
        uint32_t args[] = { open_ctx };
        executor_(dev->exports[STRM_CLOSE], args, 1);
        LOG(API, "[DEVMGR] Closed device '%ls%u:'\n", dev->prefix.c_str(), dev->index);
    }
    return true;
}

bool DeviceManager::IsDeviceHandle(uint32_t handle) const {
    return handle >= DEVICE_HANDLE_BASE && handle < DEVICE_HANDLE_BASE + 0x10000;
}
