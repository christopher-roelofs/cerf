#pragma once
/* WinCE Stream Device Manager — handles RegisterDevice/DeregisterDevice and
   routes CreateFileW/DeviceIoControl/CloseHandle to registered ARM drivers.

   On real WinCE, device.exe + devmgr.dll manage stream device drivers.
   Each driver exports XXX_Init, XXX_Open, XXX_IOControl, XXX_Close, etc.
   RegisterDevice("LPC", 1, "lpcd.dll", 0) creates the "LPC1:" device.

   We provide a minimal device manager that:
   1. Tracks registered devices (prefix + index → driver DLL + exports)
   2. Routes CreateFileW("LPC1:") → LPC_Open via callback_executor
   3. Routes DeviceIoControl → LPC_IOControl via callback_executor
   4. Routes CloseHandle → LPC_Close via callback_executor */

#include <cstdint>
#include <string>
#include <map>
#include <mutex>
#include <functional>

class ProcessSlot;

/* Stream driver export indices */
enum StreamDriverExport {
    STRM_INIT = 0,       /* XXX_Init */
    STRM_DEINIT,         /* XXX_Deinit */
    STRM_OPEN,           /* XXX_Open */
    STRM_CLOSE,          /* XXX_Close */
    STRM_READ,           /* XXX_Read */
    STRM_WRITE,          /* XXX_Write */
    STRM_SEEK,           /* XXX_Seek */
    STRM_IOCONTROL,      /* XXX_IOControl */
    STRM_POWERUP,        /* XXX_PowerUp */
    STRM_POWERDOWN,      /* XXX_PowerDown */
    STRM_EXPORT_COUNT
};

/* Standard WinCE stream driver export name suffixes */
static const char* const kStreamExportSuffixes[STRM_EXPORT_COUNT] = {
    "_Init", "_Deinit", "_Open", "_Close", "_Read",
    "_Write", "_Seek", "_IOControl", "_PowerUp", "_PowerDown"
};

struct RegisteredDevice {
    std::wstring prefix;          /* L"LPC" */
    uint32_t index;               /* 1 → device name "LPC1:" */
    std::string dll_name;         /* "lpcd.dll" */
    uint32_t init_context;        /* return value of XXX_Init */
    uint32_t exports[STRM_EXPORT_COUNT]; /* ARM addresses, 0 = not found */
};

struct DeviceOpenHandle {
    RegisteredDevice* device;
    uint32_t open_context;        /* return value of XXX_Open (per-handle state) */
};

/* RAII guard: clears ProcessSlot for driver calls, restores on destruction.
   Matches real WinCE behavior where drivers run in device.exe's process. */
struct DriverContextGuard {
    ProcessSlot* saved;
    DriverContextGuard();
    ~DriverContextGuard();
};

class DeviceManager {
public:
    using CallbackExecutor = std::function<uint32_t(uint32_t addr, uint32_t* args, int nargs)>;

    /* Register a device. Resolves XXX_ exports and calls XXX_Init.
       Returns the device handle (for RegisterDevice return value), or 0 on failure. */
    uint32_t Register(const std::wstring& prefix, uint32_t index,
                      const std::string& dll_name, uint32_t reg_context,
                      class Win32Thunks& thunks, class EmulatedMemory& mem);

    /* Deregister a device. Calls XXX_Deinit. */
    bool Deregister(uint32_t device_handle);

    /* Check if a filename matches a registered device (e.g., "LPC1:") */
    RegisteredDevice* FindDeviceByName(const std::wstring& filename);

    /* Open a device — calls XXX_Open, returns a handle for the caller. */
    uint32_t Open(RegisteredDevice* dev, uint32_t access, uint32_t share_mode);

    /* Dispatch DeviceIoControl to the device driver. */
    int32_t IOControl(uint32_t handle, uint32_t ioctl,
                      uint32_t buf_in, uint32_t len_in,
                      uint32_t buf_out, uint32_t len_out,
                      uint32_t actual_out);

    /* Close a device handle — calls XXX_Close. */
    bool Close(uint32_t handle);

    /* Check if a handle belongs to the device manager */
    bool IsDeviceHandle(uint32_t handle) const;

    /* Set the callback executor for calling ARM code */
    void SetCallbackExecutor(CallbackExecutor exec) { executor_ = exec; }

private:
    /* Device handle space: 0xCE010000+ */
    static constexpr uint32_t DEVICE_HANDLE_BASE = 0xCE010000;
    static constexpr uint32_t DEVICE_REG_BASE    = 0xCE020000; /* for RegisterDevice return */

    std::mutex mutex_;
    std::map<std::wstring, RegisteredDevice*> devices_; /* "LPC1" → device */
    std::map<uint32_t, DeviceOpenHandle> open_handles_;  /* handle → open context */
    uint32_t next_open_handle_ = DEVICE_HANDLE_BASE;
    uint32_t next_reg_handle_ = DEVICE_REG_BASE;
    CallbackExecutor executor_;
};
