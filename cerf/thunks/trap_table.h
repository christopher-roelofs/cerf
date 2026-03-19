#pragma once
/* WinCE kernel trap dispatch table.

   WinCE uses trap addresses in 0xF000xxxx range for kernel API calls.
   The trap index encodes (api_set << 8 | method):
     addr = 0xF0010000 - index * 4

   API set 0 (SH_WIN32) contains kernel functions like VirtualAlloc,
   LoadLibraryW, CreateAPISet, etc. Their trap method numbers are DIFFERENT
   from coredll ordinals — we must NOT conflate them.

   API sets 1-26 are dynamically registered via CreateAPISet/RegisterAPISet.
   The shell (explorer.exe) registers SH_SHELL=21 with a vtable of functions
   like SHCreateExplorerInstance.

   This table maps W32 (set 0) method numbers to coredll thunk handler names
   so the trap dispatch can find the correct handler. */

#include <unordered_map>
#include <string>

/* W32 method numbers from psyscall.h → coredll thunk handler names.
   Only methods we have implementations for are listed. */
inline const std::unordered_map<uint32_t, std::string>& GetW32TrapTable() {
    static const std::unordered_map<uint32_t, std::string> table = {
        /* Method  → Thunk handler name (must match thunk_handlers key) */
        {  2, "CreateAPISet" },
        {  3, "VirtualAlloc" },
        {  4, "VirtualFree" },
        {  8, "LoadLibraryW" },
        {  9, "FreeLibrary" },
        { 10, "GetProcAddressW" },
        { 13, "GetTickCount" },
        { 15, "TlsCall" },          /* TlsAlloc/TlsFree/TlsGetValue/TlsSetValue */
        { 52, "CreateEventW" },
        { 53, "CreateProcessW" },
        { 54, "CreateThread" },
        { 56, "EnterCriticalSection" },
        { 57, "LeaveCriticalSection" },
        { 58, "WaitForMultipleObjects" },
        { 67, "GetOwnerProcess" },
        { 68, "GetCallerProcess" },
        { 69, "GetIdleTime" },
        { 78, "InitializeCriticalSection" },
        { 80, "CreateMutexW" },
        { 82, "Sleep" },
        { 88, "SetLastError" },
        { 89, "GetLastError" },
        { 95, "CreateFileMapping" },
        { 99, "KernelIoControl" },
        {108, "SetKMode" },
        {112, "QueryAPISetID" },
        {113, "PerformCallBack" },
        {119, "OpenProcess" },
        {125, "GetModuleFileNameW" },
        {126, "QueryPerformanceCounter" },
        {127, "QueryPerformanceFrequency" },
        {131, "GetModuleHandleW" },
        {145, "GetCommandLineW" },
        { 40, "SetExceptionHandler" },  /* per-thread SEH handler for RaiseException */
        {146, "DisableThreadLibraryCalls" },
        {147, "CreateSemaphoreW" },
        {171, "OpenEvent" },
        {173, "DuplicateHandle" },
        {177, "LoadStringW" },
        {635, "RegisterAPISet" },     /* RegisterAPISet via _APISET_CALL */
    };
    return table;
}
