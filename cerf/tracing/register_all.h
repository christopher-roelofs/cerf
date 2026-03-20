#pragma once
/* Forward declarations for per-device trace registration functions.
   Each device has its own subdirectory under cerf/tracing/ with
   per-DLL trace files (e.g. tracing/wince5/traces_mshtml.cpp).

   To add traces for a new device (e.g. WinMobile 6):
   1. Create cerf/tracing/wm6/ directory
   2. Add traces_*.cpp files with RegisterWM6*Traces functions
   3. Add a RegisterWM6Traces() call below
   4. Call RegisterTracesForDevice("wm6", tm) from main.cpp */

#include <string>

class TraceManager;

/* WinCE 5.0 traces */
void RegisterWebviewTraces(TraceManager& tm);
void RegisterMshtmlTraces(TraceManager& tm);
void RegisterMshtmlNotifyTraces(TraceManager& tm);
void RegisterMshtmlLoadTraces(TraceManager& tm);
void RegisterShdocvwTraces(TraceManager& tm);
void RegisterBrowserTraces(TraceManager& tm);
void RegisterExplorerTraces(TraceManager& tm);
void RegisterUrlmonTraces(TraceManager& tm);
void RegisterWininetTraces(TraceManager& tm);
void RegisterOle32Traces(TraceManager& tm);
void RegisterRpcrt4Traces(TraceManager& tm);
void register_traces_dcomssd(TraceManager& tm);

/* Register all traces for a specific device profile */
inline void RegisterTracesForDevice(const std::string& device, TraceManager& tm) {
    if (device == "wince5") {
        RegisterWebviewTraces(tm);
        RegisterMshtmlTraces(tm);
        RegisterMshtmlNotifyTraces(tm);
        RegisterMshtmlLoadTraces(tm);
        RegisterShdocvwTraces(tm);
        RegisterBrowserTraces(tm);
        RegisterExplorerTraces(tm);
        RegisterUrlmonTraces(tm);
        RegisterWininetTraces(tm);
        RegisterOle32Traces(tm);
        RegisterRpcrt4Traces(tm);
        register_traces_dcomssd(tm);
    }
    /* Future: else if (device == "wm6") { RegisterWM6Traces(tm); } */
}
