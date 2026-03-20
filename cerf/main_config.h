#pragma once
#include <cstdint>

/* Parsed command-line configuration for the CERF emulator */
struct CerfConfig {
    const char* exe_path = nullptr;
    const char* device_override = nullptr;
    bool trace = false;
    bool no_init = false;  /* --no-init: skip HKLM\init boot sequence */
    bool explicit_log = false;
    const char* log_file = nullptr;
    bool flush_outputs = false;
    uint32_t no_log_mask = 0;
    int cli_fake_screen_resolution = -1; /* -1=unset, 0=false, 1=true */
    int cli_screen_width = 0;
    int cli_screen_height = 0;
    int cli_os_major = -1, cli_os_minor = -1, cli_os_build = -1;
    const char* cli_os_build_date = nullptr;
    int cli_fake_total_phys = 0;
    int gdb_port = 0;  /* 0 = disabled; >0 = GDB stub listens on this port */
};

/* Parse command-line arguments into config. Returns false if --help was requested. */
bool ParseCerfArgs(int argc, char* argv[], CerfConfig& cfg);
