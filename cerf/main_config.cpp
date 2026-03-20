/* CERF command-line argument parsing — split from main.cpp */
#include "main_config.h"
#include "log.h"
#include "cli_helpers.h"
#include <cstring>
#include <cstdlib>

bool ParseCerfArgs(int argc, char* argv[], CerfConfig& cfg) {
    for (int i = 1; i < argc; i++) {
        if (cfg.exe_path) break; /* Everything after exe_path belongs to the ARM app */
        if (strcmp(argv[i], "--trace") == 0) {
            cfg.trace = true;
            Log::EnableCategory(Log::TRACE);
        } else if (strncmp(argv[i], "--log=", 6) == 0) {
            Log::SetEnabled(Log::ParseCategories(argv[i] + 6));
            cfg.explicit_log = true;
        } else if (strncmp(argv[i], "--no-log=", 9) == 0) {
            cfg.no_log_mask |= Log::ParseCategories(argv[i] + 9);
        } else if (strncmp(argv[i], "--log-file=", 11) == 0) {
            cfg.log_file = argv[i] + 11;
        } else if (strcmp(argv[i], "--flush-outputs") == 0) {
            cfg.flush_outputs = true;
        } else if (strncmp(argv[i], "--device=", 9) == 0) {
            cfg.device_override = argv[i] + 9;
        } else if (strncmp(argv[i], "--fake-screen-resolution=", 25) == 0) {
            const char* val = argv[i] + 25;
            cfg.cli_fake_screen_resolution = (strcmp(val, "false") != 0 && strcmp(val, "0") != 0 && strcmp(val, "no") != 0) ? 1 : 0;
        } else if (strncmp(argv[i], "--screen-width=", 15) == 0) {
            cfg.cli_screen_width = atoi(argv[i] + 15);
        } else if (strncmp(argv[i], "--screen-height=", 16) == 0) {
            cfg.cli_screen_height = atoi(argv[i] + 16);
        } else if (strncmp(argv[i], "--os-major=", 11) == 0) {
            cfg.cli_os_major = atoi(argv[i] + 11);
        } else if (strncmp(argv[i], "--os-minor=", 11) == 0) {
            cfg.cli_os_minor = atoi(argv[i] + 11);
        } else if (strncmp(argv[i], "--os-build=", 11) == 0) {
            cfg.cli_os_build = atoi(argv[i] + 11);
        } else if (strncmp(argv[i], "--os-build-date=", 16) == 0) {
            cfg.cli_os_build_date = argv[i] + 16;
        } else if (strncmp(argv[i], "--fake-total-phys=", 18) == 0) {
            cfg.cli_fake_total_phys = atoi(argv[i] + 18);
        } else if (strncmp(argv[i], "--gdb-port=", 11) == 0) {
            cfg.gdb_port = atoi(argv[i] + 11);
        } else if (strcmp(argv[i], "--no-init") == 0) {
            cfg.no_init = true;
        } else if (strcmp(argv[i], "--quiet") == 0) {
            Log::SetEnabled(Log::NONE);
            cfg.explicit_log = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return false;
        } else {
            cfg.exe_path = argv[i];
        }
    }

    /* Apply --no-log after everything else */
    if (cfg.no_log_mask) {
        Log::SetEnabled(Log::GetEnabled() & ~cfg.no_log_mask);
    }

    if (cfg.flush_outputs) {
        Log::SetFlush(true);
    }

    if (cfg.log_file) {
        Log::SetFile(cfg.log_file);
    }

    return true;
}
