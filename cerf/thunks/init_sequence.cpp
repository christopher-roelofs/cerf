#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* WinCE HKLM\init boot sequence processing.
   On real WinCE, filesys.exe reads HKLM\init and launches each process
   in order, respecting DependXX synchronization. We replicate this with
   LaunchArmChildProcess for per-process isolation. */
#include "win32_thunks.h"
#include "../log.h"
#include <algorithm>
#include <cstdio>

void Win32Thunks::ProcessInitHive(EmulatedMemory& mem) {
    LOG(API, "[INIT] Processing HKLM\\init boot sequence...\n");

    /* Event handles for blacklisted entries — kept alive until init completes
       so dependent entries can wait on them successfully. */
    std::vector<HANDLE> blacklist_events;

    struct InitEntry {
        uint32_t order;           /* XX from LaunchXX key name */
        std::wstring exe_path;    /* value of LaunchXX */
        std::vector<uint32_t> depends; /* order numbers this entry depends on */
    };
    std::vector<InitEntry> entries;

    /* Read HKLM\init entries under the loader lock (registry access) */
    {
        std::lock_guard<std::recursive_mutex> lock(registry_mutex);
        std::wstring init_key = L"hklm\\init";
        auto it = registry.find(init_key);
        if (it == registry.end()) {
            LOG(API, "[INIT] No HKLM\\init key found, skipping boot sequence\n");
            return;
        }

        auto& vals = it->second.values;
        /* Collect LaunchXX entries */
        for (auto& [name, val] : vals) {
            if (name.size() < 7) continue;
            std::wstring prefix = name.substr(0, 6);
            /* Case-insensitive check for "Launch" */
            std::wstring lower_prefix = prefix;
            for (auto& c : lower_prefix) c = towlower(c);
            if (lower_prefix != L"launch") continue;

            /* Extract order number */
            std::wstring num_str = name.substr(6);
            uint32_t order = 0;
            for (auto c : num_str) {
                if (c < L'0' || c > L'9') { order = 0; break; }
                order = order * 10 + (c - L'0');
            }
            if (order == 0) continue;

            /* Get the exe path from the value */
            if (val.type != REG_SZ || val.data.size() < 2) continue;
            std::wstring exe_path((const wchar_t*)val.data.data(),
                                   val.data.size() / 2);
            if (!exe_path.empty() && exe_path.back() == L'\0')
                exe_path.pop_back();
            if (exe_path.empty()) continue;

            InitEntry entry;
            entry.order = order;
            entry.exe_path = exe_path;

            /* Look for corresponding DependXX */
            wchar_t depend_key[32];
            swprintf(depend_key, 32, L"Depend%u", order);
            auto dep_it = vals.find(depend_key);
            if (dep_it == vals.end()) {
                /* Try lowercase */
                swprintf(depend_key, 32, L"depend%u", order);
                dep_it = vals.find(depend_key);
            }
            if (dep_it != vals.end() && dep_it->second.type == REG_BINARY) {
                auto& dep_data = dep_it->second.data;
                /* DependXX is a binary blob of WORDs (16-bit order numbers) */
                for (size_t i = 0; i + 1 < dep_data.size(); i += 2) {
                    uint16_t dep_order = dep_data[i] | (dep_data[i+1] << 8);
                    if (dep_order != 0)
                        entry.depends.push_back(dep_order);
                }
            }

            entries.push_back(std::move(entry));
        }
    }

    /* Sort by order number */
    std::sort(entries.begin(), entries.end(),
        [](const InitEntry& a, const InitEntry& b) { return a.order < b.order; });

    LOG(API, "[INIT] Found %zu boot entries\n", entries.size());

    /* Launch each entry */
    for (auto& entry : entries) {
        /* Extract filename for blacklist check */
        std::wstring filename = entry.exe_path;
        auto slash = filename.rfind(L'\\');
        if (slash != std::wstring::npos) filename = filename.substr(slash + 1);
        std::string narrow_fn;
        for (auto c : filename) narrow_fn += (char)c;
        for (auto& c : narrow_fn) if (c >= 'A' && c <= 'Z') c += 32;

        if (init_blacklist.count(narrow_fn)) {
            LOG(API, "[INIT] Skipping Launch%u: '%ls' (blacklisted)\n",
                entry.order, entry.exe_path.c_str());
            /* Signal this entry's event so dependent entries don't block.
               On real WinCE, device.exe/gwes.exe would signal after init.
               Since we provide those services via thunks, signal immediately.
               Keep handle alive until init sequence completes. */
            wchar_t event_name[64];
            swprintf(event_name, 64, L"CerfInitDone_%u", entry.order);
            HANDLE h = CreateEventW(NULL, TRUE, TRUE, event_name);
            if (h) blacklist_events.push_back(h);
            continue;
        }

        /* Wait for dependencies (SignalStarted events) */
        for (auto dep : entry.depends) {
            wchar_t event_name[64];
            swprintf(event_name, 64, L"CerfInitDone_%u", dep);
            HANDLE h = OpenEventW(SYNCHRONIZE, FALSE, event_name);
            if (h) {
                LOG(API, "[INIT] Launch%u: waiting for dependency %u...\n",
                    entry.order, dep);
                WaitForSingleObject(h, 10000);
                CloseHandle(h);
            } else {
                /* Create the event so we can wait on it */
                h = CreateEventW(NULL, TRUE, FALSE, event_name);
                if (h) {
                    LOG(API, "[INIT] Launch%u: waiting for dependency %u...\n",
                        entry.order, dep);
                    WaitForSingleObject(h, 10000);
                    CloseHandle(h);
                }
            }
        }

        /* Resolve WinCE path to host path.
           Registry values are often bare filenames (e.g. "explorer.exe").
           Real WinCE CreateProcess searches \Windows\ for bare names. */
        std::wstring host_path;
        bool has_separator = (entry.exe_path.find(L'\\') != std::wstring::npos ||
                              entry.exe_path.find(L'/') != std::wstring::npos);
        if (!has_separator) {
            /* Bare filename — search \Windows\ first (WinCE system dir) */
            std::wstring in_windows = MapWinCEPath(L"\\Windows\\" + entry.exe_path);
            DWORD attrs = GetFileAttributesW(in_windows.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES) {
                host_path = in_windows;
            } else {
                /* Fall back to VFS root */
                host_path = MapWinCEPath(entry.exe_path);
            }
        } else {
            host_path = MapWinCEPath(entry.exe_path);
        }
        LOG(API, "[INIT] Launch%u: '%ls' -> '%ls'\n",
            entry.order, entry.exe_path.c_str(), host_path.c_str());
        if (boot_screen) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Init %s", narrow_fn.c_str());
            boot_screen->Step(buf);
        }

        /* Verify file exists */
        DWORD attrs = GetFileAttributesW(host_path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            LOG(API, "[INIT] Launch%u: file not found: '%ls'\n",
                entry.order, host_path.c_str());
            continue;
        }

        /* Launch via LaunchArmChildProcess */
        LaunchArmChildProcess(host_path, L"", 0, nullptr, mem);

        /* Brief delay to let the process initialize before launching the next */
        Sleep(100);
    }

    LOG(API, "[INIT] Boot sequence complete (%zu entries processed)\n",
        entries.size());

    /* Clean up blacklist event handles */
    for (HANDLE h : blacklist_events) CloseHandle(h);
}

/* Resolve an exe path from CLI input to a host filesystem path.
   Handles: absolute host paths, relative paths, WinCE paths, bare filenames. */
std::wstring Win32Thunks::ResolveExePath(const std::string& input) {
    std::wstring wide(input.begin(), input.end());

    /* Try the narrow path with fopen first — this works with MSYS2/bash
       relative paths that the wide Windows API might not resolve correctly. */
    {
        FILE* f = fopen(input.c_str(), "rb");
        if (f) {
            fclose(f);
            /* Resolve to absolute path for reliable use in child threads */
            char abs_buf[MAX_PATH] = {};
            if (GetFullPathNameA(input.c_str(), MAX_PATH, abs_buf, NULL) && abs_buf[0]) {
                LOG(API, "[INIT] ResolveExePath: '%s' -> '%s' (host path)\n",
                    input.c_str(), abs_buf);
                return std::wstring(abs_buf, abs_buf + strlen(abs_buf));
            }
            return wide;
        }
    }

    /* WinCE-style path (\Windows\foo.exe) */
    if (!wide.empty() && (wide[0] == L'\\' || wide[0] == L'/')) {
        std::wstring mapped = MapWinCEPath(wide);
        DWORD attrs = GetFileAttributesW(mapped.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) return mapped;
    }

    /* Bare filename — search \Windows\ directory */
    std::wstring in_windows = MapWinCEPath(L"\\Windows\\" + wide);
    DWORD attrs = GetFileAttributesW(in_windows.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) return in_windows;

    /* Try with .exe extension */
    if (wide.find(L'.') == std::wstring::npos) {
        std::wstring with_ext = MapWinCEPath(L"\\Windows\\" + wide + L".exe");
        attrs = GetFileAttributesW(with_ext.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) return with_ext;
    }

    /* Give up — return as-is and let caller handle the error */
    LOG(API, "[INIT] ResolveExePath: '%s' not found anywhere\n", input.c_str());
    return wide;
}
