#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"
#include <fstream>
#include <cstdio>
#include <cstring>
#include <filesystem>

/* String conversion helpers (also in registry_import.cpp — static, trivial) */

static std::wstring NarrowToWide(const std::string& s) {
    std::wstring w;
    for (char c : s) w += (wchar_t)(unsigned char)c;
    return w;
}

/* Windows registry keys are case-insensitive — normalize to lowercase */
static std::wstring ToLowerW(const std::wstring& s) {
    std::wstring r = s;
    for (auto& c : r) if (c >= L'A' && c <= L'Z') c += 32;
    return r;
}

static std::string WideToNarrow(const std::wstring& w) {
    std::string s;
    for (wchar_t c : w) s += (c < 128) ? (char)c : '?';
    return s;
}

void Win32Thunks::LoadRegistry() {
    std::lock_guard<std::recursive_mutex> lock(registry_mutex);
    if (registry_loaded) return;
    registry_loaded = true;

    /* Store registry in the device directory as standard .reg format */
    registry_path = device_dir + "registry.reg";
    LOG(REG, "[REG] Loading registry from %s\n", registry_path.c_str());

    {
        std::ifstream f(registry_path);
        if (f.is_open()) {
            f.close();
            ImportRegFile(registry_path);
            LOG(REG, "[REG] Loaded %zu keys\n", registry.size());
        } else {
            LOG(REG, "[REG] No registry file, importing from import_registry/\n");
            /* Import all .reg files from the import_registry subdirectory.
               Files are processed in sorted order for deterministic results. */
            std::string import_dir = device_dir + "import_registry";
            namespace fs = std::filesystem;
            if (fs::is_directory(import_dir)) {
                std::vector<std::string> reg_files;
                std::string custom_reg;
                for (auto& entry : fs::directory_iterator(import_dir)) {
                    if (entry.is_regular_file() &&
                        entry.path().extension() == ".reg") {
                        if (entry.path().filename() == "custom.reg")
                            custom_reg = entry.path().string();
                        else
                            reg_files.push_back(entry.path().string());
                    }
                }
                std::sort(reg_files.begin(), reg_files.end());
                for (auto& reg_path : reg_files)
                    ImportRegFile(reg_path);
                /* custom.reg imports last to override all other values */
                if (!custom_reg.empty())
                    ImportRegFile(custom_reg);
            }
            SaveRegistry(); /* persist imported data */
        }
    }

    /* All essential CLSIDs and MIME types are now provided by the .reg
       files in import_registry/ (shell.reg, ie.reg, etc.). */
}

/* Map internal abbreviated root to standard REGEDIT4 root name */
static std::string MapRootToRegFormat(const std::string& path) {
    /* Lowercase the prefix for case-insensitive matching */
    std::string lp = path;
    for (size_t i = 0; i < lp.size() && i < 5; i++)
        lp[i] = (char)tolower((unsigned char)lp[i]);
    if (lp.substr(0, 5) == "hkcr\\") return "HKEY_CLASSES_ROOT\\" + path.substr(5);
    if (lp == "hkcr") return "HKEY_CLASSES_ROOT";
    if (lp.substr(0, 5) == "hkcu\\") return "HKEY_CURRENT_USER\\" + path.substr(5);
    if (lp == "hkcu") return "HKEY_CURRENT_USER";
    if (lp.substr(0, 5) == "hklm\\") return "HKEY_LOCAL_MACHINE\\" + path.substr(5);
    if (lp == "hklm") return "HKEY_LOCAL_MACHINE";
    if (lp.substr(0, 4) == "hku\\") return "HKEY_USERS\\" + path.substr(4);
    if (lp == "hku") return "HKEY_USERS";
    return path;
}

/* Escape backslashes in string for .reg format */
static std::string EscapeRegString(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else out += c;
    }
    return out;
}

void Win32Thunks::SaveRegistry() {
    std::lock_guard<std::recursive_mutex> lock(registry_mutex);
    if (registry_path.empty()) return;

    std::ofstream f(registry_path);
    if (!f.is_open()) {
        LOG(REG, "[REG] Failed to save registry to %s\n", registry_path.c_str());
        return;
    }

    f << "REGEDIT4\n\n";
    for (auto& [path, key] : registry) {
        f << "[" << MapRootToRegFormat(WideToNarrow(path)) << "]\n";
        for (auto& [name, val] : key.values) {
            /* Default value uses @= syntax */
            if (name.empty())
                f << "@=";
            else
                f << "\"" << WideToNarrow(name) << "\"=";

            if (val.type == REG_DWORD && val.data.size() >= 4) {
                uint32_t dw;
                memcpy(&dw, val.data.data(), 4);
                char buf[16];
                sprintf(buf, "dword:%08x", dw);
                f << buf << "\n";
            } else if (val.type == REG_SZ || val.type == REG_EXPAND_SZ) {
                std::wstring ws((const wchar_t*)val.data.data(),
                                val.data.size() / 2);
                if (!ws.empty() && ws.back() == L'\0') ws.pop_back();
                f << "\"" << EscapeRegString(WideToNarrow(ws)) << "\"\n";
            } else {
                f << "hex:";
                for (size_t i = 0; i < val.data.size(); i++) {
                    char buf[4];
                    sprintf(buf, "%s%02x", i > 0 ? "," : "", val.data[i]);
                    f << buf;
                }
                f << "\n";
            }
        }
        f << "\n";
    }
    LOG(REG, "[REG] Saved %zu keys to %s\n", registry.size(), registry_path.c_str());
}

std::wstring Win32Thunks::ResolveHKey(uint32_t hkey, const std::wstring& subkey) {
    std::wstring root;

    /* Predefined HKEY constants (WinCE uses the same 32-bit values) */
    if (hkey == (uint32_t)(uintptr_t)HKEY_CLASSES_ROOT)  root = L"HKCR";
    else if (hkey == (uint32_t)(uintptr_t)HKEY_CURRENT_USER)  root = L"HKCU";
    else if (hkey == (uint32_t)(uintptr_t)HKEY_LOCAL_MACHINE) root = L"HKLM";
    else if (hkey == (uint32_t)(uintptr_t)HKEY_USERS)         root = L"HKU";
    else {
        /* Look up fake HKEY */
        auto it = hkey_map.find(hkey);
        if (it != hkey_map.end()) root = it->second;
        else root = L"HKCU"; /* fallback */
    }

    if (subkey.empty()) return root;

    /* Strip leading backslash from subkey */
    std::wstring sk = subkey;
    while (!sk.empty() && (sk[0] == L'\\' || sk[0] == L'/')) sk.erase(sk.begin());
    if (sk.empty()) return root;

    /* Normalize separators */
    std::wstring full = root + L"\\" + sk;
    /* Remove trailing backslash */
    while (!full.empty() && full.back() == L'\\') full.pop_back();
    return full;
}

void Win32Thunks::EnsureParentKeys(const std::wstring& path) {
    /* Make sure all parent keys exist and have subkey references */
    size_t pos = 0;
    while ((pos = path.find(L'\\', pos + 1)) != std::wstring::npos) {
        std::wstring parent = path.substr(0, pos);
        std::wstring child_name = path.substr(pos + 1);
        size_t next = child_name.find(L'\\');
        if (next != std::wstring::npos) child_name = child_name.substr(0, next);
        registry[parent].subkeys.insert(child_name);
    }
}

bool Win32Thunks::RegGetValue(const std::wstring& key, const std::wstring& name, RegValue& out) {
    LoadRegistry();
    std::lock_guard<std::recursive_mutex> lock(registry_mutex);
    auto kit = registry.find(key);
    if (kit == registry.end()) return false;
    auto vit = kit->second.values.find(name);
    if (vit == kit->second.values.end()) return false;
    out = vit->second;
    return true;
}

void Win32Thunks::RegSetValue(const std::wstring& key, const std::wstring& name, const RegValue& val) {
    LoadRegistry();
    std::lock_guard<std::recursive_mutex> lock(registry_mutex);
    registry[key].values[name] = val;
    EnsureParentKeys(key);
    SaveRegistry();
}

bool Win32Thunks::ResolveMuiString(const std::wstring& mui_ref, std::wstring& resolved) {
    /* Parse MUI reference: "[\path\]dllname.dll,#resid" or "dllname,#resid" */
    size_t comma = mui_ref.rfind(L',');
    if (comma == std::wstring::npos || comma + 2 >= mui_ref.size()) return false;
    if (mui_ref[comma + 1] != L'#') return false;
    std::wstring dll_path = mui_ref.substr(0, comma);
    int res_id = _wtoi(mui_ref.substr(comma + 2).c_str());
    if (res_id <= 0) return false;

    /* Extract just the DLL filename (case-insensitive match against loaded_dlls) */
    size_t last_sep = dll_path.find_last_of(L"\\/");
    std::wstring dll_name = (last_sep != std::wstring::npos) ? dll_path.substr(last_sep + 1) : dll_path;

    /* Find the loaded ARM DLL */
    uint32_t base = 0, rsrc_rva = 0, rsrc_size = 0;
    for (auto& [name, info] : loaded_dlls) {
        if (_wcsicmp(name.c_str(), dll_name.c_str()) == 0) {
            base = info.base_addr;
            rsrc_rva = info.pe_info.rsrc_rva;
            rsrc_size = info.pe_info.rsrc_size;
            break;
        }
    }
    if (!base || !rsrc_rva) return false;

    /* Load string resource (same logic as LoadStringW thunk) */
    uint32_t bundle_id = (res_id / 16) + 1, string_idx = res_id % 16;
    uint32_t data_rva = 0, data_size = 0;
    if (!FindResourceInPE(base, rsrc_rva, rsrc_size, 6, bundle_id, data_rva, data_size))
        return false;
    uint8_t* data = mem.Translate(base + data_rva);
    if (!data) return false;

    uint16_t* p = (uint16_t*)data;
    for (uint32_t i = 0; i < string_idx && (uint8_t*)p < data + data_size; i++) {
        uint16_t len = *p++; p += len;
    }
    if ((uint8_t*)p >= data + data_size) return false;
    uint16_t len = *p++;
    if (len == 0) return false;

    resolved.assign((const wchar_t*)p, len);
    return true;
}
