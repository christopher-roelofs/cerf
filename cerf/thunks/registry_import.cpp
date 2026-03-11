#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"
#include <fstream>
#include <cstring>

/* String conversion helpers (duplicated from registry_impl.cpp — static, trivial) */

static std::wstring NarrowToWide(const std::string& s) {
    std::wstring w;
    for (char c : s) w += (wchar_t)(unsigned char)c;
    return w;
}

static std::wstring ToLowerW(const std::wstring& s) {
    std::wstring r = s;
    for (auto& c : r) if (c >= L'A' && c <= L'Z') c += 32;
    return r;
}

/* Map REGEDIT4 root names to our abbreviated forms */
static std::wstring MapRegRoot(const std::wstring& key) {
    if (key.substr(0, 18) == L"HKEY_CLASSES_ROOT\\") return L"HKCR\\" + key.substr(18);
    if (key == L"HKEY_CLASSES_ROOT") return L"HKCR";
    if (key.substr(0, 18) == L"HKEY_CURRENT_USER\\") return L"HKCU\\" + key.substr(18);
    if (key == L"HKEY_CURRENT_USER") return L"HKCU";
    if (key.substr(0, 19) == L"HKEY_LOCAL_MACHINE\\") return L"HKLM\\" + key.substr(19);
    if (key == L"HKEY_LOCAL_MACHINE") return L"HKLM";
    if (key.substr(0, 11) == L"HKEY_USERS\\") return L"HKU\\" + key.substr(11);
    if (key == L"HKEY_USERS") return L"HKU";
    return key;
}

/* WinCE build system LOC_* macro definitions (US English / LCID 0x0409).
   These are resolved at import time for .reg files from the platform SDK. */
struct LocMacro { const char* name; const char* str_val; uint32_t dw_val; };
static const LocMacro loc_macros[] = {
    {"LOC_LCID",              nullptr, 0x0409},
    {"LOC_ACP",               nullptr, 0x04e4},
    {"LOC_CONSOLEFONTNAME",   "Tahoma", 0},
    {"LOC_CONSOLEFONTSIZE",   nullptr, 9},
    {"LOC_CONSOLEPAINTFIX",   nullptr, 0},
    {"LOC_MENUBARFONTWEIGHT", nullptr, 700},
    {"LOC_BUTTONFONTWEIGHT",  nullptr, 700},
    {"LOC_HKL_DEFAULT",       "00000409", 0},
    {"LOC_KEYBOARD",          "Standard Keyboard", 0},
    {"LOC_DEFAULT_TIMEZONE",  "Eastern Standard Time", 0},
    {"LOC_PATH_APPDATA",      "\\Application Data", 0},
    {"LOC_PATH_DESKTOP",      "\\Windows\\Desktop", 0},
    {"LOC_PATH_FAVORITES",    "\\Windows\\Favorites", 0},
    {"LOC_PATH_FONTS",        "\\Windows\\Fonts", 0},
    {"LOC_PATH_MYDOCUMENTS",  "\\My Documents", 0},
    {"LOC_PATH_PROGRAMFILES", "\\Program Files", 0},
    {"LOC_PATH_PROGRAMS",     "\\Windows\\Programs", 0},
    {"LOC_PATH_RECENT",       "\\Windows\\Recent", 0},
    {"LOC_PATH_STARTUP",      "\\Windows\\StartUp", 0},
    {"LOC_PATH_WINDOWS",      "\\Windows", 0},
    {"LOC_STORE_DEFAULT_FOLDER", "Storage Card", 0},
    {"LOC_STORE_PCMCIA_FOLDER",  "Storage Card", 0},
    {"LOC_STORE_HD_FOLDER",      "Hard Disk", 0},
    {"LOC_STORE_CD_FOLDER",      "CD-ROM", 0},
    {"LOC_STORE_FLOPPY_FOLDER",  "Floppy Disk", 0},
    {"LOC_HOMEAREACODE",      "425", 0},
    {"LOC_HOMECOUNTRYCODE",   "1", 0},
    {"LOC_HOMECWCODE",        "1", 0},
    {"LOC_HOMELOCATIONNAME",  "Home", 0},
    {"LOC_HOMELOCALFMT",      "0,,", 0},
    {"LOC_HOMELDFMT",         "0,,", 0},
    {"LOC_HOMEINTNTLFMT",     "011,", 0},
    {"LOC_HOMEOPTIONS",       "0", 0},
    {"LOC_WORKAREACODE",      "425", 0},
    {"LOC_WORKCOUNTRYCODE",   "1", 0},
    {"LOC_WORKCWCODE",        "1", 0},
    {"LOC_WORKLOCATIONNAME",  "Work", 0},
    {"LOC_WORKLOCALFMT",      "0,,", 0},
    {"LOC_WORKLDFMT",         "0,,", 0},
    {"LOC_WORKINTNTLFMT",     "011,", 0},
    {"LOC_WORKOPTIONS",       "0", 0},
    {"LOC_STARTPAGE",         "http://www.msn.com", 0},
    {"LOC_SEARCHPAGE",        "http://www.msn.com", 0},
};

/* Resolve LOC_* macros in a value string.
   dword:LOC_XXX → dword:XXXX, bare LOC_XXX → "resolved_string" */
static std::string ResolveLocMacros(const std::string& val_str) {
    for (auto& m : loc_macros) {
        size_t pos = val_str.find(m.name);
        if (pos == std::string::npos) continue;
        if (val_str.substr(0, 6) == "dword:" && pos == 6) {
            /* dword:LOC_XXX → dword:XXXXXXXX */
            char buf[20];
            sprintf(buf, "dword:%08x", m.dw_val);
            return buf;
        }
        if (pos == 0 && val_str.size() == strlen(m.name) && m.str_val) {
            /* Bare LOC_XXX → "string_value" */
            return std::string("\"") + m.str_val + "\"";
        }
    }
    return val_str;
}

/* Parse a value from a .reg file value string (after the '=').
   Handles: "string", dword:XXXX, hex:XX,XX,... */
static bool ParseRegFileValue(const std::string& rest, Win32Thunks::RegValue& val) {
    if (rest.empty()) return false;
    if (rest[0] == '"') {
        /* String value: "content" */
        size_t end = rest.find('"', 1);
        if (end == std::string::npos) return false;
        val.type = REG_SZ;
        std::string raw = rest.substr(1, end - 1);
        /* Unescape \\  -> \ */
        std::wstring ws;
        for (size_t i = 0; i < raw.size(); i++) {
            if (raw[i] == '\\' && i + 1 < raw.size() && raw[i+1] == '\\') { ws += L'\\'; i++; }
            else ws += (wchar_t)(unsigned char)raw[i];
        }
        val.data.resize((ws.size() + 1) * 2);
        memcpy(val.data.data(), ws.c_str(), val.data.size());
        return true;
    } else if (rest.substr(0, 6) == "dword:") {
        val.type = REG_DWORD;
        uint32_t dw = (uint32_t)strtoul(rest.substr(6).c_str(), nullptr, 16);
        val.data.resize(4);
        memcpy(val.data.data(), &dw, 4);
        return true;
    } else if (rest.size() > 8 && rest.substr(0, 7) == "mui_sz:") {
        /* WinCE MUI string: mui_sz:"dll,#resid" — store as REG_SZ for ARM code to resolve */
        size_t q1 = rest.find('"', 7);
        size_t q2 = (q1 != std::string::npos) ? rest.find('"', q1 + 1) : std::string::npos;
        if (q1 == std::string::npos || q2 == std::string::npos) return false;
        val.type = REG_SZ;
        std::string raw = rest.substr(q1 + 1, q2 - q1 - 1);
        std::wstring ws;
        for (size_t i = 0; i < raw.size(); i++) {
            if (raw[i] == '\\' && i + 1 < raw.size() && raw[i+1] == '\\') { ws += L'\\'; i++; }
            else ws += (wchar_t)(unsigned char)raw[i];
        }
        val.data.resize((ws.size() + 1) * 2);
        memcpy(val.data.data(), ws.c_str(), val.data.size());
        return true;
    } else if (rest.substr(0, 4) == "hex:") {
        val.type = REG_BINARY;
        std::string hex = rest.substr(4);
        for (size_t i = 0; i < hex.size(); ) {
            while (i < hex.size() && (hex[i] == ',' || hex[i] == ' ' || hex[i] == '\\' || hex[i] == '\r' || hex[i] == '\n')) i++;
            if (i + 1 < hex.size() && isxdigit(hex[i]) && isxdigit(hex[i+1])) {
                val.data.push_back((uint8_t)strtoul(hex.substr(i, 2).c_str(), nullptr, 16));
                i += 2;
            } else break;
        }
        return true;
    }
    return false;
}

void Win32Thunks::ImportRegFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return;
    std::wstring current_key;
    std::string line;
    size_t key_count = 0;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        /* Strip leading whitespace/tabs (ie.reg uses tab indentation) */
        size_t first_ch = line.find_first_not_of(" \t");
        if (first_ch != std::string::npos && first_ch > 0)
            line = line.substr(first_ch);
        if (line.empty() || line[0] == ';') continue;
        if (line == "REGEDIT4" || line == "Windows Registry Editor Version 5.00") continue;

        /* Key: [HKEY_...] */
        if (line[0] == '[' && line.back() == ']') {
            current_key = MapRegRoot(NarrowToWide(line.substr(1, line.size() - 2)));
            registry[current_key];
            EnsureParentKeys(current_key);
            key_count++;
            continue;
        }
        if (current_key.empty()) continue;

        /* Default value: @="..." or @=dword:... */
        std::wstring val_name;
        std::string val_str;
        if (line.size() >= 2 && line[0] == '@' && line[1] == '=') {
            val_name = L"";
            val_str = line.substr(2);
        } else if (line[0] == '"') {
            size_t eq = line.find("\"=");
            if (eq == std::string::npos || eq < 1) continue;
            val_name = NarrowToWide(line.substr(1, eq - 1));
            val_str = line.substr(eq + 2);
        } else continue;

        /* Handle line continuations: .reg hex values end lines with '\' to
           continue on the next line.  Concatenate all continuation lines. */
        while (!val_str.empty() && val_str.back() == '\\') {
            std::string next;
            if (!std::getline(f, next)) break;
            if (!next.empty() && next.back() == '\r') next.pop_back();
            /* Strip leading whitespace from continuation line */
            size_t start = next.find_first_not_of(" \t");
            if (start != std::string::npos)
                val_str += next.substr(start);
        }

        /* Resolve WinCE build system LOC_* macros */
        val_str = ResolveLocMacros(val_str);

        RegValue val = {};
        if (ParseRegFileValue(val_str, val))
            registry[current_key].values[val_name] = val;
    }
    LOG(REG, "[REG] Imported %zu keys from %s\n", key_count, path.c_str());
}
