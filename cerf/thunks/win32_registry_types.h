#pragma once
/* Emulated registry types and private members — split from win32_thunks.h.
   Included by win32_thunks.h; do not include directly.

   These are members of Win32Thunks declared in the registry section. */

    /* Emulated registry (file-backed, text format) */
    struct RegValue { uint32_t type = 0; std::vector<uint8_t> data; };
    /* Case-insensitive comparator for registry value names (Windows registry is case-insensitive) */
    struct WstrCILess {
        bool operator()(const std::wstring& a, const std::wstring& b) const {
            return _wcsicmp(a.c_str(), b.c_str()) < 0;
        }
    };
    struct RegKey { std::map<std::wstring, RegValue, WstrCILess> values; std::set<std::wstring, WstrCILess> subkeys; };
private:
    std::map<std::wstring, RegKey, WstrCILess> registry;
    std::map<uint32_t, std::wstring> hkey_map;
    uint32_t next_fake_hkey = 0xAE000000;
    bool registry_loaded = false;
    std::string registry_path;
    std::recursive_mutex registry_mutex; /* Protects registry, hkey_map, next_fake_hkey */
    void LoadRegistry();
    void SaveRegistry();
    void ImportRegFile(const std::string& path);
    std::wstring ResolveHKey(uint32_t hkey, const std::wstring& subkey);
    void EnsureParentKeys(const std::wstring& path);
    /* Internal registry helpers — handle locking + LoadRegistry internally */
    bool RegGetValue(const std::wstring& key, const std::wstring& name, RegValue& out);
    void RegSetValue(const std::wstring& key, const std::wstring& name, const RegValue& val);
    bool ResolveMuiString(const std::wstring& mui_ref, std::wstring& resolved);
    void WriteFindDataToEmu(EmulatedMemory& mem, uint32_t addr, const WIN32_FIND_DATAW& fd);
