#include "apiset.h"
#include "../cpu/mem.h"
#include "../log.h"

uint32_t ApiSetManager::Create(const char name[4], uint16_t num_methods,
                                uint32_t vtable_addr, uint32_t sigtable_addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t handle = next_handle_++;
    ApiSetEntry entry;
    entry.name = std::string(name, 4);
    entry.set_id = 0; /* not yet registered */
    entry.vtable_addr = vtable_addr;
    entry.sigtable_addr = sigtable_addr;
    entry.num_methods = num_methods;
    sets_by_handle_[handle] = std::move(entry);
    LOG(API, "[API] CreateAPISet('%.*s', %d methods, vtable=0x%08X) -> handle=0x%08X\n",
        4, name, num_methods, vtable_addr, handle);
    return handle;
}

bool ApiSetManager::Register(uint32_t handle, uint32_t set_id,
                              std::function<uint32_t(uint32_t, uint32_t*, int)> executor) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sets_by_handle_.find(handle);
    if (it == sets_by_handle_.end()) {
        LOG(API, "[API] RegisterAPISet(0x%08X, %u) -> FAIL (invalid handle)\n", handle, set_id);
        return false;
    }
    it->second.set_id = set_id;
    it->second.executor = std::move(executor);
    sets_by_id_[set_id] = handle;
    LOG(API, "[API] RegisterAPISet('%.*s', set_id=%u) -> OK\n",
        4, it->second.name.c_str(), set_id);
    return true;
}

void ApiSetManager::Close(uint32_t handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sets_by_handle_.find(handle);
    if (it != sets_by_handle_.end()) {
        sets_by_id_.erase(it->second.set_id);
        LOG(API, "[API] CloseHandle(APISet '%.*s', set_id=%u)\n",
            4, it->second.name.c_str(), it->second.set_id);
        sets_by_handle_.erase(it);
    }
}

bool ApiSetManager::IsRegistered(uint32_t set_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sets_by_id_.count(set_id) > 0;
}

bool ApiSetManager::Dispatch(uint32_t set_id, uint32_t method,
                              uint32_t* regs, EmulatedMemory& mem) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto id_it = sets_by_id_.find(set_id);
    if (id_it == sets_by_id_.end()) return false;

    auto& entry = sets_by_handle_[id_it->second];
    if (method >= entry.num_methods) {
        LOG(API, "[API] APISet '%.*s' method %u out of range (%u methods)\n",
            4, entry.name.c_str(), method, entry.num_methods);
        return false;
    }
    if (!entry.executor) {
        LOG(API, "[API] APISet '%.*s' method %u: no executor registered\n",
            4, entry.name.c_str(), method);
        return false;
    }

    /* Read the function pointer from the vtable in emulated memory */
    uint32_t func_addr = mem.Read32(entry.vtable_addr + method * 4);
    if (!func_addr) {
        LOG(API, "[API] APISet '%.*s' method %u: vtable[%u] = NULL\n",
            4, entry.name.c_str(), method, method);
        regs[0] = 0;
        return true;
    }

    LOG(API, "[API] APISet '%.*s' dispatch: method=%u func=0x%08X\n",
        4, entry.name.c_str(), method, func_addr);

    /* Call the function using the registered process's executor.
       Args are in R0-R3 (ARM calling convention). */
    uint32_t args[4] = { regs[0], regs[1], regs[2], regs[3] };
    /* Temporarily clear ProcessSlot so the call runs in the registering
       process's context (no overlay = main process). */
    ProcessSlot* saved_slot = EmulatedMemory::process_slot;
    EmulatedMemory::process_slot = nullptr;

    uint32_t result = entry.executor(func_addr, args, 4);

    EmulatedMemory::process_slot = saved_slot;
    regs[0] = result;
    return true;
}
