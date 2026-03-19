/* LPC Port Manager implementation — emulates lpcd.dll's lpcapi_* functions.
   See lpc_manager.h for architecture overview. */

#include "lpc_manager.h"
#include "../cpu/mem.h"
#include "../log.h"

/* NTSTATUS codes from lpc.h (use NTSTATUS_ prefix to avoid conflicts) */
constexpr int32_t NTSTATUS_SUCCESS                = 0;
constexpr int32_t NTSTATUS_INVALID_PARAMETER      = static_cast<int32_t>(0xC000000Du);
constexpr int32_t NTSTATUS_NO_MEMORY              = static_cast<int32_t>(0xC0000017u);
constexpr int32_t NTSTATUS_OBJECT_NAME_NOT_FOUND  = static_cast<int32_t>(0xC0000034u);
constexpr int32_t NTSTATUS_OBJECT_NAME_COLLISION  = static_cast<int32_t>(0xC0000035u);
constexpr int32_t NTSTATUS_PORT_DISCONNECTED      = static_cast<int32_t>(0xC0000037u);
constexpr int32_t NTSTATUS_INVALID_PORT_HANDLE    = static_cast<int32_t>(0xC0000042u);
constexpr int32_t NTSTATUS_INSUFFICIENT_RESOURCES = static_cast<int32_t>(0xC000009Au);
constexpr int32_t NTSTATUS_PORT_MESSAGE_TOO_LONG  = static_cast<int32_t>(0xC000002Fu);
constexpr int32_t NTSTATUS_REPLY_MESSAGE_MISMATCH = static_cast<int32_t>(0xC000021Fu);

LpcPortManager::LpcPortManager() {
    /* Pre-create the RPC endpoint mapper port (\RPC Control\epmapper).
       On real WinCE, rpcss.exe creates this at boot and handles endpoint
       resolution requests. We create it so NtConnectPort succeeds.
       The actual endpoint resolution is handled inline — when a client
       sends a request to the epmapper, we respond with the endpoint info
       for any registered local COM servers. */
    auto* epmapper = new LpcPort();
    epmapper->name = L"\\RPC Control\\epmapper";
    epmapper->handle = AllocHandle();
    epmapper->is_connection_port = true;
    epmapper->max_message_length = PORT_MAX_MESSAGE;
    epmapper->queue_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    ports_[epmapper->handle] = epmapper;
    named_[epmapper->name] = epmapper;
    LOG(API, "[LPC] Pre-created epmapper port handle=0x%08X\n", epmapper->handle);
}

LpcPortManager::~LpcPortManager() {
    for (auto& [h, p] : ports_) {
        if (p->queue_event) CloseHandle(p->queue_event);
        for (auto* m : p->message_queue) {
            if (m->hEvent) CloseHandle(m->hEvent);
            delete m;
        }
        delete p;
    }
}

uint32_t LpcPortManager::AllocHandle() { return next_handle_++; }

LpcPortManager::LpcPort* LpcPortManager::FindPort(uint32_t handle) {
    auto it = ports_.find(handle);
    return it != ports_.end() ? it->second : nullptr;
}

LpcPortManager::LpcMessage* LpcPortManager::FindMessageById(LpcPort* port, uint32_t msg_id) {
    for (auto* m : port->message_queue) {
        ArmPortMessage* hdr = (ArmPortMessage*)m->data.data();
        if (hdr->MessageId == msg_id) return m;
    }
    return nullptr;
}

void LpcPortManager::RemoveMessage(LpcPort* port, LpcMessage* msg) {
    auto& q = port->message_queue;
    q.erase(std::remove(q.begin(), q.end(), msg), q.end());
}

LpcPortManager::LpcMessage* LpcPortManager::ReadMessage(uint32_t arm_addr, EmulatedMemory& mem) {
    uint16_t total_len = mem.Read16(arm_addr + 2); /* TotalLength */
    if (total_len < sizeof(ArmPortMessage) || total_len > PORT_MAX_MESSAGE) return nullptr;
    auto* msg = new LpcMessage();
    msg->data.resize(total_len);
    for (uint16_t i = 0; i < total_len; i++)
        msg->data[i] = mem.Read8(arm_addr + i);
    return msg;
}

void LpcPortManager::WriteMessage(uint32_t arm_addr, const LpcMessage* msg, EmulatedMemory& mem) {
    for (size_t i = 0; i < msg->data.size(); i++)
        mem.Write8(arm_addr + (uint32_t)i, msg->data[i]);
}

int32_t LpcPortManager::HandleIoctl(uint32_t dwCode, uint32_t pBufIn, uint32_t dwLenIn,
    uint32_t pBufOut, uint32_t dwLenOut, uint32_t pdwActualOut, EmulatedMemory& mem)
{
    LOG(API, "[LPC] DeviceIoControl IOCTL=%u pBufIn=0x%08X dwLenIn=0x%08X "
        "pBufOut=0x%08X\n", dwCode, pBufIn, dwLenIn, pBufOut);

    switch (dwCode) {
    case 1:  return CreatePort(pBufIn, mem);
    case 2:  return ConnectPort(pBufIn, mem);
    case 3:  return AcceptConnectPort(pBufIn, mem);
    case 4:  return CompleteConnectPort(dwLenIn); /* dwLenIn = PortHandle */
    case 5:  return ReplyWaitReceivePort(dwLenIn, pBufIn, pBufOut, pdwActualOut, mem);
    case 6:  return ListenPort(dwLenIn, pBufIn, mem);
    case 7:  return ReplyPort(dwLenIn, pBufIn, mem);
    case 8:  return ReplyPort(dwLenIn, pBufIn, mem); /* ReplyWaitReplyPort ~ ReplyPort */
    case 9:  return RequestWaitReplyPort(dwLenIn, pBufIn, 0, mem); /* fire-and-forget */
    case 10: return RequestWaitReplyPort(dwLenIn, pBufIn, pBufOut, mem);
    case 11: return ClosePort(dwLenIn); /* dwLenIn = PortHandle */
    default:
        LOG(API, "[LPC] Unknown IOCTL %u\n", dwCode);
        return NTSTATUS_INVALID_PARAMETER;
    }
}

/* IOCTL 1: NtCreatePort
   pBufIn → struct { PortHandle*, ObjectAttributes*, MaxConnInfo, MaxMsg, MaxPool } */
int32_t LpcPortManager::CreatePort(uint32_t pBufIn, EmulatedMemory& mem) {
    uint32_t port_handle_ptr = mem.Read32(pBufIn + 0);
    uint32_t obj_attr_ptr    = mem.Read32(pBufIn + 4);
    uint32_t max_msg_len     = mem.Read32(pBufIn + 12);

    if (!port_handle_ptr || !obj_attr_ptr)
        return NTSTATUS_INVALID_PARAMETER;

    /* Read port name from OBJECT_ATTRIBUTES → UNICODE_STRING */
    uint32_t ustr_ptr = mem.Read32(obj_attr_ptr + 8); /* ObjectName */
    if (!ustr_ptr) return NTSTATUS_INVALID_PARAMETER;
    uint16_t name_len = mem.Read16(ustr_ptr + 0); /* Length in bytes */
    uint32_t name_buf = mem.Read32(ustr_ptr + 4); /* Buffer */
    if (!name_buf) return NTSTATUS_INVALID_PARAMETER;

    std::wstring port_name;
    for (uint16_t i = 0; i < name_len / 2; i++)
        port_name += (wchar_t)mem.Read16(name_buf + i * 2);

    std::lock_guard<std::mutex> lock(mutex_);

    /* Check for name collision */
    if (named_.count(port_name)) {
        LOG(API, "[LPC] CreatePort '%ls' -> NAME_COLLISION\n", port_name.c_str());
        return NTSTATUS_OBJECT_NAME_COLLISION;
    }

    auto* port = new LpcPort();
    port->name = port_name;
    port->handle = AllocHandle();
    port->max_message_length = max_msg_len ? max_msg_len : PORT_MAX_MESSAGE;
    port->is_connection_port = true;
    port->queue_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    ports_[port->handle] = port;
    named_[port_name] = port;

    mem.Write32(port_handle_ptr, port->handle);
    LOG(API, "[LPC] CreatePort '%ls' -> handle=0x%08X\n", port_name.c_str(), port->handle);
    return NTSTATUS_SUCCESS;
}

/* IOCTL 2: NtConnectPort
   pBufIn → struct { PortHandle*, PortName*, Qos*, ClientView*, ServerView*,
                      MaxMsgLen*, ConnInfo*, ConnInfoLen* } */
int32_t LpcPortManager::ConnectPort(uint32_t pBufIn, EmulatedMemory& mem) {
    uint32_t port_handle_ptr = mem.Read32(pBufIn + 0);
    uint32_t port_name_ptr   = mem.Read32(pBufIn + 4);

    if (!port_handle_ptr || !port_name_ptr)
        return NTSTATUS_INVALID_PARAMETER;

    /* Read UNICODE_STRING for port name */
    uint16_t name_len = mem.Read16(port_name_ptr + 0);
    uint32_t name_buf = mem.Read32(port_name_ptr + 4);
    if (!name_buf) return NTSTATUS_INVALID_PARAMETER;

    std::wstring port_name;
    for (uint16_t i = 0; i < name_len / 2; i++)
        port_name += (wchar_t)mem.Read16(name_buf + i * 2);

    std::lock_guard<std::mutex> lock(mutex_);

    /* Find the server port */
    auto it = named_.find(port_name);
    if (it == named_.end()) {
        LOG(API, "[LPC] ConnectPort '%ls' -> NOT_FOUND\n", port_name.c_str());
        return NTSTATUS_OBJECT_NAME_NOT_FOUND;
    }
    LpcPort* server = it->second;

    /* Create a communication port (client side) */
    auto* comm = new LpcPort();
    comm->handle = AllocHandle();
    comm->is_connection_port = false;
    comm->master_handle = server->handle;
    comm->max_message_length = server->max_message_length;
    comm->queue_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    ports_[comm->handle] = comm;

    /* Post a connection request to the server's queue */
    auto* conn_msg = new LpcMessage();
    ArmPortMessage hdr = {};
    hdr.DataLength = 0;
    hdr.TotalLength = sizeof(ArmPortMessage);
    hdr.Type = LPC_CONNECTION_REQUEST;
    hdr.MessageId = next_message_id_++;
    hdr.ProcessId = GetCurrentProcessId();
    hdr.ThreadId = GetCurrentThreadId();
    conn_msg->data.assign((uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));
    conn_msg->sender_handle = comm->handle;
    conn_msg->hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    /* For ports with no active server (like the pre-created epmapper),
       accept the connection immediately instead of blocking. On real WinCE,
       a server thread calls NtListenPort + NtAcceptConnectPort + NtCompleteConnectPort.
       We skip that handshake for ports that have no server listening. */
    bool has_server = false; /* TODO: track if a server is listening */
    if (!has_server) {
        /* Auto-accept: link client comm port directly */
        LOG(API, "[LPC] ConnectPort auto-accept (no server listening)\n");
    } else {
        server->message_queue.push_back(conn_msg);
        SetEvent(server->queue_event);
        HANDLE wait_event = conn_msg->hEvent;
        mutex_.unlock();
        WaitForSingleObject(wait_event, 5000);
        mutex_.lock();
    }
    CloseHandle(conn_msg->hEvent);
    delete conn_msg;

    /* Write max message length if requested */
    uint32_t max_msg_ptr = mem.Read32(pBufIn + 20);
    if (max_msg_ptr)
        mem.Write32(max_msg_ptr, server->max_message_length);

    mem.Write32(port_handle_ptr, comm->handle);
    LOG(API, "[LPC] ConnectPort '%ls' -> comm_handle=0x%08X\n",
        port_name.c_str(), comm->handle);
    return NTSTATUS_SUCCESS;
}

/* IOCTL 3: NtAcceptConnectPort */

