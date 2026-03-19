/* LPC Port Manager — IOCTL implementations (AcceptConnect through ClosePort).
   See lpc_manager.h for architecture overview, lpc_manager.cpp for core logic. */

#include "lpc_manager.h"
#include "../cpu/mem.h"
#include "../log.h"

/* NTSTATUS codes (same as lpc_manager.cpp) */
constexpr int32_t NTSTATUS_SUCCESS                = 0;
constexpr int32_t NTSTATUS_INVALID_PARAMETER      = static_cast<int32_t>(0xC000000Du);
constexpr int32_t NTSTATUS_OBJECT_NAME_NOT_FOUND  = static_cast<int32_t>(0xC0000034u);
constexpr int32_t NTSTATUS_PORT_DISCONNECTED      = static_cast<int32_t>(0xC0000037u);
constexpr int32_t NTSTATUS_INVALID_PORT_HANDLE    = static_cast<int32_t>(0xC0000042u);
constexpr int32_t NTSTATUS_PORT_MESSAGE_TOO_LONG  = static_cast<int32_t>(0xC000002Fu);
constexpr int32_t NTSTATUS_REPLY_MESSAGE_MISMATCH = static_cast<int32_t>(0xC000021Fu);

int32_t LpcPortManager::AcceptConnectPort(uint32_t pBufIn, EmulatedMemory& mem) {
    uint32_t port_handle_ptr = mem.Read32(pBufIn + 0);
    uint32_t conn_req_ptr    = mem.Read32(pBufIn + 8);  /* ConnectionRequest */
    uint8_t  accept          = mem.Read8(pBufIn + 12);   /* AcceptConnection */

    std::lock_guard<std::mutex> lock(mutex_);

    /* Create server-side communication port */
    auto* scomm = new LpcPort();
    scomm->handle = AllocHandle();
    scomm->is_connection_port = false;
    scomm->queue_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    /* Find the connection request's sender to link them */
    /* The conn_req MessageId identifies the pending connection */
    if (conn_req_ptr) {
        uint32_t msg_id = mem.Read32(conn_req_ptr + 16); /* MessageId */
        /* Find which server port has this message */
        for (auto& [h, p] : ports_) {
            if (!p->is_connection_port) continue;
            auto* msg = FindMessageById(p, msg_id);
            if (msg) {
                scomm->master_handle = p->handle;
                /* Link the client comm port to this server comm port */
                LpcPort* client_comm = FindPort(msg->sender_handle);
                if (client_comm)
                    client_comm->master_handle = scomm->handle;
                scomm->max_message_length = p->max_message_length;
                break;
            }
        }
    }

    ports_[scomm->handle] = scomm;
    if (port_handle_ptr)
        mem.Write32(port_handle_ptr, scomm->handle);

    LOG(API, "[LPC] AcceptConnectPort -> handle=0x%08X accept=%d\n",
        scomm->handle, accept);
    return NTSTATUS_SUCCESS;
}

/* IOCTL 4: NtCompleteConnectPort */
int32_t LpcPortManager::CompleteConnectPort(uint32_t port_handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    LOG(API, "[LPC] CompleteConnectPort(0x%08X)\n", port_handle);

    /* Signal any pending connection wait */
    for (auto& [h, p] : ports_) {
        if (!p->is_connection_port) continue;
        for (auto* msg : p->message_queue) {
            if (msg->hEvent) {
                SetEvent(msg->hEvent);
                RemoveMessage(p, msg);
                /* Don't delete msg yet — ConnectPort may still reference it */
                return NTSTATUS_SUCCESS;
            }
        }
    }
    return NTSTATUS_SUCCESS;
}

/* IOCTL 5: NtReplyWaitReceivePort */
int32_t LpcPortManager::ReplyWaitReceivePort(uint32_t port_handle, uint32_t pCtx,
    uint32_t pReply, uint32_t pReceive, EmulatedMemory& mem)
{
    LOG(API, "[LPC] ReplyWaitReceivePort(0x%08X)\n", port_handle);

    /* If there's a reply message, send it first */
    if (pReply) {
        ReplyPort(port_handle, pReply, mem);
    }

    /* Wait for a message on this port */
    LpcPort* port = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        port = FindPort(port_handle);
        if (!port) return NTSTATUS_INVALID_PORT_HANDLE;

        /* If server comm port, use master connection port's queue */
        if (!port->is_connection_port && port->master_handle) {
            LpcPort* master = FindPort(port->master_handle);
            if (master) port = master;
        }
    }

    /* Wait for message */
    WaitForSingleObject(port->queue_event, INFINITE);

    std::lock_guard<std::mutex> lock(mutex_);
    if (!port->message_queue.empty()) {
        LpcMessage* msg = port->message_queue.front();
        if (pReceive)
            WriteMessage(pReceive, msg, mem);
        /* Don't remove yet — RequestWaitReplyPort needs to find it for reply */
    }
    return NTSTATUS_SUCCESS;
}

/* IOCTL 6: NtListenPort — waits for connection request */
int32_t LpcPortManager::ListenPort(uint32_t port_handle, uint32_t pConnReq,
    EmulatedMemory& mem)
{
    LOG(API, "[LPC] ListenPort(0x%08X)\n", port_handle);

    LpcPort* port = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        port = FindPort(port_handle);
        if (!port) return NTSTATUS_INVALID_PORT_HANDLE;
    }

    /* Wait for a connection request */
    WaitForSingleObject(port->queue_event, INFINITE);

    std::lock_guard<std::mutex> lock(mutex_);
    if (!port->message_queue.empty() && pConnReq) {
        WriteMessage(pConnReq, port->message_queue.front(), mem);
    }
    return NTSTATUS_SUCCESS;
}

/* IOCTL 7: NtReplyPort */
int32_t LpcPortManager::ReplyPort(uint32_t port_handle, uint32_t pReply,
    EmulatedMemory& mem)
{
    if (!pReply) return NTSTATUS_INVALID_PARAMETER;

    std::lock_guard<std::mutex> lock(mutex_);
    LpcPort* port = FindPort(port_handle);
    if (!port) return NTSTATUS_INVALID_PORT_HANDLE;

    uint32_t msg_id = mem.Read32(pReply + 16); /* MessageId */
    LOG(API, "[LPC] ReplyPort(0x%08X, msgId=%u)\n", port_handle, msg_id);

    /* Find the original request's LpcMessage by MessageId in the master port */
    LpcPort* master = port->is_connection_port ? port : FindPort(port->master_handle);
    if (!master) return NTSTATUS_PORT_DISCONNECTED;

    LpcMessage* orig = FindMessageById(master, msg_id);
    if (!orig) return NTSTATUS_REPLY_MESSAGE_MISMATCH;

    /* Copy the reply into the message */
    uint16_t total_len = mem.Read16(pReply + 2);
    if (total_len > PORT_MAX_MESSAGE) total_len = PORT_MAX_MESSAGE;
    orig->data.resize(total_len);
    for (uint16_t i = 0; i < total_len; i++)
        orig->data[i] = mem.Read8(pReply + i);

    /* Set type to LPC_REPLY */
    ArmPortMessage* hdr = (ArmPortMessage*)orig->data.data();
    hdr->Type = LPC_REPLY;

    /* Signal the waiting client */
    if (orig->hEvent)
        SetEvent(orig->hEvent);

    return NTSTATUS_SUCCESS;
}

/* IOCTL 10: NtRequestWaitReplyPort */
int32_t LpcPortManager::RequestWaitReplyPort(uint32_t port_handle,
    uint32_t pRequest, uint32_t pReply, EmulatedMemory& mem)
{
    if (!pRequest) return NTSTATUS_INVALID_PARAMETER;

    LpcMessage* msg = ReadMessage(pRequest, mem);
    if (!msg) return NTSTATUS_PORT_MESSAGE_TOO_LONG;

    /* Fill in header fields */
    ArmPortMessage* hdr = (ArmPortMessage*)msg->data.data();
    hdr->Type = LPC_REQUEST;
    hdr->MessageId = next_message_id_++;
    hdr->ProcessId = GetCurrentProcessId();
    hdr->ThreadId = GetCurrentThreadId();
    hdr->ClientViewSize = 0;

    msg->hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    LpcPort* master_port = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        LpcPort* comm = FindPort(port_handle);
        if (!comm) { delete msg; return NTSTATUS_INVALID_PORT_HANDLE; }

        /* Find the server's connection port */
        LpcPort* server_comm = FindPort(comm->master_handle);
        if (!server_comm) { delete msg; return NTSTATUS_PORT_DISCONNECTED; }
        master_port = server_comm->is_connection_port
            ? server_comm : FindPort(server_comm->master_handle);
        if (!master_port) { delete msg; return NTSTATUS_PORT_DISCONNECTED; }

        msg->sender_handle = port_handle;

        /* Auto-reply for epmapper: the endpoint mapper port has no server
           thread listening. Generate an immediate RPC_S_SERVER_UNAVAILABLE
           reply so the client gets a clean error instead of blocking forever.
           On real WinCE, rpcss.exe would process the request and respond with
           endpoint resolution data. Since we don't have rpcss, the RPC call
           fails gracefully and the caller handles the error via SEH. */
        bool is_epmapper = (master_port->name == L"\\RPC Control\\epmapper");
        if (is_epmapper) {
            /* Build WMSG Fault reply in-place. RPCRT4's SendReceive checks:
               +24 (byte): MessageType — 4 = WMSG_FAULT
               +48 (dword): Fault.RpcStatus — the RPC error code
               DataLength=32, TotalLength=56 (from IDA analysis) */
            constexpr uint8_t  WMSG_FAULT = 4;
            constexpr uint16_t WMSG_FAULT_DATA_LEN = 32;
            constexpr uint16_t WMSG_FAULT_TOTAL = 56;
            constexpr uint32_t WMSG_RPCSTATUS_OFF = 0x30; /* offset 48 */
            /* Return STATUS_PORT_CONNECTION_REFUSED — the epmapper has no
               registered endpoints. RPCRT4's endpoint resolver checks the
               NtStatus return code and maps it to RPC_S_SERVER_UNAVAILABLE
               without trying to parse the reply data. */
            CloseHandle(msg->hEvent);
            delete msg;
            constexpr int32_t STATUS_PORT_CONN_REFUSED = static_cast<int32_t>(0xC0000041u);
            LOG(API, "[LPC] epmapper: returning PORT_CONNECTION_REFUSED\n");
            return STATUS_PORT_CONN_REFUSED;
        } else {
            master_port->message_queue.push_back(msg);
            SetEvent(master_port->queue_event);
        }
    }

    uint32_t saved_id = hdr->MessageId;
    LOG(API, "[LPC] RequestWaitReplyPort(0x%08X, msgId=%u) %s\n",
        port_handle, saved_id, "waiting...");

    /* Wait for reply */
    HANDLE wait_event = msg->hEvent;
    WaitForSingleObject(wait_event, INFINITE);

    LOG(API, "[LPC] RequestWaitReplyPort(0x%08X, msgId=%u) got reply\n",
        port_handle, saved_id);

    /* Copy reply to caller */
    if (pReply) {
        std::lock_guard<std::mutex> lock(mutex_);
        /* Re-find the message (it now contains the reply) */
        if (master_port) {
            LpcMessage* reply_msg = FindMessageById(master_port, saved_id);
            if (reply_msg) {
                WriteMessage(pReply, reply_msg, mem);
                RemoveMessage(master_port, reply_msg);
                CloseHandle(reply_msg->hEvent);
                delete reply_msg;
            }
        }
    }
    return NTSTATUS_SUCCESS;
}

/* IOCTL 11: NtClosePort */
int32_t LpcPortManager::ClosePort(uint32_t port_handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    LOG(API, "[LPC] ClosePort(0x%08X)\n", port_handle);

    auto it = ports_.find(port_handle);
    if (it == ports_.end()) return NTSTATUS_INVALID_PORT_HANDLE;

    LpcPort* port = it->second;
    if (port->is_connection_port)
        named_.erase(port->name);
    if (port->queue_event) CloseHandle(port->queue_event);
    for (auto* m : port->message_queue) {
        if (m->hEvent) { SetEvent(m->hEvent); CloseHandle(m->hEvent); }
        delete m;
    }
    delete port;
    ports_.erase(it);
    return NTSTATUS_SUCCESS;
}
