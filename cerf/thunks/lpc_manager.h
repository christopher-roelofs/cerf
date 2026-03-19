#pragma once
/* LPC (Local Procedure Call) Port Manager — emulates lpcd.dll device driver.
   Manages named ports, client/server connections, and message passing
   for COM cross-apartment marshaling via RPCRT4's WMSG transport.

   On real WinCE, lpcd.dll is a kernel stream device driver that registers
   "LPC1:" via RegisterDevice. LPCRT.dll opens it with CreateFileW and
   uses DeviceIoControl for all Nt* port operations. We provide the same
   DeviceIoControl interface backed by in-process C++ objects.

   Data structures match lpc.h from WinCE Platform Builder. */

#include <cstdint>
#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <windows.h>

class EmulatedMemory;

/* PORT_MESSAGE layout in ARM memory (24 bytes header) */
struct ArmPortMessage {
    uint16_t DataLength;     /* +0 */
    uint16_t TotalLength;    /* +2 */
    uint16_t Type;           /* +4 */
    uint16_t DataInfoOffset; /* +6 */
    uint32_t ProcessId;      /* +8  ClientId.UniqueProcess */
    uint32_t ThreadId;       /* +12 ClientId.UniqueThread */
    uint32_t MessageId;      /* +16 */
    uint32_t ClientViewSize; /* +20 */
    /* Data[DataLength] follows at +24 */
};
static_assert(sizeof(ArmPortMessage) == 24, "PORT_MESSAGE header size");

constexpr uint32_t PORT_MAX_MESSAGE = 256;
constexpr uint16_t LPC_REQUEST = 1;
constexpr uint16_t LPC_REPLY = 2;
constexpr uint16_t LPC_CONNECTION_REQUEST = 10;

class LpcPortManager {
public:
    LpcPortManager();
    ~LpcPortManager();

    /* DeviceIoControl dispatch — called from the thunk.
       Arguments match the non-standard LPCRT.dll calling convention:
       dwCode=IOCTL, pBufIn/dwLenIn/pBufOut/dwLenOut/pdwActualOut are ARM addresses. */
    int32_t HandleIoctl(uint32_t dwCode, uint32_t pBufIn, uint32_t dwLenIn,
                        uint32_t pBufOut, uint32_t dwLenOut, uint32_t pdwActualOut,
                        EmulatedMemory& mem);

private:
    struct LpcMessage {
        std::vector<uint8_t> data;  /* full PORT_MESSAGE including header */
        HANDLE hEvent = nullptr;    /* signaled when reply arrives */
        uint32_t sender_handle = 0; /* communication port that sent this */
    };

    struct LpcPort {
        std::wstring name;
        uint32_t handle = 0;
        uint32_t max_message_length = PORT_MAX_MESSAGE;
        uint32_t owner_process = 0;
        bool is_connection_port = false; /* true = server, false = communication */
        uint32_t master_handle = 0;      /* for comm ports: server port handle */

        /* Server-side: pending connection requests and messages */
        std::vector<LpcMessage*> message_queue;
        HANDLE queue_event = nullptr;    /* signaled when message arrives */
    };

    std::mutex mutex_;
    std::map<uint32_t, LpcPort*> ports_;       /* handle → port */
    std::map<std::wstring, LpcPort*> named_;   /* name → connection port */
    uint32_t next_handle_ = 0x4C500001;        /* LPC handle space */
    uint32_t next_message_id_ = 1;

    uint32_t AllocHandle();
    LpcPort* FindPort(uint32_t handle);
    LpcMessage* FindMessageById(LpcPort* port, uint32_t msg_id);
    void RemoveMessage(LpcPort* port, LpcMessage* msg);

    /* IOCTL implementations */
    int32_t CreatePort(uint32_t pBufIn, EmulatedMemory& mem);
    int32_t ConnectPort(uint32_t pBufIn, EmulatedMemory& mem);
    int32_t AcceptConnectPort(uint32_t pBufIn, EmulatedMemory& mem);
    int32_t CompleteConnectPort(uint32_t port_handle);
    int32_t ReplyWaitReceivePort(uint32_t port_handle, uint32_t pCtx,
                                  uint32_t pReply, uint32_t pReceive,
                                  EmulatedMemory& mem);
    int32_t ListenPort(uint32_t port_handle, uint32_t pConnReq, EmulatedMemory& mem);
    int32_t ReplyPort(uint32_t port_handle, uint32_t pReply, EmulatedMemory& mem);
    int32_t RequestWaitReplyPort(uint32_t port_handle, uint32_t pRequest,
                                  uint32_t pReply, EmulatedMemory& mem);
    int32_t ClosePort(uint32_t port_handle);

    /* Helper: read PORT_MESSAGE from ARM memory into LpcMessage */
    LpcMessage* ReadMessage(uint32_t arm_addr, EmulatedMemory& mem);
    /* Helper: write LpcMessage back to ARM PORT_MESSAGE */
    void WriteMessage(uint32_t arm_addr, const LpcMessage* msg, EmulatedMemory& mem);
};
