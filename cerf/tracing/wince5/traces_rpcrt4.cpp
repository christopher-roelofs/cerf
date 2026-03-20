#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* rpcrt4.dll (WinCE 5.0 ARM build) — RPC client/server traces.
   IDA base: 0x10000000. */

void RegisterRpcrt4Traces(TraceManager& tm) {
    const char* DLL = "rpcrt4.dll";
    tm.SetIdaBase(DLL, 0x10000000);
    tm.SetCRC32(DLL, 0xE5B495B7);

    /* WMSG_CASSOCIATION::OpenLpcPort — constructs \RPC Control\<endpoint>
       and calls NtConnectPort. Dumps the endpoint name. */
    tm.Add(DLL, 0x1000C728, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        /* this->DceBinding is at some offset. The endpoint is constructed
           from DCE_BINDING::InqEndpoint. We'll dump it after construction.
           For now just log that OpenLpcPort was called. */
        LOG(TRACE, "[TRACE] WMSG_CASSOCIATION::OpenLpcPort: this=0x%08X fBindBack=%d\n",
            r[0], r[1]);
    });

    /* WMSG_ADDRESS::SetupAddressWithEndpoint — server creates LPC port */
    tm.Add(DLL, 0x10016BF0, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        /* R1 = Endpoint (wchar_t*) */
        char ep[40] = {};
        if (r[1]) {
            for (int i = 0; i < 39; i++) {
                uint16_t c = mem->Read16(r[1] + i * 2);
                if (!c) break;
                ep[i] = (char)c;
            }
        }
        LOG(TRACE, "[TRACE] WMSG_ADDRESS::SetupAddressWithEndpoint: endpoint='%s'\n", ep);
    });

    /* RpcServerUseProtseqEpW — server registers protocol+endpoint */
    tm.Add(DLL, 0x10015004, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char protseq[20] = {}, ep[40] = {};
        if (r[0]) {
            for (int i = 0; i < 19; i++) {
                uint16_t c = mem->Read16(r[0] + i * 2);
                if (!c) break;
                protseq[i] = (char)c;
            }
        }
        if (r[2]) {
            for (int i = 0; i < 39; i++) {
                uint16_t c = mem->Read16(r[2] + i * 2);
                if (!c) break;
                ep[i] = (char)c;
            }
        }
        LOG(TRACE, "[TRACE] RpcServerUseProtseqEpW: protseq='%s' endpoint='%s'\n",
            protseq, ep);
    });

    /* NtConnectPort call inside OpenLpcPort — dump the port name.
       At this point: R1 = &UNICODE_STRING {Length, MaxLength, Buffer} */
    tm.Add(DLL, 0x1000CA60, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        uint32_t ustr = r[1]; /* UNICODE_STRING on stack */
        uint16_t len = mem->Read16(ustr);        /* Length in bytes */
        uint32_t buf = mem->Read32(ustr + 4);    /* Buffer pointer */
        char name[80] = {};
        if (buf) {
            for (int i = 0; i < 79 && i < len / 2; i++) {
                uint16_t c = mem->Read16(buf + i * 2);
                if (!c) break;
                name[i] = (char)c;
            }
        }
        LOG(TRACE, "[TRACE] OpenLpcPort -> NtConnectPort('%s')\n", name);
    });

    /* WMSG_CASSOCIATION constructor — who creates the RPC association? */
    tm.Add(DLL, 0x1000B3BC, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        /* R1 = DCE_BINDING*, R2 = CLIENT_AUTH_INFO* */
        LOG(TRACE, "[TRACE] WMSG_CASSOCIATION::ctor: this=0x%08X binding=0x%08X LR=0x%08X\n",
            r[0], r[1], r[14]);
    });

    /* WmsgCreateBindingHandle — creates a WMSG client handle */
    tm.Add(DLL, 0x10010758, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] WmsgCreateBindingHandle LR=0x%08X\n", r[14]);
    });

    /* RpcRaiseException — trace the RPC status being raised */
    tm.Add(DLL, 0x10036464, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] RpcRaiseException: status=%u (0x%08X)\n", r[0], r[0]);
    });
}
