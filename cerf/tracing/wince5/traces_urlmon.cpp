#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* urlmon.dll (WinCE 5.0 ARM build) — URL binding, data transport.
   IDA base: 0x10000000.  PE checksum: 0 (not yet captured). */

void RegisterUrlmonTraces(TraceManager& tm) {
    const char* DLL = "urlmon.dll";
    tm.SetIdaBase(DLL, 0x10000000);
    tm.SetCRC32(DLL, 0xEAE2A81C);

    tm.Add(DLL, 0x1004AFF4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CallOnDataAvailable: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1003D304, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::BSCHolder_OnDataAvailable: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10042B38, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CBinding::Create: url=0x%08X\n", r[1]);
    });
    tm.Add(DLL, 0x10042C58, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CBinding::Initialize: this=0x%08X url=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x10057D94, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CTransaction::Switch: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10045D00, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CBinding::StartBinding: this=0x%08X url=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x1004AB08, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CallOnStartBinding: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1001F0F8, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        char url[40] = {};
        if (r[1]) {
            for (int i = 0; i < 20; i++) {
                uint16_t c = mem->Read16(r[1] + i*2);
                if (!c) break;
                url[i] = (c < 128) ? (char)c : '?';
            }
        }
        LOG(TRACE, "[TRACE] urlmon::CINet::Start: this=0x%08X url='%s' sink=0x%08X\n", r[0], url, r[2]);
    });
    tm.Add(DLL, 0x1001F750, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CINet::Continue: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10022034, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::INetAsyncStart: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1003B044, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CUrl::ParseUrl: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1002B310, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::EmbdFilter::IsInited: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1006D8FC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CINetFile::INetAsyncOpen: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x100224E4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CINet::INetAsyncOpen: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10022A8C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CINet::INetAsyncConnect: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x100583C4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CTransaction::ReportData: this=0x%08X bscf=0x%X progress=%u max=%u\n", r[0], r[1], r[2], r[3]);
    });
    tm.Add(DLL, 0x1006DCE8, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CINetFile::Read: this=0x%08X buf=0x%08X cb=%u\n", r[0], r[1], r[2]);
    });
    tm.Add(DLL, 0x10021668, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::ReportResultAndStop: this=0x%08X hr=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x1005D2A8, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::DispatchReport: this=0x%08X status=%u bscf=0x%X curSize=%u\n", r[0], r[1], r[2], r[3]);
    });
    tm.Add(DLL, 0x10058844, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::OnDataReceived: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1005D5A0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::DispatchReport->ReportData: pCBdg=0x%08X target=0x%08X bscf=0x%X curSize=%u totalSize=%u\n",
            r[0], r[4], r[1], r[2], r[3]);
    });
    tm.Add(DLL, 0x1004B7EC, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CBinding::ReportData: this=0x%08X bscf=0x%X cur=%u total=%u\n", r[0], r[1], r[2], r[3]);
    });
    tm.Add(DLL, 0x1007DE64, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::COInetProt::ReportData: this=0x%08X bscf=0x%X cur=%u total=%u\n", r[0], r[1], r[2], r[3]);
    });
    tm.Add(DLL, 0x1002BBF4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CINetEmbdFilter::ReportData: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x10049EA0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::ObjectPersistMnkLoad: this=0x%08X pUnk=0x%08X fLocal=%d fFull=%d\n", r[0], r[1], r[2], r[3]);
    });
    tm.Add(DLL, 0x1004A758, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::ObjectPersistFileLoad: this=0x%08X pUnk=0x%08X\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x1004BD14, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CreateObject: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x100495F4, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        /* Dump CLSID: R1=pclsid, R2=riidResult */
        uint32_t clsid_ptr = r[1];
        uint32_t d1 = mem->Read32(clsid_ptr);
        uint16_t d2 = mem->Read16(clsid_ptr+4);
        uint16_t d3 = mem->Read16(clsid_ptr+6);
        LOG(TRACE, "[TRACE] urlmon::InstantiateObject: this=0x%08X "
            "clsid={%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X} fFull=%d\n",
            r[0], d1, d2, d3,
            mem->Read8(clsid_ptr+8), mem->Read8(clsid_ptr+9),
            mem->Read8(clsid_ptr+10), mem->Read8(clsid_ptr+11),
            mem->Read8(clsid_ptr+12), mem->Read8(clsid_ptr+13),
            mem->Read8(clsid_ptr+14), mem->Read8(clsid_ptr+15),
            mem->Read32(r[13]+0));
    });
    tm.Add(DLL, 0x1005244C, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CTransData::OnDataReceived: this=0x%08X bscf=0x%X cur=%u max=%u\n", r[0], r[1], r[2], r[3]);
    });
    tm.Add(DLL, 0x10046EC4, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CBinding::OnTransNotification: this=0x%08X status=%u\n", r[0], r[1]);
    });
    tm.Add(DLL, 0x10048874, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CBinding::OnObjectAvailable: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x100484A0, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CBinding::OnDataNotification: this=0x%08X\n", r[0]);
    });
    tm.Add(DLL, 0x1004AD20, [](uint32_t, const uint32_t* r, EmulatedMemory*) {
        LOG(TRACE, "[TRACE] urlmon::CallOnStopBinding: this=0x%08X hr=0x%08X\n", r[0], r[1]);
    });
}
