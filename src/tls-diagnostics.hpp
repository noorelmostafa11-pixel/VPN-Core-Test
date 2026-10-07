// Copyright (c) 2026 Vpn project owner (noorelmostafa11-pixel). See NOTICE.md.
#pragma once
#include <cstdint>
namespace vpn {
// Windows HRESULT identities from winerror.h. Keep the native value as well;
// these describe the reported condition, not responsibility for its cause.
inline const char* native_tls_reason(uint32_t status,const char* fallback){
    switch(status){
    case 0x80090322u:return "TLS_CERTIFICATE_NAME";
    case 0x80090325u:return "TLS_CERTIFICATE_UNTRUSTED";
    case 0x80090327u:return "TLS_CERTIFICATE_INVALID";
    case 0x80090328u:return "TLS_CERTIFICATE_VALIDITY";
    case 0x80096004u:return "TLS_CERTIFICATE_SIGNATURE";
    case 0x80090326u:return "TLS_HANDSHAKE_MESSAGE";
    case 0x80090308u:return "TLS_HANDSHAKE_TOKEN";
    case 0x80090367u:return "TLS_ALPN_NEGOTIATION";
    case 0x00090320u:return "TLS_CLIENT_CERTIFICATE_REQUIRED";
    default:return fallback;
    }
}
}
