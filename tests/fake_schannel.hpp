#pragma once
// Deterministic SSPI test double. Used only with VPN_CORE_SCHANNEL_TEST on Linux;
// production Windows includes the real Windows headers and calls the OS APIs.
#include <cstdlib>
using ULONG=uint32_t;using DWORD=uint32_t;using SECURITY_STATUS=int32_t;
struct CredHandle{uintptr_t value=0;};struct CtxtHandle{uintptr_t value=0;};struct TimeStamp{};
struct SecBuffer{ULONG cbBuffer;ULONG BufferType;void* pvBuffer;};
struct SecBufferDesc{ULONG ulVersion;ULONG cBuffers;SecBuffer* pBuffers;};
struct SecPkgContext_StreamSizes{ULONG cbHeader=3,cbTrailer=0,cbMaximumMessage=1024,cbBuffers=4,cbBlockSize=1;};
struct SecPkgContext_ApplicationProtocol{unsigned ProtoNegoStatus=0;unsigned char ProtocolId[255]{};unsigned ProtocolIdSize=0;};
struct SecPkgContext_ConnectionInfo{ULONG dwProtocol=0;};
struct SecPkgContext_CipherInfo{ULONG dwVersion=0,dwCipherSuite=0;};
struct TLS_PARAMETERS{ULONG grbitDisabledProtocols=0;};
struct SCH_CREDENTIALS{ULONG dwVersion=0,dwFlags=0,cTlsParameters=0;TLS_PARAMETERS* pTlsParameters=nullptr;};
enum SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT{SecApplicationProtocolNegotiationExt_ALPN=2};
constexpr ULONG SECBUFFER_VERSION=0,SECBUFFER_EMPTY=0,SECBUFFER_DATA=1,SECBUFFER_TOKEN=2,SECBUFFER_EXTRA=5,SECBUFFER_STREAM_HEADER=7,SECBUFFER_STREAM_TRAILER=6,SECBUFFER_ALERT=17,SECBUFFER_APPLICATION_PROTOCOLS=18;
constexpr SECURITY_STATUS SEC_E_OK=0,SEC_I_CONTINUE_NEEDED=0x90312,SEC_I_CONTEXT_EXPIRED=0x90317,SEC_I_RENEGOTIATE=0x90321,SEC_E_INCOMPLETE_MESSAGE=int32_t(0x80090318u),SEC_E_UNTRUSTED_ROOT=int32_t(0x80090325u),SEC_E_MESSAGE_ALTERED=int32_t(0x8009030fu);
constexpr ULONG ISC_REQ_SEQUENCE_DETECT=1,ISC_REQ_REPLAY_DETECT=2,ISC_REQ_CONFIDENTIALITY=4,ISC_REQ_EXTENDED_ERROR=8,ISC_REQ_ALLOCATE_MEMORY=16,ISC_REQ_STREAM=32,ISC_RET_CONFIDENTIALITY=4;
constexpr ULONG SP_PROT_SSL2=1,SP_PROT_SSL3=2,SP_PROT_TLS1_0=4,SP_PROT_TLS1_1=8,SP_PROT_TLS1_3=16,SP_PROT_TLS1_2=32;
constexpr ULONG SCH_CREDENTIALS_VERSION=5,SCH_CRED_AUTO_CRED_VALIDATION=1,SCH_CRED_NO_DEFAULT_CREDS=2,SCH_USE_STRONG_CRYPTO=4,SECPKG_CRED_OUTBOUND=2;
constexpr ULONG SECPKG_ATTR_STREAM_SIZES=1,SECPKG_ATTR_APPLICATION_PROTOCOL=2,SECPKG_ATTR_CONNECTION_INFO=3,SECPKG_ATTR_CIPHER_INFO=4,SecApplicationProtocolNegotiationStatus_Success=1,SCHANNEL_SHUTDOWN=1;
constexpr int CP_UTF8=65001,MB_ERR_INVALID_CHARS=8;constexpr wchar_t UNISP_NAME_W[]=L"test";
inline ULONG fake_tls_protocol=SP_PROT_TLS1_3,fake_tls_cipher=0x1301;
inline bool fake_need_context=false;inline unsigned fake_encrypt_calls=0,fake_isc_calls=0;
template<class T>inline void SecInvalidateHandle(T* p){p->value=0;}
inline bool SecIsValidHandle(CtxtHandle* p){return p->value!=0;}
inline SECURITY_STATUS DeleteSecurityContext(CtxtHandle*){fake_need_context=false;return 0;}
inline SECURITY_STATUS FreeCredentialsHandle(CredHandle*){return 0;}
inline SECURITY_STATUS FreeContextBuffer(void* p){std::free(p);return 0;}
inline int MultiByteToWideChar(int,int,const char* p,int size,wchar_t* out,int){if(out)for(int i=0;i<size;++i)out[i]=static_cast<unsigned char>(p[i]);return size;}
inline SECURITY_STATUS AcquireCredentialsHandleW(void*,wchar_t*,ULONG,void*,SCH_CREDENTIALS* sc,void*,void*,CredHandle* cred,TimeStamp*){if(sc->dwFlags!=(SCH_CRED_AUTO_CRED_VALIDATION|SCH_CRED_NO_DEFAULT_CREDS|SCH_USE_STRONG_CRYPTO))return SEC_E_UNTRUSTED_ROOT;cred->value=1;return 0;}
inline void fake_output(SecBufferDesc* out,const char* p,size_t size){out->pBuffers[0].pvBuffer=std::malloc(size);out->pBuffers[0].cbBuffer=ULONG(size);std::memcpy(out->pBuffers[0].pvBuffer,p,size);}
inline SECURITY_STATUS InitializeSecurityContextW(CredHandle*,CtxtHandle* previous,wchar_t*,ULONG,ULONG,ULONG,SecBufferDesc* in,ULONG,CtxtHandle* context,SecBufferDesc* out,ULONG* attrs,TimeStamp*){
    ++fake_isc_calls;context->value=1;*attrs=ISC_RET_CONFIDENTIALITY;
    if(!previous){fake_output(out,"H",1);return SEC_I_CONTINUE_NEEDED;}
    auto& b=in->pBuffers[0];if(b.BufferType!=SECBUFFER_TOKEN)throw std::runtime_error("ISC input is not TOKEN");auto p=static_cast<const uint8_t*>(b.pvBuffer);
    if(!fake_need_context){if(b.cbBuffer<1)return SEC_E_INCOMPLETE_MESSAGE;if(p[0]!='F')throw std::runtime_error("initial fake handshake");if(b.cbBuffer>1)in->pBuffers[1]={b.cbBuffer-1,SECBUFFER_EXTRA,const_cast<uint8_t*>(p+1)};return SEC_E_OK;}
    if(b.cbBuffer<3)return SEC_E_INCOMPLETE_MESSAGE;std::string tag(reinterpret_cast<const char*>(p),3);
    if(tag=="bad")return SEC_E_UNTRUSTED_ROOT;
    if(tag=="mor"){fake_output(out,"A",1);if(b.cbBuffer>3)in->pBuffers[1]={b.cbBuffer-3,SECBUFFER_EXTRA,const_cast<uint8_t*>(p+3)};return SEC_I_CONTINUE_NEEDED;}
    if(tag!="tic"&&tag!="fin")throw std::runtime_error("ISC did not receive modified Decrypt token");
    fake_output(out,tag=="tic"?"K":"B",1);fake_need_context=false;if(b.cbBuffer>3)in->pBuffers[1]={b.cbBuffer-3,SECBUFFER_EXTRA,const_cast<uint8_t*>(p+3)};return SEC_E_OK;
}
inline SECURITY_STATUS QueryContextAttributesW(CtxtHandle*,ULONG attribute,void* out){if(attribute==SECPKG_ATTR_STREAM_SIZES)*static_cast<SecPkgContext_StreamSizes*>(out)=SecPkgContext_StreamSizes{};if(attribute==SECPKG_ATTR_CONNECTION_INFO)static_cast<SecPkgContext_ConnectionInfo*>(out)->dwProtocol=fake_tls_protocol;if(attribute==SECPKG_ATTR_CIPHER_INFO)static_cast<SecPkgContext_CipherInfo*>(out)->dwCipherSuite=fake_tls_cipher;return SEC_E_OK;}
inline SECURITY_STATUS EncryptMessage(CtxtHandle*,ULONG,SecBufferDesc* desc,ULONG){if(fake_need_context)throw std::runtime_error("EncryptMessage called during post handshake");++fake_encrypt_calls;auto& data=desc->pBuffers[1];auto p=static_cast<uint8_t*>(desc->pBuffers[0].pvBuffer);p[0]='D';p[1]=uint8_t(data.cbBuffer>>8);p[2]=uint8_t(data.cbBuffer);return SEC_E_OK;}
inline SECURITY_STATUS DecryptMessage(CtxtHandle*,SecBufferDesc* desc,ULONG,ULONG*){
    if(fake_need_context)throw std::runtime_error("DecryptMessage called during post handshake");auto input=desc->pBuffers[0];auto p=static_cast<uint8_t*>(input.pvBuffer);if(input.cbBuffer<3)return SEC_E_INCOMPLETE_MESSAGE;size_t n=size_t(p[1])*256+p[2];if(input.cbBuffer<n+3)return SEC_E_INCOMPLETE_MESSAGE;
    for(unsigned i=0;i<desc->cBuffers;++i)desc->pBuffers[i]={0,SECBUFFER_EMPTY,nullptr};
    if(p[0]=='D'){desc->pBuffers[1]={ULONG(n),SECBUFFER_DATA,p+3};if(input.cbBuffer>n+3)desc->pBuffers[3]={input.cbBuffer-ULONG(n+3),SECBUFFER_EXTRA,p+n+3};return SEC_E_OK;}
    if(p[0]=='Z')return SEC_E_MESSAGE_ALTERED;
    fake_need_context=true;
    if(p[0]=='E')desc->pBuffers[3]={input.cbBuffer-3,SECBUFFER_EXTRA,p+3};
    else{desc->pBuffers[0]={ULONG(n),SECBUFFER_TOKEN,p+3};if(input.cbBuffer>n+3)desc->pBuffers[3]={input.cbBuffer-ULONG(n+3),SECBUFFER_EXTRA,p+n+3};}
    return SEC_I_RENEGOTIATE;
}
inline SECURITY_STATUS ApplyControlToken(CtxtHandle*,SecBufferDesc*){return SEC_E_OK;}
