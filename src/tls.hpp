// Copyright (c) 2026 Vpn project owner (noorelmostafa11-pixel). See NOTICE.md.
#pragma once
#include "net.hpp"
#include "tls-diagnostics.hpp"
#include <memory>
#ifdef VPN_CORE_SCHANNEL_TEST
#include "../tests/fake_schannel.hpp"
#elif defined(_WIN32)
#define SECURITY_WIN32
#include <windows.h>
#include <winternl.h>
#define SCHANNEL_USE_BLACKLISTS
#include <security.h>
#include <schannel.h>
#elif defined(VPN_CORE_PORTABLE)
// Verified TLS is supplied by the existing pinned provider.
#elif defined(VPN_CORE_TEST_BACKEND)
#include <openssl/ssl.h>
#include <openssl/err.h>
#else
#error Select Windows, VPN_CORE_PORTABLE, or the independent test backend.
#endif

namespace vpn {
inline std::vector<std::string> tls_protocols(const Config& c){if(!c.alpn.empty()){if(c.transport=="websocket"||c.transport=="httpupgrade"){if(std::find(c.alpn.begin(),c.alpn.end(),"http/1.1")!=c.alpn.end())return {"http/1.1"};return c.alpn;}return c.alpn;}if(c.transport=="grpc"||c.transport=="http")return {"h2"};if(c.transport=="xhttp")return {"h2","http/1.1"};if(c.transport=="websocket"||c.transport=="httpupgrade")return {"http/1.1"};return {};}
#if defined(_WIN32) || defined(VPN_CORE_SCHANNEL_TEST)
class NativeTls {
    CredHandle cred_{};CtxtHandle ctx_{};bool have_cred_=false,have_ctx_=false,closed_=false;
    SecPkgContext_StreamSizes sizes_{};Bytes cipher_,control_,deferred_,resume_tail_;std::wstring name_;std::string alpn_,version_;
    bool negotiating_=false,shutdown_pending_=false;unsigned continuation_steps_=0;
    Clock::time_point continuation_deadline_{};unsigned continuation_ms_=10000;
    static constexpr ULONG flags_=ISC_REQ_SEQUENCE_DETECT|ISC_REQ_REPLAY_DETECT|ISC_REQ_CONFIDENTIALITY|ISC_REQ_EXTENDED_ERROR|ISC_REQ_ALLOCATE_MEMORY|ISC_REQ_STREAM;
    struct Output {
        SecBuffer b[2]{{0,SECBUFFER_TOKEN,nullptr},{0,SECBUFFER_ALERT,nullptr}};
        SecBufferDesc desc{SECBUFFER_VERSION,2,b};
        ~Output(){for(auto& x:b)if(x.pvBuffer)FreeContextBuffer(x.pvBuffer);}
        Bytes token()const{if(!b[0].cbBuffer)return {};auto p=static_cast<const uint8_t*>(b[0].pvBuffer);return Bytes(p,p+b[0].cbBuffer);}
    };
    static std::wstring wide(const std::string& s) {
        int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),nullptr,0);
        if(!n)throw std::runtime_error("Invalid TLS server name");
        std::wstring w(size_t(n),L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),w.data(),n);return w;
    }
    bool continue_context() {
        if(Clock::now()>continuation_deadline_)throw Failure("TLS_FAILED: post-handshake timeout","TLS_POST_HANDSHAKE_TIMEOUT");
        if(++continuation_steps_>256)throw Failure("TLS_FAILED: post-handshake step limit","TLS_POST_HANDSHAKE_LIMIT");
        SecBuffer in[2]{{ULONG(cipher_.size()),SECBUFFER_TOKEN,cipher_.empty()?nullptr:cipher_.data()},{0,SECBUFFER_EMPTY,nullptr}};
        SecBufferDesc desc{SECBUFFER_VERSION,2,in};Output out;ULONG attributes=0;TimeStamp expiry{};
        auto status=InitializeSecurityContextW(&cred_,&ctx_,name_.data(),flags_,0,0,&desc,0,&ctx_,&out.desc,&attributes,&expiry);
        if(status==SEC_E_INCOMPLETE_MESSAGE)return false;
        if(status!=SEC_E_OK&&status!=SEC_I_CONTINUE_NEEDED)throw Failure("TLS_FAILED: post-handshake verification failed",native_tls_reason(uint32_t(status),"TLS_POST_HANDSHAKE_VERIFY"),uint32_t(status));
        auto token=out.token();control_.insert(control_.end(),token.begin(),token.end());
        size_t extra=in[1].BufferType==SECBUFFER_EXTRA?in[1].cbBuffer:0;
        if(extra>cipher_.size()||(extra==cipher_.size()&&extra))throw Failure("TLS_FAILED: post-handshake made no progress","TLS_POST_HANDSHAKE_BUFFER");
        cipher_.erase(cipher_.begin(),cipher_.end()-std::ptrdiff_t(extra));
        if(status==SEC_E_OK){
            if(!(attributes&ISC_RET_CONFIDENTIALITY)||QueryContextAttributesW(&ctx_,SECPKG_ATTR_STREAM_SIZES,&sizes_)!=SEC_E_OK)throw Failure("TLS_FAILED: post-handshake stream setup","TLS_POST_HANDSHAKE_STREAM");
            verify_policy();negotiating_=false;continuation_steps_=0;
            cipher_.insert(cipher_.end(),resume_tail_.begin(),resume_tail_.end());resume_tail_.clear();
            if(!deferred_.empty()){auto pending=std::exchange(deferred_,{});auto encrypted=encrypt(pending);control_.insert(control_.end(),encrypted.begin(),encrypted.end());}
            if(shutdown_pending_){shutdown_pending_=false;auto close=close_notify();control_.insert(control_.end(),close.begin(),close.end());}
            return true;
        }
        return !cipher_.empty();
    }
public:
    NativeTls(){SecInvalidateHandle(&ctx_);SecInvalidateHandle(&cred_);}
    NativeTls(const NativeTls&)=delete;NativeTls& operator=(const NativeTls&)=delete;
    ~NativeTls(){if(have_ctx_)DeleteSecurityContext(&ctx_);if(have_cred_)FreeCredentialsHandle(&cred_);}
    const char* backend()const{return "Windows Schannel; TLS 1.2/1.3 depends on OS";}
    const std::string& selected_alpn()const{return alpn_;}
    const std::string& version()const{return version_;}
    void verify_policy(){SecPkgContext_ConnectionInfo info{};SecPkgContext_CipherInfo cipher{};cipher.dwVersion=1;if(QueryContextAttributesW(&ctx_,SECPKG_ATTR_CONNECTION_INFO,&info)!=SEC_E_OK||QueryContextAttributesW(&ctx_,SECPKG_ATTR_CIPHER_INFO,&cipher)!=SEC_E_OK)throw Failure("TLS_FAILED: negotiated TLS policy unavailable","TLS_SECURITY_POLICY");bool modern=(info.dwProtocol&SP_PROT_TLS1_3)!=0;bool permitted=modern?(cipher.dwCipherSuite==0x1301||cipher.dwCipherSuite==0x1302||cipher.dwCipherSuite==0x1303):((info.dwProtocol&SP_PROT_TLS1_2)!=0&&std::set<DWORD>{0xc02b,0xc02c,0xc02f,0xc030,0xcca8,0xcca9}.count(cipher.dwCipherSuite));if(!permitted)throw Failure("TLS_FAILED: negotiated cipher outside security policy","TLS_SECURITY_POLICY");version_=modern?"TLS1.3":"TLS1.2";}
    void handshake(Socket& socket,const Config& c,Clock::time_point deadline) {
        continuation_ms_=c.connect_ms;
        name_=wide(c.tls_name);
        TLS_PARAMETERS parameters{};parameters.grbitDisabledProtocols=SP_PROT_SSL2|SP_PROT_SSL3|SP_PROT_TLS1_0|SP_PROT_TLS1_1;
        SCH_CREDENTIALS sc{};sc.dwVersion=SCH_CREDENTIALS_VERSION;sc.dwFlags=SCH_CRED_AUTO_CRED_VALIDATION|SCH_CRED_NO_DEFAULT_CREDS|SCH_USE_STRONG_CRYPTO;sc.cTlsParameters=1;sc.pTlsParameters=&parameters;
        TimeStamp expiry{};auto status=AcquireCredentialsHandleW(nullptr,const_cast<wchar_t*>(UNISP_NAME_W),SECPKG_CRED_OUTBOUND,nullptr,&sc,nullptr,nullptr,&cred_,&expiry);
        if(status!=SEC_E_OK)throw Failure("TLS_FAILED: cannot initialize Windows TLS credentials","TLS_CREDENTIALS",uint32_t(status));
        have_cred_=true;ULONG attributes=0;Output first;
        auto protocols=tls_protocols(c);
        Bytes encoded;for(const auto& p:protocols){encoded.push_back(uint8_t(p.size()));encoded.insert(encoded.end(),p.begin(),p.end());}
        Bytes application;SecBuffer application_buffer{};SecBufferDesc application_desc{SECBUFFER_VERSION,1,&application_buffer};
        if(!encoded.empty()){if(encoded.size()>65535)throw std::runtime_error("TLS_FAILED: ALPN list too large");ULONG list_size=ULONG(sizeof(SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT)+sizeof(unsigned short)+encoded.size());application.resize(sizeof(ULONG)+list_size);auto ext=SecApplicationProtocolNegotiationExt_ALPN;auto count=static_cast<unsigned short>(encoded.size());std::memcpy(application.data(),&list_size,sizeof(list_size));std::memcpy(application.data()+sizeof(ULONG),&ext,sizeof(ext));std::memcpy(application.data()+sizeof(ULONG)+sizeof(ext),&count,sizeof(count));std::copy(encoded.begin(),encoded.end(),application.begin()+std::ptrdiff_t(sizeof(ULONG)+sizeof(ext)+sizeof(count)));application_buffer={ULONG(application.size()),SECBUFFER_APPLICATION_PROTOCOLS,application.data()};}
        status=InitializeSecurityContextW(&cred_,nullptr,name_.data(),flags_,0,0,application.empty()?nullptr:&application_desc,0,&ctx_,&first.desc,&attributes,&expiry);
        have_ctx_=SecIsValidHandle(&ctx_);
        if(status!=SEC_I_CONTINUE_NEEDED&&status!=SEC_E_OK)throw Failure("TLS_FAILED: cannot start Windows TLS handshake",native_tls_reason(uint32_t(status),"TLS_HANDSHAKE_START"),uint32_t(status));
        auto output=first.token();send_all(socket,output.data(),output.size(),deadline);
        Bytes input;
        while(status!=SEC_E_OK) {
            auto b=receive_some(socket,deadline);input.insert(input.end(),b.begin(),b.end());
            if(input.size()>262144)throw std::runtime_error("TLS handshake buffer limit exceeded");
            for(;;) {
                SecBuffer in[2]{{ULONG(input.size()),SECBUFFER_TOKEN,input.data()},{0,SECBUFFER_EMPTY,nullptr}};
                SecBufferDesc desc{SECBUFFER_VERSION,2,in};Output next;
                status=InitializeSecurityContextW(&cred_,&ctx_,name_.data(),flags_,0,0,&desc,0,&ctx_,&next.desc,&attributes,&expiry);
                if(status==SEC_E_INCOMPLETE_MESSAGE)break;
                if(status!=SEC_E_OK&&status!=SEC_I_CONTINUE_NEEDED)throw Failure("TLS_FAILED: Windows handshake/certificate verification failed",native_tls_reason(uint32_t(status),"TLS_HANDSHAKE_VERIFY"),uint32_t(status));
                output=next.token();send_all(socket,output.data(),output.size(),deadline);
                size_t extra=in[1].BufferType==SECBUFFER_EXTRA?in[1].cbBuffer:0;
                if(extra>input.size())throw std::runtime_error("Invalid Windows TLS buffer state");
                input.erase(input.begin(),input.end()-std::ptrdiff_t(extra));
                if(status==SEC_E_OK||input.empty())break;
            }
        }
        if(!(attributes&ISC_RET_CONFIDENTIALITY)||QueryContextAttributesW(&ctx_,SECPKG_ATTR_STREAM_SIZES,&sizes_)!=SEC_E_OK)throw std::runtime_error("Windows TLS stream setup failed");
        cipher_=std::move(input);
        SecPkgContext_ApplicationProtocol negotiated{};if(QueryContextAttributesW(&ctx_,SECPKG_ATTR_APPLICATION_PROTOCOL,&negotiated)==SEC_E_OK&&negotiated.ProtoNegoStatus==SecApplicationProtocolNegotiationStatus_Success)alpn_.assign(reinterpret_cast<const char*>(negotiated.ProtocolId),negotiated.ProtocolIdSize);
        verify_policy();
    }
    Bytes encrypt(const Bytes& plain) {
        if(negotiating_){if(deferred_.size()+plain.size()>524288)throw Failure("TLS_FAILED: pending application data limit","TLS_PENDING_LIMIT");deferred_.insert(deferred_.end(),plain.begin(),plain.end());return {};}
        Bytes output;
        for(size_t off=0;off<plain.size();) {
            size_t n=std::min(size_t(sizes_.cbMaximumMessage),plain.size()-off);
            if(!n)throw std::runtime_error("Invalid Windows TLS record size");
            Bytes record(size_t(sizes_.cbHeader)+n+sizes_.cbTrailer);
            std::copy_n(plain.data()+off,n,record.data()+sizes_.cbHeader);
            SecBuffer b[4]{{sizes_.cbHeader,SECBUFFER_STREAM_HEADER,record.data()},{ULONG(n),SECBUFFER_DATA,record.data()+sizes_.cbHeader},{sizes_.cbTrailer,SECBUFFER_STREAM_TRAILER,record.data()+sizes_.cbHeader+n},{0,SECBUFFER_EMPTY,nullptr}};
            SecBufferDesc desc{SECBUFFER_VERSION,4,b};
            auto status=EncryptMessage(&ctx_,0,&desc,0);if(status!=SEC_E_OK)throw Failure("TLS_FAILED: Windows TLS encryption failed","TLS_ENCRYPT",uint32_t(status));
            for(int i=0;i<3;++i){auto p=static_cast<const uint8_t*>(b[i].pvBuffer);output.insert(output.end(),p,p+b[i].cbBuffer);}
            off+=n;
        }
        return output;
    }
    Bytes feed(const uint8_t* data,size_t n) {
        if(negotiating_&&Clock::now()>continuation_deadline_)throw Failure("TLS_FAILED: post-handshake timeout","TLS_POST_HANDSHAKE_TIMEOUT");
        if(n)cipher_.insert(cipher_.end(),data,data+n);
        if(cipher_.size()>262144)throw std::runtime_error("TLS input buffer limit exceeded");
        Bytes plain;
        while(!cipher_.empty()&&!closed_) {
            if(negotiating_){if(!continue_context())break;if(negotiating_)continue;if(cipher_.empty())break;}
            SecBuffer b[4]{{ULONG(cipher_.size()),SECBUFFER_DATA,cipher_.data()},{0,SECBUFFER_EMPTY,nullptr},{0,SECBUFFER_EMPTY,nullptr},{0,SECBUFFER_EMPTY,nullptr}};
            SecBufferDesc desc{SECBUFFER_VERSION,4,b};ULONG qop=0;
            auto status=DecryptMessage(&ctx_,&desc,0,&qop);
            if(status==SEC_E_INCOMPLETE_MESSAGE)break;
            if(status==SEC_I_RENEGOTIATE){
                // Schannel reuses this status for TLS 1.3 session tickets and
                // KeyUpdate. Pass its returned token to ISC before any further
                // encryption/decryption; do not discard or ignore the status.
                SecBuffer* token=&b[0];
                for(auto& x:b)if(x.BufferType==SECBUFFER_EXTRA){token=&x;break;}
                for(auto& x:b)if(x.BufferType==SECBUFFER_TOKEN){token=&x;break;}
                auto copy_buffer=[&](const SecBuffer& x){Bytes bytes;if(x.cbBuffer){auto p=static_cast<const uint8_t*>(x.pvBuffer);auto begin=reinterpret_cast<uintptr_t>(cipher_.data()),end=begin+cipher_.size(),start=reinterpret_cast<uintptr_t>(p);if(start<begin||start>end||x.cbBuffer>end-start)throw Failure("TLS_FAILED: invalid post-handshake token","TLS_POST_HANDSHAKE_BUFFER");bytes.assign(p,p+x.cbBuffer);}return bytes;};
                Bytes next=copy_buffer(*token);if(token->BufferType!=SECBUFFER_EXTRA)for(auto& x:b)if(x.BufferType==SECBUFFER_EXTRA)resume_tail_=copy_buffer(x);
                cipher_=std::move(next);negotiating_=true;continuation_steps_=0;continuation_deadline_=Clock::now()+std::chrono::milliseconds(continuation_ms_);
                if(!continue_context())break;continue;
            }
            if(status!=SEC_E_OK&&status!=SEC_I_CONTEXT_EXPIRED)throw Failure("TLS_FAILED: Windows record verification failed","TLS_RECORD_VERIFY",uint32_t(status));
            size_t extra=0;
            for(auto& x:b) {
                if(x.BufferType==SECBUFFER_DATA&&x.cbBuffer){auto p=static_cast<const uint8_t*>(x.pvBuffer);plain.insert(plain.end(),p,p+x.cbBuffer);}
                if(x.BufferType==SECBUFFER_EXTRA)extra=x.cbBuffer;
            }
            if(status==SEC_I_CONTEXT_EXPIRED)closed_=true;
            if(extra>=cipher_.size()&&extra)throw std::runtime_error("TLS decryption made no progress");
            cipher_.erase(cipher_.begin(),cipher_.end()-std::ptrdiff_t(extra));
        }
        return plain;
    }
    bool closed()const{return closed_;}
    bool negotiating()const{return negotiating_;}
    size_t pending_bytes()const{return deferred_.size();}
    Bytes take_control(){return std::exchange(control_,{});}
    Bytes close_notify() {
        if(negotiating_){shutdown_pending_=true;return {};}
        DWORD token=SCHANNEL_SHUTDOWN;SecBuffer b{sizeof(token),SECBUFFER_TOKEN,&token};SecBufferDesc d{SECBUFFER_VERSION,1,&b};
        if(ApplyControlToken(&ctx_,&d)!=SEC_E_OK)throw std::runtime_error("Windows TLS shutdown failed");
        Output out;ULONG attrs=0;TimeStamp expiry{};
        auto r=InitializeSecurityContextW(&cred_,&ctx_,name_.data(),flags_,0,0,nullptr,0,&ctx_,&out.desc,&attrs,&expiry);
        if(r!=SEC_E_OK&&r!=SEC_I_CONTEXT_EXPIRED)throw std::runtime_error("Windows TLS shutdown token failed");
        return out.token();
    }
};
#elif !defined(VPN_CORE_PORTABLE)
// Test-only transport adapter. This file's Windows branch never includes or
// links OpenSSL. Protocol, parser, SOCKS and relay code are shared unchanged.
class NativeTls {
    SSL_CTX* ctx_=nullptr;SSL* ssl_=nullptr;bool closed_=false;std::string alpn_,version_;
    Bytes output() {
        Bytes b;uint8_t chunk[16384];int n;
        while((n=BIO_read(SSL_get_wbio(ssl_),chunk,sizeof(chunk)))>0)b.insert(b.end(),chunk,chunk+n);
        return b;
    }
public:
    NativeTls()=default;NativeTls(const NativeTls&)=delete;NativeTls& operator=(const NativeTls&)=delete;
    ~NativeTls(){if(ssl_)SSL_free(ssl_);if(ctx_)SSL_CTX_free(ctx_);}
    const char* backend()const{return "TEST ONLY: Linux OpenSSL (TLS 1.2/1.3)";}
    const std::string& selected_alpn()const{return alpn_;}
    const std::string& version()const{return version_;}
    void handshake(Socket& socket,const Config& c,Clock::time_point deadline) {
        ctx_=SSL_CTX_new(TLS_client_method());if(!ctx_)throw std::runtime_error("Test TLS initialization failed");
        SSL_CTX_set_min_proto_version(ctx_,TLS1_2_VERSION);
        if(!SSL_CTX_set_cipher_list(ctx_,"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"))throw Failure("TLS_FAILED: cipher policy initialization","TLS_SECURITY_POLICY");
        SSL_CTX_set_verify(ctx_,SSL_VERIFY_PEER,nullptr);
        if(c.test_ca_file.empty()){if(!SSL_CTX_set_default_verify_paths(ctx_))throw std::runtime_error("Test TLS roots unavailable");}
        else if(!SSL_CTX_load_verify_locations(ctx_,c.test_ca_file.c_str(),nullptr))throw std::runtime_error("Test CA unavailable");
        ssl_=SSL_new(ctx_);if(!ssl_)throw std::runtime_error("Test TLS allocation failed");
        auto protocols=tls_protocols(c);Bytes encoded;for(const auto& p:protocols){encoded.push_back(uint8_t(p.size()));encoded.insert(encoded.end(),p.begin(),p.end());}if(!encoded.empty()&&SSL_set_alpn_protos(ssl_,encoded.data(),unsigned(encoded.size())))throw std::runtime_error("TLS_FAILED: ALPN setup");
        auto in=BIO_new(BIO_s_mem());auto out=BIO_new(BIO_s_mem());
        if(!in||!out){BIO_free(in);BIO_free(out);throw std::runtime_error("Test TLS buffers unavailable");}
        BIO_set_mem_eof_return(in,-1);BIO_set_mem_eof_return(out,-1);SSL_set_bio(ssl_,in,out);SSL_set_connect_state(ssl_);
        uint8_t addr[16];bool ip=inet_pton(AF_INET,c.tls_name.c_str(),addr)==1||inet_pton(AF_INET6,c.tls_name.c_str(),addr)==1;
        if(ip){if(!X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl_),c.tls_name.c_str()))throw std::runtime_error("Test TLS IP setup failed");}
        else if(!SSL_set1_host(ssl_,c.tls_name.c_str())||!SSL_set_tlsext_host_name(ssl_,c.tls_name.c_str()))throw std::runtime_error("Test TLS name setup failed");
        for(;;) {
            int r=SSL_do_handshake(ssl_);int e=SSL_get_error(ssl_,r);auto b=output();send_all(socket,b.data(),b.size(),deadline);
            if(r==1)break;
            if(e!=SSL_ERROR_WANT_READ)throw Failure("TLS_FAILED: test handshake/certificate verification failed","TLS_HANDSHAKE_VERIFY",uint32_t(SSL_get_verify_result(ssl_)));
            b=receive_some(socket,deadline);if(BIO_write(SSL_get_rbio(ssl_),b.data(),int(b.size()))!=int(b.size()))throw std::runtime_error("Test TLS input failed");
        }
        const unsigned char* selected=nullptr;unsigned selected_size=0;SSL_get0_alpn_selected(ssl_,&selected,&selected_size);if(selected_size)alpn_.assign(reinterpret_cast<const char*>(selected),selected_size);version_=SSL_get_version(ssl_);
    }
    Bytes encrypt(const Bytes& plain) {
        for(size_t offset=0;offset<plain.size();) {int n=SSL_write(ssl_,plain.data()+offset,int(std::min(size_t(16384),plain.size()-offset)));if(n<=0)throw std::runtime_error("Test TLS encryption failed");offset+=size_t(n);}
        return output();
    }
    Bytes feed(const uint8_t* data,size_t n) {
        if(n&&BIO_write(SSL_get_rbio(ssl_),data,int(n))!=int(n))throw std::runtime_error("Test TLS input failed");
        if(BIO_ctrl_pending(SSL_get_rbio(ssl_))>262144)throw std::runtime_error("Test TLS input limit exceeded");
        Bytes out;uint8_t b[16384];
        for(;;){int r=SSL_read(ssl_,b,sizeof(b));if(r>0){out.insert(out.end(),b,b+r);continue;}int e=SSL_get_error(ssl_,r);if(e==SSL_ERROR_ZERO_RETURN){closed_=true;break;}if(e==SSL_ERROR_WANT_READ)break;throw std::runtime_error("Test TLS record verification failed");}
        return out;
    }
    bool closed()const{return closed_;}
    bool negotiating()const{return false;}
    size_t pending_bytes()const{return 0;}
    Bytes take_control(){return output();}
    Bytes close_notify(){int r=SSL_shutdown(ssl_);if(r<0&&SSL_get_error(ssl_,r)!=SSL_ERROR_WANT_READ)throw std::runtime_error("Test TLS shutdown failed");return output();}
};
#endif
}

#include "tls-provider.hpp"
namespace vpn {
#ifdef VPN_CORE_PORTABLE
using NativeTls = ProviderTls;
#endif
class Tls {
    NativeTls native_;std::unique_ptr<ProviderTls> provider_;
public:
    const char* backend()const{return "native TLS + pinned uTLS provider; project-owned proxy protocols";}
    void handshake(Socket& socket,const Config& config,Clock::time_point deadline){bool use=config.security=="xtls"||config.flow=="xtls-rprx-vision"||config.flow=="xtls-rprx-vision-udp443"||config.security=="reality"||!config.ech.empty()||(!config.fingerprint.empty()&&config.fingerprint!="unsafe")||!certificate_pins(config).empty()||!certificate_names(config).empty();if(use){provider_=std::make_unique<ProviderTls>();provider_->handshake(socket,config,deadline);}else native_.handshake(socket,config,deadline);}
    Bytes encrypt(const Bytes& b){return provider_?provider_->encrypt(b):native_.encrypt(b);}
    Bytes feed(const uint8_t* b,size_t n){return provider_?provider_->feed(b,n):native_.feed(b,n);}
    Bytes release_input(){if(!provider_)throw Failure("PROTOCOL_FAILED: Vision provider unavailable","VISION_TLS_PROVIDER");return provider_->release_input();}
    Bytes take_control(){return provider_?provider_->take_control():native_.take_control();}
    Bytes close_notify(){return provider_?provider_->close_notify():native_.close_notify();}
    bool closed()const{return provider_?provider_->closed():native_.closed();}
    bool negotiating()const{return provider_?provider_->negotiating():native_.negotiating();}
    size_t pending_bytes()const{return provider_?provider_->pending_bytes():native_.pending_bytes();}
    const std::string& selected_alpn()const{return provider_?provider_->selected_alpn():native_.selected_alpn();}
    const std::string& version()const{return provider_?provider_->version():native_.version();}
};
}
