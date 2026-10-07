// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
#pragma once
#include "provider-module.hpp"
namespace vpn {
struct PortableCrypto {
    int(*random)(char*,int)=nullptr;
    int(*hash)(int,char*,int,char*,int)=nullptr;
    int(*cipher)(char*,int,char*,int,char*,int,char*,int,int,int,char*,int)=nullptr;
    PortableCrypto(){auto& m=ProviderModule::instance();m.symbol(random,"vpn_crypto_random");m.symbol(hash,"vpn_crypto_digest");m.symbol(cipher,"vpn_crypto_aes");}
    static PortableCrypto& instance(){static PortableCrypto p;return p;}
    static char* data(const Bytes& b){return reinterpret_cast<char*>(const_cast<uint8_t*>(b.data()));}
    static int size(size_t n){if(n>1048576)throw Failure("CRYPTO_FAILED: input limit","CRYPTO_INPUT_LIMIT");return int(n);}
};
}
