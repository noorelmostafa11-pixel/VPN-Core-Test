#pragma once
#include "crypto.hpp"
namespace vpn {
// BLAKE3 compression, independently written from the BLAKE3 specification.
// These bounded one-chunk operations are used only for SS2022 PSKs, salts,
// identity hashes and context strings (all <= 1024 bytes).
inline Bytes blake3_chunk(const Bytes& input,const std::array<uint32_t,8>& key,uint32_t mode){
    if(input.size()>1024)throw std::runtime_error("CRYPTO_FAILED: BLAKE3 one-chunk input limit");
    constexpr std::array<uint32_t,8> iv{{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}};
    constexpr std::array<unsigned,16> permutation{{2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8}};
    auto cv=key;size_t blocks=std::max(size_t(1),(input.size()+63)/64);
    for(size_t block=0;block<blocks;++block){size_t offset=block*64,length=offset<input.size()?std::min(size_t(64),input.size()-offset):0;Bytes bytes(64);if(length)std::copy_n(input.data()+offset,length,bytes.data());std::array<uint32_t,16> message{},state{};for(unsigned i=0;i<16;++i)message[i]=little32(bytes.data()+4*i);std::copy(cv.begin(),cv.end(),state.begin());std::copy_n(iv.begin(),4,state.begin()+8);state[14]=uint32_t(length);state[15]=mode|(block==0?1u:0u)|(block+1==blocks?2u|8u:0u);
        auto mix=[&](unsigned a,unsigned b,unsigned c,unsigned d,uint32_t x,uint32_t y){state[a]+=state[b]+x;state[d]=rotate_left(state[d]^state[a],16);state[c]+=state[d];state[b]=rotate_left(state[b]^state[c],20);state[a]+=state[b]+y;state[d]=rotate_left(state[d]^state[a],24);state[c]+=state[d];state[b]=rotate_left(state[b]^state[c],25);};
        for(unsigned round=0;round<7;++round){mix(0,4,8,12,message[0],message[1]);mix(1,5,9,13,message[2],message[3]);mix(2,6,10,14,message[4],message[5]);mix(3,7,11,15,message[6],message[7]);mix(0,5,10,15,message[8],message[9]);mix(1,6,11,12,message[10],message[11]);mix(2,7,8,13,message[12],message[13]);mix(3,4,9,14,message[14],message[15]);auto prior=message;for(unsigned i=0;i<16;++i)message[i]=prior[permutation[i]];}
        for(unsigned i=0;i<8;++i)cv[i]=state[i]^state[i+8];
    }
    Bytes output(32);for(unsigned i=0;i<8;++i)put_little32(output.data()+4*i,cv[i]);return output;
}
inline constexpr std::array<uint32_t,8> blake3_iv{{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}};
inline Bytes blake3_short_hash(const Bytes& input){return blake3_chunk(input,blake3_iv,0);}
inline Bytes blake3_derive(const std::string& context,const Bytes& material){auto context_key=blake3_chunk(to_bytes(context),blake3_iv,32);std::array<uint32_t,8> key{};for(unsigned i=0;i<8;++i)key[i]=little32(context_key.data()+4*i);return blake3_chunk(material,key,64);}
}
