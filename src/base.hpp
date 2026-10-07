#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace vpn {
using Bytes = std::vector<uint8_t>;
// Diagnostics contain fixed reason codes and numeric status values, never a URI.
struct Failure : std::runtime_error {
    std::string code,http_header_name; uint32_t native_status=0; unsigned http_status=0;
    Failure(const std::string& message,std::string reason,uint32_t native=0,unsigned http=0,std::string header="")
        :std::runtime_error(message),code(std::move(reason)),http_header_name(std::move(header)),native_status(native),http_status(http){}
};
inline std::string trim(std::string s) {
    auto a = s.find_first_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, s.find_last_not_of(" \t\r\n") - a + 1);
}
inline std::string lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = char(c + ('a' - 'A'));
    return s;
}
inline uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
// Original implementation of the SHA-224 algorithm specified by FIPS 180-4.
// The round constants and initial values are mathematical standard constants.
inline std::string sha224(const std::string& input) {
    static constexpr uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    std::array<uint32_t,8> h = {0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4};
    Bytes data(input.begin(), input.end());
    uint64_t bitlen = uint64_t(data.size()) * 8;
    data.push_back(0x80);
    while (data.size() % 64 != 56) data.push_back(0);
    for (int i = 7; i >= 0; --i) data.push_back(uint8_t(bitlen >> (8 * i)));
    for (size_t offset = 0; offset < data.size(); offset += 64) {
        uint32_t w[64]{};
        for (int i=0;i<16;++i) for (int j=0;j<4;++j) w[i]=(w[i]<<8)|data[offset+4*i+j];
        for (int i=16;i<64;++i) {
            uint32_t a=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
            uint32_t b=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+a+w[i-7]+b;
        }
        auto v=h;
        for (int i=0;i<64;++i) {
            uint32_t t1=v[7]+(rotr(v[4],6)^rotr(v[4],11)^rotr(v[4],25))+((v[4]&v[5])^(~v[4]&v[6]))+k[i]+w[i];
            uint32_t t2=(rotr(v[0],2)^rotr(v[0],13)^rotr(v[0],22))+((v[0]&v[1])^(v[0]&v[2])^(v[1]&v[2]));
            v={t1+t2,v[0],v[1],v[2],v[3]+t1,v[4],v[5],v[6]};
        }
        for (int i=0;i<8;++i) h[i]+=v[i];
    }
    std::ostringstream out;
    out<<std::hex<<std::setfill('0');
    for (int i=0;i<7;++i) out<<std::setw(8)<<h[i];
    return out.str();
}
inline int hex_digit(char c) {
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10;
    return -1;
}
inline std::string percent_decode(const std::string& s) {
    std::string out;
    for(size_t i=0;i<s.size();++i) {
        if(s[i]!='%') { out+=s[i]; continue; }
        if(i+2>=s.size()||hex_digit(s[i+1])<0||hex_digit(s[i+2])<0)throw std::runtime_error("Invalid percent encoding");
        out+=char(hex_digit(s[i+1])*16+hex_digit(s[i+2])); i+=2;
    }
    return out;
}
inline unsigned number(const std::string& s,unsigned min,unsigned max) {
    if(s.empty()||s.size()>9||s.find_first_not_of("0123456789")!=std::string::npos)throw std::runtime_error("Invalid numeric setting");
    unsigned long n=std::stoul(s);
    if(n<min||n>max)throw std::runtime_error("Numeric setting out of range");
    return unsigned(n);
}
inline void check_host(const std::string& s) {
    if(s.empty()||s.size()>253)throw std::runtime_error("Invalid server name");
    for(unsigned char c:s)if(c<=32||c>=127||c=='/'||c=='\\'||c=='@'||c=='%'||c=='?'||c=='#')throw std::runtime_error("Server names must be ASCII; use IDNA/punycode for international names");
}
}
