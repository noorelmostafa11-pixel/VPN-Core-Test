#pragma once
#include "protocol.hpp"
#include <bitset>
#include <chrono>
#include <map>
namespace vpn {
// Returns zero only for incomplete input. All callers bound their input.
inline size_t socks_address_size(const Bytes& b,size_t p=0){
    if(p>=b.size())return 0;
    size_t n=b[p]==1?7:b[p]==4?19:0;
    if(b[p]==3){if(p+2>b.size())return 0;if(!b[p+1])throw Failure("PROTOCOL_FAILED: empty UDP hostname","UDP_ADDRESS");n=size_t(b[p+1])+4;}
    if(!n)throw Failure("PROTOCOL_FAILED: invalid UDP address","UDP_ADDRESS");
    if(p+n>b.size())return 0;
    if(b[p]==3)for(size_t i=p+2;i<p+n-2;++i)if(b[i]<=32||b[i]>=127)throw Failure("PROTOCOL_FAILED: invalid UDP hostname","UDP_ADDRESS");
    if(b[p+n-2]==0&&b[p+n-1]==0)throw Failure("PROTOCOL_FAILED: zero UDP destination port","UDP_PORT");
    return n;
}
struct Datagram {Bytes address,payload;};
class UdpStreamCodec {
    const Config& config_;Bytes address_,input_;size_t maximum_payload_;
public:
    // Legacy SOCKS keeps its IPv4-carrier bound by default. Native IPv6
    // endpoints explicitly select their standard payload limit; wire framing,
    // protocol authentication and the old path's validation remain identical.
    UdpStreamCodec(const Config& config,Bytes address,size_t maximum_payload=65507):config_(config),address_(std::move(address)),maximum_payload_(maximum_payload){
        if((maximum_payload_!=65507&&maximum_payload_!=65527)||(maximum_payload_==65527&&(address_.empty()||address_[0]!=4)))throw Failure("PROTOCOL_FAILED: UDP family limit","UDP_DATAGRAM_LENGTH");
    }
    Bytes encode(Protocol& protocol,const Bytes& payload){
        if(config_.protocol=="vmess"&&payload.empty())throw Failure("PROTOCOL_FAILED: VMess empty packet means EOF","VMESS_UDP_EMPTY");
        if(payload.size()>maximum_payload_)throw Failure("PROTOCOL_FAILED: UDP packet too large","UDP_DATAGRAM_LENGTH");
        if(config_.protocol=="vmess")return protocol.encode_datagram(payload);
        Bytes b;if(config_.protocol=="trojan")append(b,address_);be16(b,payload.size());
        if(config_.protocol=="trojan")append(b,Bytes{13,10});append(b,payload);return protocol.encode(b);
    }
    std::vector<Datagram> decode(Protocol& protocol,const Bytes& wire){
        auto plain=protocol.decode(wire);std::vector<Datagram> out;
        if(config_.protocol=="vmess"){for(auto& b:protocol.take_datagrams())out.push_back({address_,std::move(b)});return out;}
        append(input_,plain);if(input_.size()>262144)throw Failure("PROTOCOL_FAILED: UDP stream buffer","UDP_BUFFER_LIMIT");
        for(;;){size_t prefix=0;Bytes address=address_;
            if(config_.protocol=="trojan"){prefix=socks_address_size(input_);if(!prefix)break;address=Bytes(input_.begin(),input_.begin()+std::ptrdiff_t(prefix));}
            auto extra=config_.protocol=="trojan"?4u:2u;if(input_.size()<prefix+extra)break;
            auto n=get16(input_,prefix);if(n>maximum_payload_)throw Failure("PROTOCOL_FAILED: UDP response length","UDP_DATAGRAM_LENGTH");
            if(extra==4&&(input_[prefix+2]!=13||input_[prefix+3]!=10))throw Failure("PROTOCOL_FAILED: Trojan UDP delimiter","TROJAN_UDP_DELIMITER");
            if(input_.size()<prefix+extra+n)break;consume(input_,prefix+extra);out.push_back({std::move(address),consume(input_,n)});
        }return out;
    }
};
struct UdpReplayWindow {
    uint64_t maximum=0;bool initialized=false;std::bitset<2048> seen;
    void accept(uint64_t id){
        if(!initialized){maximum=id;initialized=true;seen.set(0);return;}
        if(id>maximum){auto delta=id-maximum;if(delta>=seen.size())seen.reset();else seen<<=size_t(delta);maximum=id;seen.set(0);return;}
        auto delta=maximum-id;if(delta>=seen.size()||seen.test(size_t(delta)))throw Failure("PROTOCOL_FAILED: replayed UDP packet","SS_UDP_REPLAY");seen.set(size_t(delta));
    }
};
class ShadowsocksUdp {
    const Config& c_;SsCipherSpec spec_;bool modern_;std::vector<Bytes> keys_;Bytes master_,session_;uint64_t counter_=0;
    struct Session {UdpReplayWindow replay;std::chrono::steady_clock::time_point last;};
    std::map<std::string,Session> sessions_;std::deque<std::string> salts_;
    std::string cipher()const {auto name=modern_?c_.cipher.substr(12):c_.cipher;return name=="chacha20-poly1305"?"chacha20-ietf-poly1305":name;}
    Bytes subkey(const Bytes& salt)const{if(!modern_)return hkdf_sha1(master_,salt,to_bytes("ss-subkey"),spec_.key);auto material=master_;append(material,salt);return first(blake3_derive("shadowsocks 2022 session subkey",material),spec_.key);}
    Bytes stream(const Bytes& input,const Bytes& iv,bool decrypt){
        if(c_.cipher.find("aes-")==0){AesCfb cipher;cipher.start(master_,iv,c_.cipher.substr(8));return cipher.apply(input,decrypt);}
        SsStreamCipher cipher;cipher.start(c_.cipher,master_,iv,decrypt);return cipher.apply(input);
    }
public:
    explicit ShadowsocksUdp(const Config& c):c_(c),spec_(ss_cipher_spec(c.cipher)),modern_(c.cipher.find("2022-blake3-")==0){
        if(modern_){keys_=ss2022_keys(c);master_=keys_.back();session_=random_bytes(8);}else master_=ss_master(c.password,spec_.key);
    }
    Bytes encode(const Datagram& packet){
        Bytes body=packet.address;append(body,packet.payload);Bytes wire;
        if(c_.cipher=="none"||c_.cipher=="plain")wire=body;
        else if(spec_.stream){auto iv=random_bytes(spec_.iv);wire=iv;append(wire,stream(body,iv,false));}
        else if(!modern_){auto salt=random_bytes(spec_.key);wire=salt;append(wire,aead(cipher(),subkey(salt),Bytes(spec_.iv),body));}
        else{
            if(counter_==UINT64_MAX)throw Failure("PROTOCOL_FAILED: UDP counter exhausted","SS_UDP_COUNTER");
            Bytes separate=session_;be64(separate,counter_++);Bytes main{0};be64(main,uint64_t(std::time(nullptr)));be16(main,0);append(main,body);
            if(cipher()=="chacha20-ietf-poly1305"){append(separate,main);wire=random_bytes(24);append(wire,aead("xchacha20-ietf-poly1305",master_,wire,separate));}
            else{wire=aes(keys_.front(),{},separate,{},false,true);
                for(size_t i=0;i+1<keys_.size();++i){auto identity=first(blake3_short_hash(keys_[i+1]),16);for(size_t j=0;j<16;++j)identity[j]^=separate[j];append(wire,aes(keys_[i],{},identity,{},false,true));}
                Bytes nonce(separate.begin()+4,separate.end());append(wire,aead(cipher(),subkey(session_),nonce,main));}
        }
        if(wire.size()>65507)throw Failure("PROTOCOL_FAILED: encrypted UDP packet too large","UDP_DATAGRAM_LENGTH");return wire;
    }
    Datagram decode(const Bytes& wire){
        Bytes body;std::string replay_salt;Bytes server_session;uint64_t id=0;
        if(c_.cipher=="none"||c_.cipher=="plain")body=wire;
        else if(spec_.stream){if(wire.size()<spec_.iv)throw Failure("PROTOCOL_FAILED: UDP IV truncated","SS_UDP_TRUNCATED");body=stream(Bytes(wire.begin()+std::ptrdiff_t(spec_.iv),wire.end()),first(wire,spec_.iv),true);}
        else if(!modern_){if(wire.size()<spec_.key+16)throw Failure("PROTOCOL_FAILED: UDP salt truncated","SS_UDP_TRUNCATED");auto salt=first(wire,spec_.key);body=aead(cipher(),subkey(salt),Bytes(spec_.iv),Bytes(wire.begin()+std::ptrdiff_t(spec_.key),wire.end()),{},true);replay_salt=hex_bytes(salt);}
        else{
            Bytes separate;
            if(cipher()=="chacha20-ietf-poly1305"){if(wire.size()<40)throw Failure("PROTOCOL_FAILED: UDP nonce truncated","SS_UDP_TRUNCATED");auto plain=aead("xchacha20-ietf-poly1305",master_,first(wire,24),Bytes(wire.begin()+24,wire.end()),{},true);if(plain.size()<16)throw Failure("PROTOCOL_FAILED: UDP header truncated","SS_UDP_TRUNCATED");separate=consume(plain,16);body=std::move(plain);}
            else{if(wire.size()<32)throw Failure("PROTOCOL_FAILED: UDP header truncated","SS_UDP_TRUNCATED");separate=aes(master_,{},first(wire,16),{},true,true);server_session=first(separate,8);body=aead(cipher(),subkey(server_session),Bytes(separate.begin()+4,separate.end()),Bytes(wire.begin()+16,wire.end()),{},true);}
            server_session=first(separate,8);id=get64(separate,8);
            if(equal_bytes(server_session,session_)||body.size()<19||body[0]!=1)throw Failure("PROTOCOL_FAILED: UDP response type","SS_UDP_RESPONSE_TYPE");
            auto timestamp=get64(body,1),now=uint64_t(std::time(nullptr));if(timestamp>now+30||now>timestamp+30)throw Failure("PROTOCOL_FAILED: UDP timestamp","SS_UDP_TIMESTAMP");
            if(!equal_bytes(Bytes(body.begin()+9,body.begin()+17),session_))throw Failure("PROTOCOL_FAILED: UDP session mismatch","SS_UDP_SESSION");
            auto padding=get16(body,17);if(body.size()<19+padding)throw Failure("PROTOCOL_FAILED: UDP padding truncated","SS_UDP_TRUNCATED");consume(body,19+padding);
        }
        auto n=socks_address_size(body);if(!n)throw Failure("PROTOCOL_FAILED: UDP address truncated","SS_UDP_TRUNCATED");Datagram packet{consume(body,n),std::move(body)};
        // Only authenticated, fully validated responses update replay state.
        if(modern_){auto key=hex_bytes(server_session);auto now=std::chrono::steady_clock::now();
            if(!sessions_.count(key)){for(auto it=sessions_.begin();it!=sessions_.end();)if(now-it->second.last>std::chrono::seconds(60))it=sessions_.erase(it);else ++it;
                if(sessions_.size()>=64)throw Failure("PROTOCOL_FAILED: UDP server session limit","SS_UDP_SESSION_LIMIT");}
            auto& session=sessions_[key];session.replay.accept(id);session.last=now;
        }else if(!replay_salt.empty()){if(std::find(salts_.begin(),salts_.end(),replay_salt)!=salts_.end())throw Failure("PROTOCOL_FAILED: replayed UDP salt","SS_UDP_REPLAY");salts_.push_back(replay_salt);if(salts_.size()>4096)salts_.pop_front();}
        return packet;
    }
};
}
