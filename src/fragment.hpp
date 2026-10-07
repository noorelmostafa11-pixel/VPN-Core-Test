#pragma once
#include "crypto.hpp"

namespace vpn {
struct MaskRange {
    unsigned lo=0,hi=0;
    unsigned choose()const {
        if(lo==hi)return lo;
        // Rejection sampling avoids a modulo bias in the configured range.
        uint32_t width=hi-lo+1,limit=uint32_t(-width)%width,n;
        do{auto b=random_bytes(4);n=uint32_t(b[0])|(uint32_t(b[1])<<8)|(uint32_t(b[2])<<16)|(uint32_t(b[3])<<24);}while(n<limit);
        return lo+n%width;
    }
};
inline MaskRange mask_range(const Json& j,unsigned maximum) {
    if(j.kind==Json::Null)return {};
    if(j.kind==Json::String&&j.text.empty())return {};
    auto s=j.scalar();if(s.empty())throw std::runtime_error("PARSE_INVALID: fragment range must be a number or string");
    auto dash=s.find('-');auto a=number(trim(s.substr(0,dash)),0,maximum);
    auto b=dash==std::string::npos?a:number(trim(s.substr(dash+1)),0,maximum);
    return {std::min(a,b),std::max(a,b)};
}
struct FragmentSpec {
    bool tlshello=false;MaskRange packets,max_split;std::vector<MaskRange> lengths,delays;
};
inline std::vector<FragmentSpec> fragment_specs(const Json& original) {
    Json normalized=original;
    if(original.kind==Json::Object&&original.at("type").scalar()=="fragment"){
        normalized=Json::obj();normalized["tcp"]=Json::arr();normalized["tcp"].array.push_back(original);
    }else if(original.kind==Json::Object&&original.object.size()==1&&original.at("outbounds").kind==Json::Array){
        const auto& outbounds=original.at("outbounds").array;
        if(outbounds.size()!=1||outbounds[0].at("protocol").scalar()!="freedom")throw std::runtime_error("PARSE_INVALID: legacy fragment outbound");
        const auto& outbound=outbounds[0];for(const auto& item:outbound.object)if(item.first!="protocol"&&item.first!="settings"&&item.first!="tag")throw std::runtime_error("FEATURE_UNIMPLEMENTED: legacy fragment outbound option");
        const auto& settings=outbound.at("settings");if(settings.kind!=Json::Object||settings.object.size()!=1||settings.at("fragment").kind!=Json::Object)throw std::runtime_error("PARSE_INVALID: legacy fragment settings");
        Json fragment=Json::obj();fragment["type"]=Json("fragment");fragment["settings"]=settings.at("fragment");auto& legacy=fragment["settings"];if(legacy.object.count("interval")){if(legacy.object.count("delay"))throw std::runtime_error("PARSE_INVALID: duplicate legacy fragment interval");legacy["delay"]=legacy.at("interval");legacy.object.erase("interval");}normalized=Json::obj();normalized["tcp"]=Json::arr();normalized["tcp"].array.push_back(fragment);
    }
    const auto& fm=normalized;
    if(fm.kind==Json::Null)return {};
    if(fm.kind!=Json::Object)throw std::runtime_error("PARSE_INVALID: FinalMask must be an object");
    for(const auto& p:fm.object)if(p.first!="tcp"&&p.first!="udp")throw Failure("PARSE_INVALID: FinalMask root must contain TCP or UDP mask lists","FINALMASK_STRUCTURE_INVALID");
    // UDP masks are inactive for TCP carriers. UDP carriers are checked below.
    if(fm.at("udp").kind!=Json::Null&&fm.at("udp").kind!=Json::Array)throw std::runtime_error("PARSE_INVALID: FinalMask UDP list");
    auto& tcp=fm.at("tcp");if(tcp.kind==Json::Null)return {};
    if(tcp.kind!=Json::Array||tcp.array.size()>8)throw std::runtime_error("PARSE_INVALID: FinalMask TCP list");
    std::vector<FragmentSpec> out;
    for(const auto& item:tcp.array) {
        if(item.kind!=Json::Object||item.at("type").scalar()!="fragment")throw std::runtime_error("FEATURE_UNIMPLEMENTED: FinalMask TCP type");
        for(const auto& p:item.object)if(p.first!="type"&&p.first!="settings")throw std::runtime_error("FEATURE_UNIMPLEMENTED: FinalMask TCP option");
        auto& settings=item.at("settings");if(settings.kind!=Json::Object)throw std::runtime_error("PARSE_INVALID: fragment settings");
        for(const auto& p:settings.object)if(p.first!="packets"&&p.first!="length"&&p.first!="lengths"&&p.first!="delay"&&p.first!="delays"&&p.first!="maxSplit")throw std::runtime_error("FEATURE_UNIMPLEMENTED: fragment option");
        FragmentSpec spec;auto packets=lower(settings.at("packets").scalar());
        if(packets=="tlshello")spec.tlshello=true;
        else if(!packets.empty()){spec.packets=mask_range(Json(packets),1000000);if(!spec.packets.lo)throw std::runtime_error("PARSE_INVALID: fragment packet range starts at zero");}
        auto list=[&](const char* plural,const char* singular,unsigned maximum){std::vector<MaskRange> ranges;auto& j=settings.at(plural);if(j.kind==Json::Array&&!j.array.empty()){if(j.array.size()>64)throw std::runtime_error("PARSE_INVALID: fragment range list limit");for(const auto& x:j.array)ranges.push_back(mask_range(x,maximum));}else{if(j.kind!=Json::Null&&j.kind!=Json::Array)throw std::runtime_error("PARSE_INVALID: fragment range list");ranges.push_back(mask_range(settings.at(singular),maximum));}return ranges;};
        spec.lengths=list("lengths","length",1048576);spec.delays=list("delays","delay",1000);spec.max_split=mask_range(settings.at("maxSplit"),65536);
        if(!spec.lengths.back().lo)throw std::runtime_error("PARSE_INVALID: final fragment length must be positive");
        out.push_back(std::move(spec));
    }
    return out;
}
inline bool supported_finalmask(const Config& c){try{(void)fragment_specs(c.finalmask);bool udp=c.transport=="kcp"||(c.transport=="xhttp"&&std::find(c.alpn.begin(),c.alpn.end(),"h3")!=c.alpn.end());if(udp&&c.finalmask.at("udp").kind==Json::Array&&!c.finalmask.at("udp").array.empty())return false;return true;}catch(const std::exception& e){if(std::string(e.what()).find("FEATURE_UNIMPLEMENTED:")==0)return false;throw;}}
struct WireChunk {Bytes bytes;unsigned delay_after_ms=0;};
// Each stage counts logical writes, including writes produced by earlier stages.
// TLS mode splits the first complete handshake record into new TLS records;
// TCP mode splits writes without changing the bytes. Partial socket writes do
// not advance a stage's counter or regenerate its random decisions.
class FragmentMask {
    std::vector<FragmentSpec> specs_;std::vector<uint64_t> counts_;
    std::vector<WireChunk> split(size_t stage,const Bytes& bytes) {
        auto& spec=specs_[stage];auto count=++counts_[stage];
        bool tls=spec.tlshello;size_t begin=0,end=bytes.size();
        if(tls){if(count!=1||bytes.size()<=5||bytes[0]!=22)return {{bytes,0}};end=5+size_t(bytes[3])*256+bytes[4];if(end>bytes.size())return {{bytes,0}};begin=5;}
        else if(spec.packets.lo&&(count<spec.packets.lo||count>spec.packets.hi))return {{bytes,0}};
        unsigned maximum=spec.max_split.choose();std::vector<WireChunk> out;size_t offset=begin,index=0;bool merge=tls&&spec.delays.size()==1&&spec.delays[0].hi==0;
        do {
            auto length=spec.lengths[std::min(index,spec.lengths.size()-1)].choose();size_t n=std::min(size_t(length),end-offset);
            if(maximum&&index+1>=maximum)n=end-offset;
            WireChunk chunk;auto delay=spec.delays[std::min(index,spec.delays.size()-1)];chunk.delay_after_ms=delay.choose();
            if(tls){chunk.bytes={bytes[0],bytes[1],bytes[2],uint8_t(n>>8),uint8_t(n)};}
            chunk.bytes.insert(chunk.bytes.end(),bytes.begin()+std::ptrdiff_t(offset),bytes.begin()+std::ptrdiff_t(offset+n));
            if(merge&&!out.empty())out[0].bytes.insert(out[0].bytes.end(),chunk.bytes.begin(),chunk.bytes.end());else out.push_back(std::move(chunk));
            offset+=n;++index;if(index>65536)throw std::runtime_error("TRANSPORT_FAILED: fragment count limit");
        }while(offset<end);
        if(end<bytes.size())out.push_back({Bytes(bytes.begin()+std::ptrdiff_t(end),bytes.end()),0});
        return out;
    }
public:
    FragmentMask()=default;explicit FragmentMask(const Config& c):specs_(fragment_specs(c.finalmask)),counts_(specs_.size(),0){}
    bool active()const{return !specs_.empty();}
    std::vector<WireChunk> write(const uint8_t* p,size_t n) {
        std::vector<WireChunk> chunks{{Bytes(p,p+n),0}};
        for(size_t stage=0;stage<specs_.size();++stage){std::vector<WireChunk> next;for(auto& chunk:chunks){auto pieces=split(stage,chunk.bytes);if(!pieces.empty())pieces.back().delay_after_ms+=chunk.delay_after_ms;for(auto& piece:pieces)next.push_back(std::move(piece));if(next.size()>65536)throw std::runtime_error("TRANSPORT_FAILED: fragment count limit");}chunks=std::move(next);}
        return chunks;
    }
};
}
