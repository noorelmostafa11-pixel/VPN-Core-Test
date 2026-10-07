#pragma once
#include "crypto.hpp"

namespace vpn {
inline bool vision_flow(const Config& c){return c.flow=="xtls-rprx-vision"||c.flow=="xtls-rprx-vision-udp443";}

class Vision {
    const Config& config_;Bytes input_,hello_,handshake_;bool enabled_,prefix_=true,writing_done_=false,reading_done_=false,direct_=false,tls13_=false,probe_done_=false;unsigned command_=0;size_t content_=0,padding_=0;bool need_header_=true;
    static size_t word(const Bytes& b,size_t p){return size_t(b[p])*256+b[p+1];}
    static Bytes pop(Bytes& b,size_t n){Bytes out(b.begin(),b.begin()+std::ptrdiff_t(n));b.erase(b.begin(),b.begin()+std::ptrdiff_t(n));return out;}
    static void length(Bytes& b,size_t n){b.push_back(uint8_t(n>>8));b.push_back(uint8_t(n));}
    Bytes frame(unsigned command,const Bytes& data,bool first){auto padding=random_bytes(first?900+random_bytes(1)[0]:1+random_bytes(1)[0]);Bytes out;if(first)out.insert(out.end(),config_.uuid.begin(),config_.uuid.end());out.push_back(uint8_t(command));length(out,data.size());length(out,padding.size());out.insert(out.end(),data.begin(),data.end());out.insert(out.end(),padding.begin(),padding.end());return out;}
    void probe(const Bytes& data){
        if(probe_done_||data.empty())return;
        if(hello_.size()+handshake_.size()+data.size()>32768){probe_done_=true;hello_.clear();handshake_.clear();return;}
        hello_.insert(hello_.end(),data.begin(),data.end());
        while(hello_.size()>=5){
            auto n=word(hello_,3);if(hello_[0]!=22||hello_[1]!=3||hello_[2]!=3||n>16384){probe_done_=true;hello_.clear();handshake_.clear();return;}
            if(hello_.size()<n+5)return;
            handshake_.insert(handshake_.end(),hello_.begin()+5,hello_.begin()+std::ptrdiff_t(n+5));pop(hello_,n+5);
            if(handshake_.size()<4)continue;
            const auto& b=handshake_;auto handshake=size_t(b[1])*65536+size_t(b[2])*256+b[3];
            if(b[0]!=2||handshake<38||handshake>32764){probe_done_=true;hello_.clear();handshake_.clear();return;}
            if(b.size()<handshake+4)continue;
            auto end=handshake+4;size_t p=38;auto sid=b[p++];
            if(p+sid+5>end){probe_done_=true;hello_.clear();handshake_.clear();return;}
            p+=sid;auto cipher=word(b,p);p+=3;auto ext=word(b,p);p+=2;
            if(p+ext!=end){probe_done_=true;hello_.clear();handshake_.clear();return;}
            while(p<end){if(p+4>end)break;auto kind=word(b,p),size=word(b,p+2);p+=4;if(p+size>end)break;if(kind==43&&size==2&&word(b,p)==0x0304&&cipher>=0x1301&&cipher<=0x1304)tls13_=true;p+=size;}
            probe_done_=true;hello_.clear();handshake_.clear();return;
        }
    }

public:
    explicit Vision(const Config& c):config_(c),enabled_(vision_flow(c)){}
    Bytes initial_padding(){return enabled_?frame(0,{},true):Bytes{};}
    Bytes encode(const Bytes& data){if(!enabled_||writing_done_||data.empty())return data;if(data.size()>65535)throw Failure("PROTOCOL_FAILED: Vision payload length","VISION_LENGTH");writing_done_=true;return frame(1,data,false);}
    bool take_direct(){return std::exchange(direct_,false);}
    Bytes decode(const Bytes& data){
        if(!enabled_||reading_done_)return data;
        if(input_.size()+data.size()>262144)throw Failure("PROTOCOL_FAILED: Vision input limit","VISION_LIMIT");input_.insert(input_.end(),data.begin(),data.end());Bytes out;
        if(prefix_){auto n=std::min(input_.size(),size_t(16));if(!std::equal(input_.begin(),input_.begin()+std::ptrdiff_t(n),config_.uuid.begin())){reading_done_=true;return std::exchange(input_,{});}if(input_.size()<16)return {};pop(input_,16);prefix_=false;}
        for(;;){
            if(need_header_){if(input_.size()<5)break;command_=input_[0];if(command_>2)throw Failure("PROTOCOL_FAILED: Vision command","VISION_COMMAND");content_=word(input_,1);padding_=word(input_,3);pop(input_,5);need_header_=false;}
            if(content_){auto n=std::min(content_,input_.size());auto part=pop(input_,n);probe(part);out.insert(out.end(),part.begin(),part.end());content_-=n;if(content_)break;}
            if(padding_){auto n=std::min(padding_,input_.size());pop(input_,n);padding_-=n;if(padding_)break;}
            if(command_==0){need_header_=true;continue;}
            if(command_==2){if(!tls13_||config_.transport!="raw")throw Failure("PROTOCOL_FAILED: Vision direct requires inner TLS 1.3 and raw carrier","VISION_DIRECT_SECURITY");direct_=true;}
            reading_done_=true;out.insert(out.end(),input_.begin(),input_.end());input_.clear();break;
        }
        return out;
    }
};
}
