#pragma once
namespace vpn {
// A connection owns one TCP substream. Mux concurrency is an upper bound;
// opening a separate carrier for each SOCKS request preserves isolation.
class MuxCool {
    Bytes input_;bool opened_=false,closed_=false,ended_=false;const Config& c_;
    Bytes frame(uint8_t status,const Bytes& data){Bytes metadata{0,1,status,uint8_t(data.empty()?0:1)};if(status==1){metadata.push_back(1);be16(metadata,c_.port);std::array<uint8_t,16> ip{};if(inet_pton(AF_INET,c_.server.c_str(),ip.data())==1){metadata.push_back(1);metadata.insert(metadata.end(),ip.begin(),ip.begin()+4);}else if(inet_pton(AF_INET6,c_.server.c_str(),ip.data())==1){metadata.push_back(3);metadata.insert(metadata.end(),ip.begin(),ip.end());}else{metadata.push_back(2);metadata.push_back(uint8_t(c_.server.size()));append(metadata,to_bytes(c_.server));}}Bytes out;be16(out,metadata.size());append(out,metadata);if(!data.empty()){be16(out,data.size());append(out,data);}return out;}
public:
    explicit MuxCool(const Config& c):c_(c){}
    Bytes encode(const Bytes& data){if(ended_)throw Failure("TRANSPORT_FAILED: mux write after end","MUX_WRITE_AFTER_END");Bytes out;for(size_t offset=0;offset<data.size();){size_t n=std::min(size_t(16384),data.size()-offset);Bytes part(data.begin()+std::ptrdiff_t(offset),data.begin()+std::ptrdiff_t(offset+n));append(out,frame(opened_?2:1,part));opened_=true;offset+=n;}return out;}
    Bytes finish(){if(ended_)return {};ended_=true;return opened_?frame(3,{}):Bytes{};}
    bool closed()const{return closed_;}
    Bytes decode(const Bytes& wire){append(input_,wire);if(input_.size()>1048576)throw Failure("TRANSPORT_FAILED: mux input limit","MUX_BUFFER_LIMIT");Bytes out;for(;;){if(input_.size()<2)break;size_t length=get16(input_);if(length<4||length>512)throw Failure("TRANSPORT_FAILED: mux metadata length","MUX_METADATA");if(input_.size()<length+2)break;auto id=get16(input_,2);auto status=input_[4],options=input_[5];if(status<2||status>4||options&~3u||(options&2u&&status!=3))throw Failure("TRANSPORT_FAILED: invalid mux response","MUX_METADATA");size_t data_length=0,total=length+2;if(options&1){if(input_.size()<total+2)break;data_length=get16(input_,total);total+=2+data_length;}if(input_.size()<total)break;if(status!=4&&id!=1)throw Failure("TRANSPORT_FAILED: unknown mux session","MUX_SESSION");if(status!=4){if(closed_)throw Failure("TRANSPORT_FAILED: mux bytes after end","MUX_AFTER_END");if(options&2)throw Failure("TRANSPORT_FAILED: remote mux error","MUX_REMOTE_ERROR");if(data_length)out.insert(out.end(),input_.begin()+std::ptrdiff_t(total-data_length),input_.begin()+std::ptrdiff_t(total));if(status==3)closed_=true;}consume(input_,total);}return out;}
};
}
