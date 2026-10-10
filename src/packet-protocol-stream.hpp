#pragma once
#include "transport.hpp"
#include "xhttp-provider.hpp"
namespace vpn {
class PacketProtocolStream {
    const Config& config_;
    Socket server_;
    SecureStream tls_;
    Transport transport_;
    Protocol protocol_;
    XHttpStream provider_;
    Queue up_;
    Bytes down_,pending_;
    bool provider_path_,upload_closed_=false,finished_=false,eof_=false;
    void decode(const Bytes& wire) {
        auto plain=protocol_.decode(provider_path_?wire:transport_.decode(wire));
        if(protocol_.take_direct()) {
            if(provider_path_)throw Failure("PROTOCOL_FAILED: Vision provider bypass","VISION_DIRECT_SECURITY");
            auto held=tls_.switch_direct_receive();auto direct=protocol_.decode(transport_.decode(held));append(plain,direct);
        }
        if(down_.size()+plain.size()>524288)throw Failure("RELAY_FAILED: stack receive buffer","NETSTACK_BUFFER_LIMIT");
        append(down_,plain);
        auto control=protocol_.take_control();
        if(provider_path_)append(pending_,control);
        else {
            up_.append(tls_.take_control());
            if(!control.empty()&&tls_.write_open())up_.append(tls_.encrypt(transport_.encode(control)));
            auto carrier_control=transport_.take_control();
            if(!carrier_control.empty()&&tls_.write_open())up_.append(tls_.encrypt(carrier_control));
        }
    }
public:
    PacketProtocolStream(const Config& c,const Bytes& destination,const char** phase=nullptr):config_(c),transport_(c),protocol_(c),provider_path_(c.transport=="xhttp"||c.transport=="http"||c.transport=="kcp"||c.transport=="quic") {
        auto deadline=Clock::now()+std::chrono::milliseconds(c.connect_ms);
        if(provider_path_){if(phase)*phase="TRANSPORT";provider_.open(c,protocol_.open(destination),deadline);return;}
        if(phase)*phase="CONNECT";server_=connect_server(c,deadline);
        if(phase)*phase="TLS";tls_.handshake(server_,c,deadline);Bytes header;
        if(phase)*phase="PROTOCOL";
        if(c.transport=="websocket"&&c.ws_early_data)header=transport_.prepare(protocol_.open(destination));
        if(phase)*phase="TRANSPORT";auto initial=transport_.open(server_,tls_,deadline,header.empty()?nullptr:&header);
        if(phase)*phase="PROTOCOL";
        if(c.transport=="websocket"&&c.ws_early_data){if(!header.empty())send_secure(server_,tls_,transport_.encode_prepared(header),deadline);}
        else send_secure(server_,tls_,transport_.encode(protocol_.open(destination)),deadline);
        decode(initial);
    }
    bool write(const Bytes& plain) {
        if(upload_closed_)throw Failure("RELAY_FAILED: upload closed","NETSTACK_WRITE_CLOSED");
        if(up_.size()+pending_.size()+tls_.pending_bytes()+transport_.pending_bytes()+protocol_.pending_bytes()+plain.size()>524288)return false;
        auto wire=protocol_.encode(plain);
        if(provider_path_)append(pending_,wire);else up_.append(tls_.encrypt(transport_.encode(wire)));
        return true;
    }
    void finish_upload() {
        if(upload_closed_)return;
        upload_closed_=true;auto final=protocol_.finish();
        if(provider_path_)append(pending_,final);else if(!final.empty())up_.append(tls_.encrypt(transport_.encode(final)));
    }
    const Bytes& received()const noexcept{return down_;}
    void consume(size_t n){if(n>down_.size())throw std::logic_error("receive accounting");down_.erase(down_.begin(),down_.begin()+std::ptrdiff_t(n));}
    bool eof()const noexcept{return eof_;}
    bool upload_drained(){return upload_closed_&&finished_&&up_.empty()&&pending_.empty()&&!protocol_.pending_bytes();}
    Handle carrier_handle()const noexcept{return provider_path_?invalid_socket:server_.get();}
    bool poll() {
        check_cancelled();bool progress=false;const auto before_down=down_.size(),before_up=up_.size(),before_pending=pending_.size();const bool before_eof=eof_;
        if(provider_path_) {
            if(down_.size()<524288-65536)decode(provider_.read());
            if(!pending_.empty()&&provider_.write(pending_))pending_.clear();
            if(upload_closed_&&!finished_&&pending_.empty()&&!protocol_.pending_bytes()){provider_.finish();finished_=true;}
            eof_=provider_.closed()||protocol_.closed();return down_.size()!=before_down||pending_.size()!=before_pending||eof_!=before_eof;
        }
        if(down_.size()<524288-65536)decode(tls_.feed(nullptr,0));
        if(upload_closed_&&!finished_&&!protocol_.pending_bytes()) {
            auto final=transport_.finish();if(!final.empty())up_.append(tls_.encrypt(final));
            if((config_.transport=="raw"||config_.transport=="httpupgrade"||config_.transport=="obfs-http"||config_.transport=="obfs-tls")&&tls_.secure())up_.append(tls_.close_notify());
            finished_=true;
        }
        if(!up_.empty())up_.flush(server_);
        if(finished_&&up_.empty()&&!tls_.secure()&&(config_.transport=="raw"||config_.transport=="httpupgrade")) {
#ifdef _WIN32
            shutdown(server_.get(),SD_SEND);
#else
            shutdown(server_.get(),SHUT_WR);
#endif
        }
        // Re-check capacity before EVERY socket read in this bounded batch.
        // A fast peer can fill the queue before all 16 reads are consumed.
        if(!eof_)for(unsigned i=0;i<16&&down_.size()<524288-65536;++i) {
            uint8_t b[16384];int n=server_.receive(b,sizeof(b));if(n==-2)break;
            if(n==0){eof_=true;if(tls_.secure()&&!tls_.direct_receive()&&!tls_.closed())throw Failure("TLS_FAILED: truncated stream","TLS_TRUNCATED");break;}
            progress=true;decode(tls_.feed(b,size_t(n)));
        }
        eof_=eof_||tls_.closed()||transport_.closed()||protocol_.closed();
        return progress||down_.size()!=before_down||up_.size()!=before_up||eof_!=before_eof;
    }
};

}
