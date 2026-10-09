// Component probe: production parser, transport and TLS adapters, no core main.
#include "../src/protocol.hpp"
#include "../src/transport.hpp"
#include <iostream>

using namespace vpn;
void require(bool value,const char* text){if(!value)throw std::runtime_error(text);}
Bytes final_payload(){std::string text;for(unsigned i=0;i<2048;++i)text+="authenticated final payload|";return to_bytes(text);}
void wire_send(Socket& socket,const Bytes& wire,Clock::time_point deadline){send_all(socket,wire.data(),wire.size(),deadline);}
Bytes until_closed(Socket& socket,SecureStream& tls,Clock::time_point deadline){
    Bytes plain;
    while(Clock::now()<deadline){
        append(plain,tls.feed(nullptr,0));
        if(tls.closed())return plain;
        fd_set reads;FD_ZERO(&reads);FD_SET(socket.get(),&reads);timeval timeout{0,1000};
        auto result=select(int(socket.get()+1),&reads,nullptr,nullptr,&timeout);
        if(result<0)throw std::runtime_error("probe socket wait failed");
        if(result){auto data=receive_some(socket,deadline);require(!data.empty(),"unauthenticated TCP EOF is not TLS closure");append(plain,tls.feed(data.data(),data.size()));}
    }
    throw std::runtime_error("authenticated TLS closure did not arrive");
}
void rejected_write(SecureStream& tls){bool rejected=false;try{(void)tls.encrypt(to_bytes("forbidden late application data"));}catch(const Failure&){rejected=true;}require(rejected,"late TLS application write was accepted");}
void direct_api_close(Socket& socket,const Config& config,Clock::time_point deadline){
    auto& api=TlsProviderAPI::instance();auto settings=json_dump(provider_settings(config));auto id=api.create(settings.data(),int(settings.size()));require(id!=0,"provider session allocation failed");
    struct Release {TlsProviderAPI& api;uint64_t id;~Release(){api.free(id);}} release{api,id};
    auto drain=[&](int kind){Bytes result;char data[65536];for(;;){auto n=api.read(id,kind,data,sizeof(data));require(n>=0,"provider output failure");if(!n)return result;result.insert(result.end(),data,data+n);}};
    auto feed_socket=[&]{fd_set reads;FD_ZERO(&reads);FD_SET(socket.get(),&reads);timeval timeout{0,1000};auto count=select(int(socket.get()+1),&reads,nullptr,nullptr,&timeout);require(count>=0,"provider probe socket wait failed");if(count){auto data=receive_some(socket,deadline);require(!data.empty(),"provider received unauthenticated EOF");require(api.feed(id,reinterpret_cast<char*>(data.data()),int(data.size()))==int(data.size()),"provider input failed");}};
    while(api.state(id)==0&&Clock::now()<deadline){wire_send(socket,drain(0),deadline);feed_socket();}
    require(api.state(id)==1,"provider handshake did not finish");wire_send(socket,drain(0),deadline);
    require(api.shutdown(id)==0,"provider local shutdown failed");wire_send(socket,drain(0),deadline);
    char late[]="forbidden late data";require(api.write(id,late,sizeof(late)-1)==-1,"provider C ABI accepted writing after local shutdown");
    require(api.state(id)>=1,"rejecting the C ABI late write poisoned the remaining read direction");
    Bytes received;
    while(Clock::now()<deadline){append(received,drain(1));if(api.state(id)==2)break;require(api.state(id)>=1,"provider read direction failed after local shutdown");feed_socket();}
    append(received,drain(1));require(api.state(id)==2&&received==final_payload(),"provider C ABI lost final data after a rejected local write");
    require(api.shutdown(id)==0,"provider repeated shutdown was not idempotent");require(api.write(id,late,sizeof(late)-1)==-1,"peer closure revived local writes");
}
int main(int argc,char** argv){try{
    require(argc==3,"expected probe mode and original URI");[[maybe_unused]] NetworkRuntime runtime;
    std::string mode=argv[1],input=argv[2];Config c;if(input.find("://")!=std::string::npos)parse_uri(c,input);else c=read_config(input);require(missing_features(c).empty(),"unsupported fixture configuration");
    if(mode=="host"){std::cout<<http_host(c)<<'\n';return 0;}
    auto deadline=Clock::now()+std::chrono::seconds(10);auto socket=connect_server(c,deadline);
    if(mode=="direct-api-close"){direct_api_close(socket,c,deadline);std::cout<<"PASS: direct provider C ABI local closure\n";return 0;}
    SecureStream tls;tls.handshake(socket,c,deadline);
    require(tls.write_open(),"completed TLS handshake has no writing direction");
    if(mode=="upgrade"){
        Transport transport(c);Protocol protocol(c);auto initial=transport.open(socket,tls,deadline);
        auto destination=to_bytes(std::string("\3\14",2)+"example.test"+std::string("\1\273",2));
        send_secure(socket,tls,transport.encode(protocol.open(destination)),deadline);
        const auto greeting=to_bytes("SERVER-FIRST: independent peer\n");Bytes received=protocol.decode(transport.decode(initial));
        while(received.size()<greeting.size()){auto data=receive_some(socket,deadline);require(!data.empty(),"upgrade closed before greeting");append(received,protocol.decode(transport.decode(tls.feed(data.data(),data.size()))));wire_send(socket,tls.take_control(),deadline);auto control=transport.take_control();if(!control.empty())send_secure(socket,tls,control,deadline);}
        require(received==greeting,"authenticated upgraded data changed");
        auto payload=to_bytes(std::string(32000,'x'));send_secure(socket,tls,transport.encode(protocol.encode(payload)),deadline);received.clear();
        while(received.size()<payload.size()){auto data=receive_some(socket,deadline);require(!data.empty(),"upgrade closed before echo");append(received,protocol.decode(transport.decode(tls.feed(data.data(),data.size()))));wire_send(socket,tls.take_control(),deadline);auto control=transport.take_control();if(!control.empty())send_secure(socket,tls,control,deadline);}
        require(received==payload,"REALITY upgraded data was lost");
    }else if(mode=="peer-close"||mode=="websocket-close"){
        auto received=until_closed(socket,tls,deadline);Transport transport(c);
        require((mode=="websocket-close"?transport.decode(received):received)==final_payload(),"data preceding close_notify was lost");
        bool modern=tls.version()=="TLS1.3"||tls.version()=="TLSv1.3";
        require(tls.write_open()==modern,"peer read closure has incorrect write policy");
        if(modern){auto control=mode=="websocket-close"?transport.take_control():to_bytes("required final control");require(!control.empty(),"required final transport control is missing");send_secure(socket,tls,control,deadline);}else rejected_write(tls);
        wire_send(socket,tls.close_notify(),deadline);require(!tls.write_open(),"local closure left writes enabled");rejected_write(tls);
    }else if(mode=="local-close"){
        wire_send(socket,tls.close_notify(),deadline);require(!tls.write_open(),"local closure left writes enabled");rejected_write(tls);
        require(tls.close_notify().empty(),"repeated close_notify emitted another close");
        require(until_closed(socket,tls,deadline)==final_payload(),"rejecting a local late write damaged the remaining read direction");
        require(!tls.write_open(),"peer closure revived a locally closed writing direction");rejected_write(tls);
    }else if(mode=="bad-record"){
        bool rejected=false;std::string observed;try{(void)until_closed(socket,tls,deadline);}catch(const Failure& f){observed=f.code;rejected=f.code=="TLS_PROVIDER_RECORD"||f.code=="TLS_RECORD_VERIFY"||(f.code=="TLS_ALERT"&&f.native_status==318);}
        // The independent OpenSSL test adapter reports std::runtime_error.
        catch(const std::runtime_error& e){observed=e.what();rejected=observed=="Test TLS record verification failed";}
        if(!rejected)throw std::runtime_error("corrupted TLS record did not produce the required record failure: "+observed);require(!tls.write_open(),"TLS error left writes enabled");rejected_write(tls);
    }else throw std::runtime_error("unknown component probe mode");
    std::cout<<"PASS: "<<mode<<" "<<tls.version()<<'\n';return 0;
}catch(const Failure& f){std::cerr<<f.code<<'\n';return 1;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
