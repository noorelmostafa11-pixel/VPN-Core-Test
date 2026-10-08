// Native callbacks avoid attributing Python/Go thread caches to the C++ worker.
#include "../src/net.hpp"
#include <iostream>

using namespace vpn;
void check(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
struct Gate {
    std::mutex mutex;std::condition_variable ready;
    bool block_callback=false,callback_entered=false,callback_release=false;
    bool block_cleanup=true,cleanup_entered=false,cleanup_release=false,cleaned=false;
};
struct ThreadContext {
    Gate* gate=nullptr;
    ~ThreadContext(){if(!gate)return;std::unique_lock<std::mutex> lock(gate->mutex);
        gate->cleanup_entered=true;gate->ready.notify_all();
        if(gate->block_cleanup)gate->ready.wait(lock,[&]{return gate->cleanup_release;});
        gate->cleaned=true;gate->ready.notify_all();}
};
int resolver(const char* host,char* out,int cap,void* user){
    auto& gate=*static_cast<Gate*>(user);
    if(std::string(host)=="held.invalid"){
        thread_local ThreadContext context;context.gate=&gate;
        std::unique_lock<std::mutex> lock(gate.mutex);gate.callback_entered=true;gate.ready.notify_all();
        if(gate.block_callback)gate.ready.wait(lock,[&]{return gate.callback_release;});
    }
    constexpr char address[]="127.0.0.1\n";
    if(cap<int(sizeof(address)))return -1;std::memcpy(out,address,sizeof(address)-1);return sizeof(address)-1;
}
bool entered(Gate& gate,bool cleanup){std::unique_lock<std::mutex> lock(gate.mutex);
    return gate.ready.wait_for(lock,std::chrono::seconds(3),[&]{return cleanup?gate.cleanup_entered:gate.callback_entered;});}
void release(Gate& gate,bool cleanup){std::lock_guard<std::mutex> lock(gate.mutex);
    if(cleanup)gate.cleanup_release=true;else gate.callback_release=true;gate.ready.notify_all();}
bool cleaned(Gate& gate){std::unique_lock<std::mutex> lock(gate.mutex);
    return gate.ready.wait_for(lock,std::chrono::seconds(3),[&]{return gate.cleaned;});}
unsigned handles(){
#ifdef _WIN32
    DWORD count=0;check(GetProcessHandleCount(GetCurrentProcess(),&count)!=0,"Handle count failed");return count;
#else
    unsigned count=0;for([[maybe_unused]] const auto& entry:std::filesystem::directory_iterator("/proc/self/fd"))++count;return count;
#endif
}
int main(int argc,char** argv){try{
    check(argc==2,"Expected cleanup, drain, resources or resources-retained");const std::string mode=argv[1];
    [[maybe_unused]] NetworkRuntime runtime;
    Gate gate;network_hooks={nullptr,resolver,&gate};stopping=false;
    if(mode=="cleanup"){
        std::atomic<bool> returned{false};std::exception_ptr error;
        std::thread caller([&]{try{check(invoke_bootstrap("held.invalid",HookClock::now()+std::chrono::seconds(3))=="127.0.0.1\n","DNS result changed");}catch(...){error=std::current_exception();}returned=true;});
        const bool began=entered(gate,true);
        std::this_thread::sleep_for(std::chrono::milliseconds(40));const bool premature=returned.load();
        release(gate,true);caller.join();const bool complete=cleaned(gate);if(error)std::rethrow_exception(error);
        check(began&&!premature&&complete,"DNS returned before native thread-local cleanup");
        std::cout<<"PASS: DNS success joins native thread-local cleanup\n";
    }else if(mode=="drain"){
        gate.block_callback=true;bool timed_out=false;
        try{(void)invoke_bootstrap("held.invalid",HookClock::now()+std::chrono::milliseconds(50));}
        catch(const Failure& error){timed_out=error.code=="BOOTSTRAP_DNS_TIMEOUT";}
        // The same resolver must service another lookup while the first is held.
        const bool independent=invoke_bootstrap("second.invalid",HookClock::now()+std::chrono::seconds(3))=="127.0.0.1\n";
        stopping=true;std::atomic<bool> drained{false};std::exception_ptr error;
        std::thread stop([&]{try{configure_network_hooks({});}catch(...){error=std::current_exception();}drained=true;});
        std::this_thread::sleep_for(std::chrono::milliseconds(40));const bool callback_live=!drained.load();
        release(gate,false);const bool began=entered(gate,true);
        std::this_thread::sleep_for(std::chrono::milliseconds(40));const bool premature=drained.load();
        release(gate,true);stop.join();const bool complete=cleaned(gate);if(error)std::rethrow_exception(error);
        check(timed_out&&independent&&callback_live&&began&&!premature&&complete,"Stop did not preserve callback/native cleanup lifetime");
        check(network_hooks_active==0&&network_dns_active==0,"Callback lease retained after drain");
        std::cout<<"PASS: independent DNS, timeout and Stop drain native thread cleanup\n";
    }else if(mode=="resources"||mode=="resources-retained"){
        gate.block_cleanup=false;
        std::vector<Socket> retained;
        auto sample=[&](const char* stage,unsigned cycle,const char* phase){
            const auto count=handles();
            std::cout<<"DNS_RESOURCE {\"stage\":\""<<stage<<"\",\"cycle\":"<<cycle
                     <<",\"phase\":\""<<phase<<"\",\"handles\":"<<count<<"}"<<std::endl;
            return count;
        };
        auto callback_step=[&](const char* stage,unsigned cycle){
            check(invoke_bootstrap("held.invalid",HookClock::now()+std::chrono::seconds(3))=="127.0.0.1\n","DNS result changed");
            return sample(stage,cycle,"callback");
        };
        auto system_step=[&](const char* stage,unsigned cycle){
            network_hooks={};
            const auto addresses=node_addresses("localhost",HookClock::now()+std::chrono::seconds(3));
            network_hooks={nullptr,resolver,&gate};
            check(!addresses.empty(),"System DNS returned no addresses");
            return sample(stage,cycle,"system");
        };
        // Both resolver paths must be initialized before choosing a baseline.
        // A bounded warmup may initialize Windows DNS resources once, but its
        // final three cycles must already be stable; growth cannot reset it.
        sample("initial",0,"before");
        std::vector<std::pair<unsigned,unsigned>> warmup;
        for(unsigned i=0;i<8;++i){
            if(mode=="resources-retained"){
                retained.emplace_back(::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
                check(retained.back().get()!=invalid_socket,"Retained socket creation failed");
            }
            const auto callback_count=callback_step("warmup",i);
            const auto system_count=system_step("warmup",i);
            warmup.emplace_back(callback_count,system_count);
        }
        const auto stable=warmup.back().second;
        for(size_t i=warmup.size()-3;i<warmup.size();++i)
            check(warmup[i].first==stable&&warmup[i].second==stable,"DNS warmup handles did not stabilize");
        const auto baseline=sample("baseline",0,"fixed");
        check(baseline==stable,"DNS handles changed before fixed baseline");
        for(unsigned i=0;i<32;++i){
            check(callback_step("measured",i)==baseline,"Native DNS callback worker retained handles");
            check(system_step("measured",i)==baseline,"System DNS worker retained handles");
        }
        std::cout<<"PASS: native callback and system DNS handles stable for 32 cycles; baseline="<<baseline<<'\n';
    }else throw std::runtime_error("Unknown mode");
    return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
