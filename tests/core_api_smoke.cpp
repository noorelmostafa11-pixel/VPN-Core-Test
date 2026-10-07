#include <dlfcn.h>
#include <cstring>
#include <iostream>
int main(int argc,char** argv){
    if(argc!=2)return 1;
    auto module=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!module){std::cerr<<dlerror()<<'\n';return 1;}
    int(*run)(int,char**)=nullptr;const char*(*version)()=nullptr;
    auto raw=dlsym(module,"vpn_core_run");std::memcpy(&run,&raw,sizeof(run));
    raw=dlsym(module,"vpn_core_version");std::memcpy(&version,&raw,sizeof(version));
    if(!run||!version)return 1;
    for(const char* option:{"--self-test","--check-components"}){char name[]="vpn-core";char* args[]{name,const_cast<char*>(option)};if(run(2,args))return 1;}
    std::cout<<"PASS: shared core "<<version()<<'\n';
    // The Go runtime remains resident: do not dlclose its provider/core.
    return 0;
}
