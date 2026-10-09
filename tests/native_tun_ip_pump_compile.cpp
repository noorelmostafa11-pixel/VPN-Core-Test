// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Compilation-only check: never creates an adapter, route or TCP connection.
#include "../src/native-tun-ip-pump.hpp"
#include <iostream>
#ifdef _WIN32
void compile_pump(vpn::NativeWintunSession& adapter,const vpn::Config& config) {
    vpn::NativeTunIpPump pump(adapter,config);
    (void)pump.step([](uint64_t,const std::string&){});
}
int main(){std::cout<<"PASS: Windows native IPv4 TCP/UDP pump compiled; not activated\n";}
#else
int main(){std::cout<<"SKIP: Windows-only Wintun pump\n";}
#endif
