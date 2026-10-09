// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Queries route/DNS state without changing any Windows network setting.
#include "../src/native-windows-network-snapshot.hpp"
#include <iostream>
#ifdef _WIN32
#include <stdexcept>
int main() {
    auto network=vpn::NativeWindowsNetworkSnapshot::capture();
    if(network.interfaces.empty())
        throw std::runtime_error("Windows adapter enumeration returned no interfaces");
    for(const auto& item:network.routes)
        if(item.DestinationPrefix.Prefix.si_family!=AF_INET &&
           item.DestinationPrefix.Prefix.si_family!=AF_INET6)
            throw std::runtime_error("Invalid route family");
    std::cout<<"PASS: read-only Windows route/DNS inventory; interfaces="
             <<network.interfaces.size()<<" routes="<<network.routes.size()<<"\n";
}
#else
int main(){std::cout<<"SKIP: Windows-only route/DNS inventory\n";}
#endif
