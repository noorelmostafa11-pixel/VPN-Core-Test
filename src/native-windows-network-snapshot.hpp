// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Read-only snapshot of Windows interface DNS and IPv4/IPv6 routing state.
// This is groundwork for a future transactional rollback implementation.
// It does not install routes, change DNS, or provide a leak-proof kill switch.
#pragma once
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace vpn {
struct NativeStoredSockaddr {
    SOCKADDR_STORAGE value{};
    int length=0;
};
struct NativeInterfaceSnapshot {
    uint64_t luid=0;
    unsigned long ipv4_index=0;
    unsigned long ipv6_index=0;
    unsigned int operational_status=0;
    std::vector<NativeStoredSockaddr> dns_servers;
    std::vector<NativeStoredSockaddr> gateways;
};
struct NativeWindowsNetworkSnapshot {
    std::vector<NativeInterfaceSnapshot> interfaces;
    std::vector<MIB_IPFORWARD_ROW2> routes;
    static NativeStoredSockaddr copy_address(const SOCKET_ADDRESS& source) {
        if(!source.lpSockaddr||source.iSockaddrLength<=0||
           source.iSockaddrLength>int(sizeof(SOCKADDR_STORAGE)))
            throw std::runtime_error("Invalid Windows network address length");
        NativeStoredSockaddr out;
        out.length=source.iSockaddrLength;
        std::memcpy(&out.value,source.lpSockaddr,size_t(source.iSockaddrLength));
        return out;
    }
    static NativeWindowsNetworkSnapshot capture() {
        NativeWindowsNetworkSnapshot out;
        MIB_IPFORWARD_TABLE2* raw_routes=nullptr;
        const auto route_status=GetIpForwardTable2(AF_UNSPEC,&raw_routes);
        if(route_status!=NO_ERROR)
            throw std::runtime_error("Windows route inventory failed: "+std::to_string(route_status));
        try {
            if(raw_routes&&raw_routes->NumEntries>0) {
                if(raw_routes->NumEntries>100000)
                    throw std::runtime_error("Windows route inventory exceeds limit");
                out.routes.assign(raw_routes->Table,raw_routes->Table+raw_routes->NumEntries);
            }
        } catch(...) {
            if(raw_routes)FreeMibTable(raw_routes);
            throw;
        }
        if(raw_routes)FreeMibTable(raw_routes);
        unsigned long bytes=16384;
        std::vector<unsigned char> buffer(bytes);
        unsigned long status=ERROR_BUFFER_OVERFLOW;
        for(unsigned attempt=0;attempt<6;++attempt) {
            status=GetAdaptersAddresses(AF_UNSPEC,
                GAA_FLAG_INCLUDE_PREFIX|GAA_FLAG_INCLUDE_GATEWAYS,
                nullptr,reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),&bytes);
            if(status!=ERROR_BUFFER_OVERFLOW)break;
            if(bytes>16u*1024u*1024u)
                throw std::runtime_error("Windows adapter inventory exceeds limit");
            buffer.resize(bytes);
        }
        if(status!=NO_ERROR)
            throw std::runtime_error("Windows adapter inventory failed: "+std::to_string(status));
        auto* adapter=reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        for(size_t n=0;adapter&&n<4096;++n,adapter=adapter->Next) {
            NativeInterfaceSnapshot state;
            state.luid=adapter->Luid.Value;
            state.ipv4_index=adapter->IfIndex;
            state.ipv6_index=adapter->Ipv6IfIndex;
            state.operational_status=unsigned(adapter->OperStatus);
            for(auto* server=adapter->FirstDnsServerAddress;server;server=server->Next)
                state.dns_servers.push_back(copy_address(server->Address));
            for(auto* gateway=adapter->FirstGatewayAddress;gateway;gateway=gateway->Next)
                state.gateways.push_back(copy_address(gateway->Address));
            out.interfaces.push_back(std::move(state));
        }
        if(adapter)throw std::runtime_error("Windows adapter inventory exceeds adapter limit");
        return out;
    }
};
} // namespace vpn
#endif
