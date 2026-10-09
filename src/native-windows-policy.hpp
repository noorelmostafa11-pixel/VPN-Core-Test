// Experimental persistent, app-owned WFP guard. No global firewall reset.
#pragma once
#ifdef _WIN32
#include "native-wintun.hpp"
#include <fwpmu.h>
#include "native-wfp-constants.hpp"
#include <vector>
#include <array>
#include <algorithm>
#include <map>
#include <set>
namespace vpn {
// Fixed owner IDs let recovery enumerate precisely our filters after a crash.
inline const GUID tun_policy_owner={0x56504e01,0x7617,0x4e6a,{0xa7,0x19,0x61,0x0d,0x39,0x4a,0x6b,0x10}};
inline const GUID tun_policy_layer={0x56504e02,0x7617,0x4e6a,{0xa7,0x19,0x61,0x0d,0x39,0x4a,0x6b,0x10}};
class NativeWindowsPolicy {
    HANDLE engine_=nullptr;

    static void checked(DWORD code){if(code)throw Failure("STARTUP_FAILED: owned WFP policy","TUN_WFP_POLICY",code);}
    void add(const GUID& layer,std::vector<FWPM_FILTER_CONDITION0>& c) {
        FWPM_FILTER0 filter{};filter.providerKey=const_cast<GUID*>(&tun_policy_owner);filter.subLayerKey=tun_policy_layer;
        filter.layerKey=layer;filter.displayData.name=const_cast<wchar_t*>(L"VpnCore Native TUN guard v1");
        filter.flags=tun_wfp_persistent;filter.action.type=FWP_ACTION_BLOCK;
        filter.weight.type=FWP_UINT8;filter.weight.uint8=15;filter.numFilterConditions=UINT32(c.size());filter.filterCondition=c.data();checked(FwpmFilterAdd0(engine_,&filter,nullptr,nullptr));
    }
    static bool bit(const std::array<uint8_t,16>& ip,unsigned b){return (ip[b/8]>>(7-b%8))&1;}
    void complement(bool v6,std::array<uint8_t,16> base,unsigned prefix,const std::vector<std::array<uint8_t,16>>& excluded,uint64_t luid) {
        const unsigned bits=v6?128:32;
        if(excluded.empty()) {
            FWPM_FILTER_CONDITION0 iface{};iface.fieldKey=tun_fwpm_condition_ip_local_interface;iface.matchType=FWP_MATCH_NOT_EQUAL;iface.conditionValue.type=FWP_UINT64;iface.conditionValue.uint64=&luid;
            FWPM_FILTER_CONDITION0 loop{};loop.fieldKey=tun_fwpm_condition_flags;loop.matchType=FWP_MATCH_FLAGS_NONE_SET;loop.conditionValue.type=FWP_UINT32;loop.conditionValue.uint32=FWP_CONDITION_FLAG_IS_LOOPBACK;
            FWPM_FILTER_CONDITION0 remote{};remote.fieldKey=tun_fwpm_condition_ip_remote_address;remote.matchType=FWP_MATCH_EQUAL;
            FWP_V4_ADDR_AND_MASK v4{};FWP_V6_ADDR_AND_MASK v6mask{};
            if(v6){std::copy(base.begin(),base.end(),v6mask.addr);v6mask.prefixLength=uint8_t(prefix);remote.conditionValue.type=FWP_V6_ADDR_MASK;remote.conditionValue.v6AddrMask=&v6mask;}
            else{v4.addr=uint32_t(base[0])<<24|uint32_t(base[1])<<16|uint32_t(base[2])<<8|base[3];v4.mask=prefix?0xffffffffu<<(32-prefix):0;remote.conditionValue.type=FWP_V4_ADDR_MASK;remote.conditionValue.v4AddrMask=&v4;}
            std::vector<FWPM_FILTER_CONDITION0> conditions{iface,loop,remote};add(v6?tun_fwpm_layer_outbound_transport_v6:tun_fwpm_layer_outbound_transport_v4,conditions);add(v6?tun_fwpm_layer_ale_auth_connect_v6:tun_fwpm_layer_ale_auth_connect_v4,conditions);return;
        }
        if(prefix==bits)return;
        for(unsigned side=0;side<2;++side){auto next=base;next[prefix/8]|=uint8_t(side<<(7-prefix%8));std::vector<std::array<uint8_t,16>> ips;for(const auto& ip:excluded)if(bit(ip,prefix)==bool(side))ips.push_back(ip);complement(v6,next,prefix+1,ips,luid);}
    }
public:
    NativeWindowsPolicy(){checked(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,nullptr,&engine_));}
    ~NativeWindowsPolicy(){if(engine_)FwpmEngineClose0(engine_);}
    // Persistent by design: destruction/crash does not silently open networking.
    void acquire(uint64_t tun_luid,const std::vector<std::pair<std::string,uint16_t>>& endpoints) {
        checked(FwpmTransactionBegin0(engine_,0));
        try {
            FWPM_PROVIDER0 owner{};owner.providerKey=tun_policy_owner;owner.flags=tun_wfp_persistent;owner.displayData.name=const_cast<wchar_t*>(L"VpnCore Native TUN owned policy v1");
            checked(FwpmProviderAdd0(engine_,&owner,nullptr)); // existing owner means explicit recovery required
            FWPM_SUBLAYER0 sub{};sub.subLayerKey=tun_policy_layer;sub.providerKey=const_cast<GUID*>(&tun_policy_owner);sub.flags=tun_wfp_persistent;sub.weight=0x7fff;sub.displayData.name=owner.displayData.name;checked(FwpmSubLayerAdd0(engine_,&sub,nullptr));
            wchar_t executable[32768]{};if(!GetModuleFileNameW(nullptr,executable,32768))throw Failure("STARTUP_FAILED: process identity","TUN_POLICY_PROCESS");
            FWP_BYTE_BLOB* identity=nullptr;checked(FwpmGetAppIdFromFileName0(executable,&identity));
            struct ReleaseIdentity {FWP_BYTE_BLOB*& p;~ReleaseIdentity(){FwpmFreeMemory0(reinterpret_cast<void**>(&p));}} release{identity};
            std::vector<std::array<uint8_t,16>> ipv4,ipv6;std::map<std::string,std::set<uint16_t>> nodes;
            for(const auto& endpoint:endpoints)nodes[endpoint.first].insert(endpoint.second);
            for(const auto& entry:nodes){const auto& node=entry.first;std::array<uint8_t,16> ip{};bool v6=node.find(':')!=std::string::npos;if(InetPtonA(v6?AF_INET6:AF_INET,node.c_str(),ip.data())!=1)throw Failure("STARTUP_FAILED: node IP","TUN_POLICY_ADDRESS");(v6?ipv6:ipv4).push_back(ip);
                // Exact protected bootstrap ports only, including separate download/ECH.
                FWPM_FILTER_CONDITION0 remote{};remote.fieldKey=tun_fwpm_condition_ip_remote_address;remote.matchType=FWP_MATCH_EQUAL;FWP_BYTE_ARRAY16 array{};uint32_t v4=uint32_t(ip[0])<<24|uint32_t(ip[1])<<16|uint32_t(ip[2])<<8|ip[3];
                if(v6){std::copy(ip.begin(),ip.end(),array.byteArray16);remote.conditionValue.type=FWP_BYTE_ARRAY16_TYPE;remote.conditionValue.byteArray16=&array;}else{remote.conditionValue.type=FWP_UINT32;remote.conditionValue.uint32=v4;}
                FWPM_FILTER_CONDITION0 port{};port.fieldKey=tun_fwpm_condition_ip_remote_port;port.matchType=FWP_MATCH_RANGE;port.conditionValue.type=FWP_RANGE_TYPE;
                FWPM_FILTER_CONDITION0 iface{};iface.fieldKey=tun_fwpm_condition_ip_local_interface;iface.matchType=FWP_MATCH_NOT_EQUAL;iface.conditionValue.type=FWP_UINT64;iface.conditionValue.uint64=&tun_luid;
                FWPM_FILTER_CONDITION0 loop{};loop.fieldKey=tun_fwpm_condition_flags;loop.matchType=FWP_MATCH_FLAGS_NONE_SET;loop.conditionValue.type=FWP_UINT32;loop.conditionValue.uint32=FWP_CONDITION_FLAG_IS_LOOPBACK;
                // Complement the union of ports, not separate NOT_EQUAL conditions.
                // Multiple ports on the same IP must not block one another.
                std::vector<FWPM_FILTER_CONDITION0> c;
                auto deny_ports=[&](unsigned low,unsigned high){if(low>high)return;FWP_RANGE0 range{};range.valueLow.type=range.valueHigh.type=FWP_UINT16;range.valueLow.uint16=uint16_t(low);range.valueHigh.uint16=uint16_t(high);port.conditionValue.rangeValue=&range;c={remote,port,iface,loop};add(v6?tun_fwpm_layer_outbound_transport_v6:tun_fwpm_layer_outbound_transport_v4,c);add(v6?tun_fwpm_layer_ale_auth_connect_v6:tun_fwpm_layer_ale_auth_connect_v4,c);};
                unsigned next=0;for(auto allowed:entry.second){if(next<unsigned(allowed))deny_ports(next,unsigned(allowed)-1);next=unsigned(allowed)+1;}if(next<=65535)deny_ports(next,65535);
                FWPM_FILTER_CONDITION0 process{};process.fieldKey=tun_fwpm_condition_ale_app_id;process.matchType=FWP_MATCH_NOT_EQUAL;process.conditionValue.type=FWP_BYTE_BLOB_TYPE;process.conditionValue.byteBlob=identity;
                c={remote,process,iface,loop};add(v6?tun_fwpm_layer_ale_auth_connect_v6:tun_fwpm_layer_ale_auth_connect_v4,c);
            }
            complement(false,{},0,ipv4,tun_luid);complement(true,{},0,ipv6,tun_luid);
            checked(FwpmTransactionCommit0(engine_));
        }catch(...){FwpmTransactionAbort0(engine_);throw;}
    }
    void recover() {
        checked(FwpmTransactionBegin0(engine_,0));HANDLE enumeration=nullptr;
        try {
            for(const auto& layer:std::vector<GUID>{tun_fwpm_layer_outbound_transport_v4,tun_fwpm_layer_outbound_transport_v6,tun_fwpm_layer_ale_auth_connect_v4,tun_fwpm_layer_ale_auth_connect_v6}) {
                FWPM_FILTER_ENUM_TEMPLATE0 query{};query.providerKey=const_cast<GUID*>(&tun_policy_owner);query.layerKey=layer;query.enumType=FWP_FILTER_ENUM_FULLY_CONTAINED;query.actionMask=0xffffffffu;
                checked(FwpmFilterCreateEnumHandle0(engine_,&query,&enumeration));
                for(;;){FWPM_FILTER0** filters=nullptr;UINT32 count=0;checked(FwpmFilterEnum0(engine_,enumeration,256,&filters,&count));for(UINT32 i=0;i<count;++i)checked(FwpmFilterDeleteById0(engine_,filters[i]->filterId));FwpmFreeMemory0(reinterpret_cast<void**>(&filters));if(count<256)break;}
                FwpmFilterDestroyEnumHandle0(engine_,enumeration);enumeration=nullptr;
            }
            DWORD code=FwpmSubLayerDeleteByKey0(engine_,&tun_policy_layer);if(code!=DWORD(FWP_E_SUBLAYER_NOT_FOUND))checked(code);
            code=FwpmProviderDeleteByKey0(engine_,&tun_policy_owner);if(code!=DWORD(FWP_E_PROVIDER_NOT_FOUND))checked(code);
            checked(FwpmTransactionCommit0(engine_));
        }catch(...){if(enumeration)FwpmFilterDestroyEnumHandle0(engine_,enumeration);FwpmTransactionAbort0(engine_);throw;}
    }
};
}
#endif
