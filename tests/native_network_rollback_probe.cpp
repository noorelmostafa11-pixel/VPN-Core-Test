// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
#include "../src/native-network-rollback.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
int main(){
    using vpn::NativeNetworkRollback;
    std::vector<std::string> state;
    {
        NativeNetworkRollback journal;
        journal.step("protect_endpoint",[&]{state.push_back("hostroute");},[&]{assert(state.back()=="hostroute");state.pop_back();});
        journal.step("protect_dns",[&]{state.push_back("dns");},[&]{assert(state.back()=="dns");state.pop_back();});
        journal.step("protect_ipv6",[&]{state.push_back("ipv6");},[&]{assert(state.back()=="ipv6");state.pop_back();});
        assert(state.size()==3);
        assert(journal.rollback().empty()&&state.empty());
        assert(journal.pending_compensations()==0);
    }
    {
        NativeNetworkRollback journal;
        journal.step("host_route",[&]{state.push_back("hostroute");},[&]{assert(state.back()=="hostroute");state.pop_back();});
        try {
            journal.step("dns",[&]{state.push_back("dns");throw std::runtime_error("simulated partial apply");},[&]{assert(state.back()=="dns");state.pop_back();});
            assert(false);
        }catch(const std::runtime_error&){}
        assert(state.empty()&&journal.pending_compensations()==0);
    }
    {
        NativeNetworkRollback journal;
        bool first=true;
        journal.step("retry",[&]{state.push_back("route");},[&]{if(first){first=false;throw std::runtime_error("temporary undo failure");}state.pop_back();});
        auto failed=journal.rollback();
        assert(failed.size()==1&&failed[0]=="retry");
        assert(journal.pending_compensations()==1&&state.size()==1);
        assert(journal.rollback().empty()&&state.empty());
    }
    std::cout<<"PASS: reverse rollback, partial apply compensation, retryable undo\n";
}
