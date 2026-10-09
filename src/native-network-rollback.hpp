// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Application-scoped rollback journal for experimental native networking.
// No OS API is called: this header does not modify DNS, routes or adapters.
#pragma once
#include <exception>
#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace vpn {
class NativeNetworkRollback final {
    struct Entry {std::string name;std::function<void()> undo;};
    std::vector<Entry> entries_;
    std::vector<std::string> failures_;
    bool closed_=false;
public:
    NativeNetworkRollback()=default;
    NativeNetworkRollback(const NativeNetworkRollback&)=delete;
    NativeNetworkRollback& operator=(const NativeNetworkRollback&)=delete;
    NativeNetworkRollback(NativeNetworkRollback&&)=delete;
    NativeNetworkRollback& operator=(NativeNetworkRollback&&)=delete;
    ~NativeNetworkRollback()noexcept { (void)rollback(); }

    // Every undo MUST be idempotent and compensate even a partially applied
    // Windows API change. Compensation is registered BEFORE doing the change.
    template<class Apply,class Undo>
    void step(const std::string& name,Apply apply,Undo undo) {
        if(closed_)throw std::logic_error("Native network transaction is closed");
        if(name.empty())throw std::invalid_argument("Invalid rollback step");
        entries_.push_back({name,std::function<void()>(std::move(undo))});
        try {apply();}
        catch(...) {
            const auto failure=std::current_exception();
            (void)rollback();
            std::rethrow_exception(failure);
        }
    }
    // Failed undo steps are retained for retry. Caller must inspect failures
    // before declaring network restoration. Destruction retries best-effort.
    std::vector<std::string> rollback()noexcept {
        failures_.clear();
        std::vector<Entry> pending;
        for(auto it=entries_.rbegin();it!=entries_.rend();++it) {
            try {it->undo();}
            catch(...) {failures_.push_back(it->name);pending.push_back(*it);}
        }
        entries_.assign(pending.rbegin(),pending.rend());
        if(entries_.empty())closed_=true;
        return failures_;
    }
    size_t pending_compensations()const noexcept{return entries_.size();}
    const std::vector<std::string>& failures()const noexcept{return failures_;}
};
} // namespace vpn
