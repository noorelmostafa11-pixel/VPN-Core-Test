// Copyright (c) 2026 Vpn project owner. See NOTICE.md.
// Compile/link smoke for the Wintun loader; never creates an adapter.
#include "../src/native-wintun.hpp"
#include "../src/native-wintun-session.hpp"
#include <iostream>
#ifdef _WIN32
#include <stdexcept>
int main() {
    try {
        vpn::NativeWintunApi api(L"wintun.dll");
        std::cerr<<"FAIL: relative DLL path unexpectedly accepted\n";
        return 1;
    } catch(const std::invalid_argument&) {
        std::cout<<"PASS: relative Wintun DLL path rejected\n";
        return 0;
    } catch(const std::exception& e) {
        std::cerr<<"FAIL: "<<e.what()<<"\n";
        return 1;
    }
}
#else
int main() {
    std::cout<<"SKIP: native Wintun loader requires Windows\n";
    return 0;
}
#endif
