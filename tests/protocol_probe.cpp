#include "../src/protocol.hpp"
#include <iostream>
int main() {
    std::string hex;
    while(std::getline(std::cin,hex)) {
        if(hex.size()%2)return 1;
        std::string data;
        for(size_t i=0;i<hex.size();i+=2) {
            int a=vpn::hex_digit(hex[i]),b=vpn::hex_digit(hex[i+1]);
            if(a<0||b<0)return 1;
            data+=char(a*16+b);
        }
        std::cout<<vpn::sha224(data)<<'\n';
    }
}
