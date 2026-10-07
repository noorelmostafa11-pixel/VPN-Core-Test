#define VPN_CORE_CNG_TEST
#include "../src/crypto.hpp"
#include <iostream>
void check(bool v,const char* message){if(!v)throw std::runtime_error(message);}
void no_handles(){check(fake_cng_live_hashes==0&&fake_cng_live_keys==0&&fake_cng_live_algorithms==0,"CNG handle leak");}
int main(int argc,char** argv){try{
    using namespace vpn;std::string only=argc>1?argv[1]:"all";
    if(only!="aes"){
        for(unsigned i=0;i<72767;++i)check(hex_bytes(digest("sha256",to_bytes("abc")))=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","SHA256 vector");
        for(int failure:{1,2}){fake_cng_fail=failure;bool failed=false;try{(void)digest("sha256",to_bytes("abc"));}catch(const std::runtime_error&){failed=true;}check(failed,"Hash injected failure ignored");fake_cng_fail=0;no_handles();}
    }
    if(only!="hash"){
        for(unsigned i=0;i<5000;++i)for(unsigned length:{16u,24u,32u}){
            Bytes key(length),nonce(12),input{1,2,3,4,5},aad{6,7};auto encrypted=aes(key,nonce,input,aad,false);check(aes(key,nonce,encrypted,aad,true)==input,"AES-GCM oracle");
            encrypted.back()^=1;bool rejected=false;try{(void)aes(key,nonce,encrypted,aad,true);}catch(const std::runtime_error&){rejected=true;}check(rejected,"Corrupted GCM tag accepted");
            Bytes block(16);auto encoded=aes(key,{},block,{},false,true);check(aes(key,{},encoded,{},true,true)==block,"AES-ECB oracle");
        }
        for(int failure:{3,4}){bool failed=false;fake_cng_fail=failure==3?3:0;try{(void)aes(Bytes(16),Bytes(failure==4?11:12),Bytes(16),{},false);}catch(const std::runtime_error&){failed=true;}check(failed,"AES failure ignored");fake_cng_fail=0;no_handles();}
    }
    no_handles();std::cout<<"PASS: Windows CNG branch, retained object lifetime, SHA256 stress, AES-GCM/ECB oracle, rejected tags and failure cleanup\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
