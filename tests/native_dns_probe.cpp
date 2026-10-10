// DNS protocol boundaries and large-answer TCP fallback, without network I/O.
#include "../src/native-tun-dns.hpp"
#include <iostream>
using namespace vpn;
static void require(bool value){if(!value)throw std::runtime_error("DNS boundary check failed");}
int main(){
    try{
        Bytes question{0x56,0x50,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
        require(dns_question_end(question)==question.size());
        for(size_t n=0;n<question.size();++n){Bytes partial(question.begin(),question.begin()+std::ptrdiff_t(n));bool rejected=false;try{dns_question_end(partial);}catch(const Failure&){rejected=true;}require(rejected);}
        auto pointer=question;pointer[12]=0xff;pointer[13]=0xff;bool rejected=false;try{dns_question_end(pointer);}catch(const Failure&){rejected=true;}require(rejected);
        auto small=question;small[2]=0x81;small[3]=0x80;require(dns_udp_answer(question,small)==small);
        auto large=small;large.resize(4096,0x42);auto truncated=dns_udp_answer(question,large);
        require(truncated.size()==question.size()&&(truncated[2]&2)&&get16(truncated)==get16(question)&&get16(truncated,4)==1);
        for(size_t i=6;i<12;++i)require(truncated[i]==0);
        require(std::equal(question.begin()+12,question.end(),truncated.begin()+12));
        auto failure=dns_failure_reply(question);require(failure.size()==12&&get16(failure)==get16(question)&&(failure[3]&15)==2);
        NetstackFlow flow;flow.protocol=17;flow.address_size=4;flow.port=53;const uint8_t local[]{198,18,0,53};std::copy(local,local+4,flow.address);require(native_dns_flow(flow));flow.address[0]=9;require(!native_dns_flow(flow));
        Config node;const char* phase="RELAY";NativeDnsSession tcp(node,false,&phase,{});
        require(tcp.write(Bytes{0}));require(!tcp.poll());tcp.finish_upload();rejected=false;try{tcp.poll();}catch(const Failure& error){rejected=error.code=="DNS_TCP_TRUNCATED";}require(rejected);
        std::cout<<"{\"test\":\"NATIVE_DNS_BOUNDARIES\",\"status\":\"PASS\",\"network_io\":false}\n";return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
