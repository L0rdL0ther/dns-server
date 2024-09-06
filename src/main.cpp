#include <csignal>
#include <iostream>

#include "header/dns.h"
#include "header/udp.h"
#include "header/dnsRequestBody.h"
#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>

#include "header/dnsEnum.h"


#define PORT 53
#define MAXLINE 1024

void processData(const char* data, size_t length, const sockaddr_in& client_addr) {
    std::vector<uint8_t> dataVector(data, data + length);

    std::stringstream neeee;

    for (int i = 0; i < length; i++) {
        neeee << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)data[i] << " " ;
    }

    std::cout << neeee.str() << std::endl;

    DNS::ParseResponse dnsManager;
    DnsRequestBody requestBody = dnsManager.parseDnsRequest(dataVector);

    if (requestBody.transactionID != 0) {
        std::cout << "_____________________________________________________________";
        std::cout << "\nTransaction ID: " << requestBody.transactionID << std::endl;
        std::cout << "Flags: " << requestBody.flags << std::endl;
        std::cout << "Questions: " << requestBody.questions << std::endl;
        std::cout << "Answer RRs: " << requestBody.answerRRs << std::endl;
        std::cout << "Authority RRs: " << requestBody.authorityRRs << std::endl;
        std::cout << "Additional RRs: " << requestBody.additionalRRs << std::endl;

        uint16_t flags = static_cast<int>(DNS::DnsEnum::ResponseFlags::RESPONSE);
        std::string name = "example.com";
        uint32_t ttl = 3600;
        std::string rData = "192.1.13.2";

        for (const auto &section : requestBody.questionsSection) {
            std::cout << "Query: " << section.query << std::endl;
            std::cout << "Query Type: " << section.type << std::endl;
            std::cout << "Query Class: " <<section.queryClass << std::endl;
        }

        std::pmr::list<AnswerSectionWithPriority> answerSectionWithPriority;
        std::pmr::list<AnswerSection> answerSection;
        answerSection.push_back(AnswerSection{"example.com",DNS::DnsEnum::QueryType::A,DNS::DnsEnum::QueryClass::IN,ttl,rData});
        answerSection.push_back(AnswerSection{"example.com",DNS::DnsEnum::QueryType::A,DNS::DnsEnum::QueryClass::IN,ttl,rData});

        auto response = DNS::CreateResponse::createResponse(flags, answerSectionWithPriority, answerSection, requestBody.questionsSection, requestBody);
        auto& udp = DNS::UDP::getInstance();
        udp.sendResponse(reinterpret_cast<const char*>(response.data()), response.size(), MSG_CONFIRM);

    }
}



int main() {

    auto& udpSoc = DNS::UDP::getInstance();
    udpSoc.setPort(PORT);
    udpSoc.setMaxLine(MAXLINE);
    udpSoc.bindUdp();
    std::cout << "Udp socket bound" << '\n';
    udpSoc.setDataCallback(processData);
    std::cout << "Udp socket listening" << '\n';
    udpSoc.listenForData();

}

