#include <csignal>
#include <iostream>
#include "header/dns.h"
#include "header/udp.h"
#include "header/dnsRequestBody.h"
#include <vector>
#include <cstdint>
#include <sstream>
#include "database/postegre.h"

#define PORT 53
#define MAXLINE 1024

std::string conn_str = "";
auto &db = postegre::Database::get_database(conn_str);


void processData(const char *data, size_t length, const sockaddr_in &client_addr) {
    std::vector<uint8_t> dataVector(data, data + length);
    DnsRequestBody requestBody = DNS::ParseResponse::parseDnsRequest(dataVector);


    if (requestBody.transactionID != 0) {

        std::pmr::list<AnswerSection> answers;

        for (auto &question: requestBody.questionsSection) {
            std::cout << question.query << std::endl;
            std::string subdomain, mainDomain;
            DNS::ParseResponse::splitDomain(question.query, subdomain, mainDomain);
            std::string domainQuery =
                    "SELECT * FROM dnsrecord_entries WHERE archived = FALSE AND deleted = FALSE AND domain_name = ($1)";
            pqxx::result domainRecords = db.execute_query(domainQuery, mainDomain);


            std::cout << subdomain << std::endl;
            std::cout << mainDomain << std::endl;
            //std::cout << domainRecords << std::endl;
            std::cout << domainRecords.size() << std::endl;

            for (const auto &row: domainRecords) {
                auto name = row["name"].as<std::string>();
                auto value = row["value"].as<std::string>();
                auto type_str = row["type"].as<std::string>();
                DNS::DnsEnum::QueryType type = DNS::DnsEnum::get_query_type(type_str);

                std::cout << "Name: " << name << ", Value: " << value << ", Type: " << static_cast<int>(type) <<
                        std::endl;
                if (subdomain.empty() && name == "@" ) {
                    answers.push_back(AnswerSection(question.query,type,DNS::DnsEnum::QueryClass::IN,3600,value));
                }

                if (!subdomain.empty() && name == subdomain ) {
                    answers.push_back(AnswerSection(question.query,type,DNS::DnsEnum::QueryClass::IN,3600,value));
                }

            }
        }

        auto dnsResponse =  DNS::CreateResponse::createResponse(static_cast<int>(DNS::DnsEnum::ResponseFlags::RESPONSE),answers ,requestBody.questionsSection,requestBody);
        auto& udp = DNS::UDP::getInstance();
        udp.sendResponse(reinterpret_cast<const char*>(dnsResponse.data()), dnsResponse.size(), MSG_CONFIRM);
    }
}


int main() {
    auto &udpSoc = DNS::UDP::getInstance();
    udpSoc.setPort(PORT);
    udpSoc.setMaxLine(MAXLINE);
    udpSoc.bindUdp();
    std::cout << "Udp socket bound" << '\n';
    udpSoc.setDataCallback(processData);
    std::cout << "Udp socket listening" << '\n';
    udpSoc.listenForData();
}


//
// std::cout << "_____________________________________________________________";
//       std::cout << "\nTransaction ID: " << requestBody.transactionID << std::endl;
//       std::cout << "Flags: " << requestBody.flags << std::endl;
//       std::cout << "Questions: " << requestBody.questions << std::endl;
//       std::cout << "Answer RRs: " << requestBody.answerRRs << std::endl;
//       std::cout << "Authority RRs: " << requestBody.authorityRRs << std::endl;
//       std::cout << "Additional RRs: " << requestBody.additionalRRs << std::endl;
//
//       uint16_t flags = static_cast<int>(DNS::DnsEnum::ResponseFlags::RESPONSE);
//       std::string name = "example.com";
//       uint32_t ttl = 3600;
//       std::string rData = "123.24.12.33";
//
//       for (const auto &section : requestBody.questionsSection) {
//           std::cout << "Query: " << section.query << std::endl;
//           std::cout << "Query Type: " << section.type << std::endl;
//           std::cout << "Query Class: " <<section.queryClass << std::endl;
//       }
//
//       std::pmr::list<AnswerSectionWithPriority> answerSectionWithPriority;
//       std::pmr::list<AnswerSection> answerSection;
//
//       answerSectionWithPriority.push_back(AnswerSectionWithPriority("example.com",DNS::DnsEnum::QueryType::MX,DNS::DnsEnum::QueryClass::IN,10,ttl,rData));
//       answerSection.push_back(AnswerSection{"example.com",DNS::DnsEnum::QueryType::A,DNS::DnsEnum::QueryClass::IN,ttl,rData});
//       //answerSection.push_back(AnswerSection{"example.com",DNS::DnsEnum::QueryType::A,DNS::DnsEnum::QueryClass::IN,ttl,rData});
//
//       auto response = DNS::CreateResponse::createResponse(flags, answerSection, requestBody.questionsSection, requestBody);
//
//       //response = DNS::CreateResponse::createMxResponse(flags, answerSectionWithPriority, requestBody.questionsSection, requestBody);
//
//       std::cout << "Response Packet: " << DNS::Log::bytesToHex(response) << std::endl;
//
//       auto& udp = DNS::UDP::getInstance();
//       udp.sendResponse(reinterpret_cast<const char*>(response.data()), response.size(), MSG_CONFIRM);
