//
// Created by yusuf on 9/5/24.
//

#ifndef DNSREQUESTBODY_H
#define DNSREQUESTBODY_H
#include <cstdint>
#include <list>
#include <string>
#include <utility>

#include "dnsEnum.h"



class QuestionSection {
public:
    std::string query;
    uint16_t type;
    uint16_t queryClass;
};

class AnswerSection {
public:
    std::string query;
    DNS::DnsEnum::QueryType queryType;
    DNS::DnsEnum::QueryClass queryClass;
    uint32_t ttl;
    std::string rData;

    AnswerSection(std::string q, DNS::DnsEnum::QueryType qType, DNS::DnsEnum::QueryClass qClass, uint32_t timeToLive, std::string data)
       : query(std::move(q)), queryType(qType), queryClass(qClass), ttl(timeToLive), rData(std::move(data)) {}

};

class AnswerSectionWithPriority {
public:

    std::string query;
    DNS::DnsEnum::QueryType queryType;
    DNS::DnsEnum::QueryClass queryClass;
    uint16_t priority;
    uint32_t ttl;
    std::string rData;

    AnswerSectionWithPriority(std::string q, DNS::DnsEnum::QueryType qType, DNS::DnsEnum::QueryClass qClass, uint16_t priority, uint32_t timeToLive, std::string data)
        : query(std::move(q)), queryType(qType), queryClass(qClass), priority(priority), ttl(timeToLive), rData(std::move(data)) {}


};


class DnsRequestBody {
    public:
    uint16_t transactionID;
    uint16_t flags;
    uint16_t questions;
    uint16_t answerRRs;
    uint16_t authorityRRs;
    uint16_t additionalRRs;
    std::pmr::list<QuestionSection> questionsSection;
};


#endif //DNSREQUESTBODY_H
