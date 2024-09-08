//
// Created by yusuf on 9/5/24.
//

#ifndef DNS_H
#define DNS_H
#include <vector>

#include "dnsRequestBody.h"

namespace DNS {
    class CreateResponse {
    public:



        static std::vector<uint8_t> createResponse(
            uint16_t flags,
            const std::pmr::list<AnswerSection> &answerSection,
            const std::pmr::list<QuestionSection> &questions_section,
            const DnsRequestBody &requestBody
        );

        static std::vector<uint8_t> createMxResponse(
            uint16_t flags,
            const std::pmr::list<AnswerSectionWithPriority> &answerWithPriority,
            const std::pmr::list<QuestionSection> &questions_section,
            const DnsRequestBody &requestBody
        );

    private:
        // Helper function to add a domain name to the response
        static void addDomainName(std::vector<uint8_t> &packet, const std::string &domainName);

        // Helper function to convert domain name to DNS format
        static std::vector<uint8_t> domainToDnsFormat(const std::string &domain);

        static void addUint16(std::vector<uint8_t> &packet, uint16_t value);

        static void addUint32(std::vector<uint8_t> &packet, uint32_t value);

        static std::vector<uint8_t> ipToBytes(const std::string &ipAddress);

        static std::vector<uint8_t> parseIPv6Address(const std::string &ipv6Address);

        //static void addRPacket(std::vector<uint8_t> &responsePacket,const AnswerSection &answerSection, const QuestionSection &questions_section);

        static std::vector<uint8_t> createBody(
            const DnsRequestBody &requestBody,
            const std::pmr::list<QuestionSection> &questions_section,
            uint16_t flags,
            uint16_t answerCount);
    };

    class ParseResponse {
    public:
        static DnsRequestBody parseDnsRequest(const std::vector<uint8_t> &data);

        static void splitDomain(const std::string& domain, std::string& subdomain, std::string& mainDomain);
    private:
    };

    class Log {
    public:
        // Helper function to convert a byte vector to a hex string
        static std::string bytesToHex(const std::vector<uint8_t> &bytes);

        static std::string bytesToHex(const std::vector<uint16_t> &bytes);
    };
}


#endif //DNS_H
