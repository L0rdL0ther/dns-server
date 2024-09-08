#include "dns.h"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include "dnsEnum.h"
#include "dnsRequestBody.h"


std::vector<uint8_t> DNS::CreateResponse::createResponse(
    uint16_t flags,
    const std::pmr::list<AnswerSection> &answerSection,
    const std::pmr::list<QuestionSection> &questions_section,
    const DnsRequestBody &requestBody
) {
    uint16_t answerCount = answerSection.size();
    std::vector<uint8_t> responsePacket = createBody(requestBody, questions_section, flags, answerCount);

    // Answer Section
    for (const auto &section: answerSection) {
        addDomainName(responsePacket, section.query);
        addUint16(responsePacket, static_cast<int>(section.queryType));
        addUint16(responsePacket, static_cast<int>(section.queryClass));
        addUint32(responsePacket, section.ttl);

        std::vector<uint8_t> rDataBytes;
        switch (static_cast<int>(section.queryType)) {
            case static_cast<int>(DnsEnum::QueryType::A):
                rDataBytes = ipToBytes(section.rData);
                break;
            case static_cast<int>(DnsEnum::QueryType::CNAME):
                rDataBytes = domainToDnsFormat(section.rData);
                break;
            case static_cast<int>(DnsEnum::QueryType::AAAA):
                rDataBytes = parseIPv6Address(section.rData);
                break;
            case static_cast<int>(DnsEnum::QueryType::MX):
                rDataBytes = domainToDnsFormat(section.rData);
                break;
        }
        addUint16(responsePacket, rDataBytes.size());
        responsePacket.insert(responsePacket.end(), rDataBytes.begin(), rDataBytes.end());
    }

    // MX Specific Answer Section

    return responsePacket;
}

std::vector<uint8_t> DNS::CreateResponse::createMxResponse(
    uint16_t flags,
    const std::pmr::list<AnswerSectionWithPriority> &answerWithPriority,
    const std::pmr::list<QuestionSection> &questions_section, const DnsRequestBody &requestBody) {

    uint16_t answerCount = answerWithPriority.size();
    std::vector<uint8_t> responsePacket = createBody(requestBody, questions_section, flags, answerCount);

    for (const auto &section: answerWithPriority) {
        addDomainName(responsePacket, section.query); // Domain name of the mail exchanger
        addUint16(responsePacket, static_cast<int>(DnsEnum::QueryType::MX)); // MX type
        addUint16(responsePacket, static_cast<int>(DnsEnum::QueryClass::IN)); // Class IN
        addUint32(responsePacket, section.ttl); // TTL

        std::vector<uint8_t> rDataBytes;
        addUint16(rDataBytes, section.priority); // Priority

        std::vector<uint8_t> domainBytes = domainToDnsFormat(section.rData); // Mail exchanger domain
        rDataBytes.insert(rDataBytes.end(), domainBytes.begin(), domainBytes.end());

        addUint16(responsePacket, rDataBytes.size()); // Length field for MX record
        responsePacket.insert(responsePacket.end(), rDataBytes.begin(), rDataBytes.end());
    }
    return responsePacket;
}

void DNS::CreateResponse::addDomainName(std::vector<uint8_t> &packet, const std::string &domain) {
    size_t pos = 0;
    while (pos < domain.size()) {
        size_t end = domain.find('.', pos);
        if (end == std::string::npos) {
            end = domain.size();
        }
        size_t labelLength = end - pos;
        if (labelLength > 63) {
            throw std::runtime_error("Label length exceeds 63 bytes");
        }
        packet.push_back(static_cast<uint8_t>(labelLength));
        packet.insert(packet.end(), domain.begin() + pos, domain.begin() + end);
        pos = end + 1;
    }
    packet.push_back(0x00); // End of domain name
}

std::vector<uint8_t> DNS::CreateResponse::domainToDnsFormat(const std::string &domain) {
    std::vector<uint8_t> dnsFormat;
    size_t pos = 0;
    size_t nextPos;

    while ((nextPos = domain.find('.', pos)) != std::string::npos) {
        std::string label = domain.substr(pos, nextPos - pos);
        dnsFormat.push_back(static_cast<uint8_t>(label.size()));
        dnsFormat.insert(dnsFormat.end(), label.begin(), label.end());
        pos = nextPos + 1;
    }

    std::string lastLabel = domain.substr(pos);
    dnsFormat.push_back(static_cast<uint8_t>(lastLabel.size()));
    dnsFormat.insert(dnsFormat.end(), lastLabel.begin(), lastLabel.end());
    dnsFormat.push_back(0x00); // End of domain name

    return dnsFormat;
}

void DNS::CreateResponse::addUint16(std::vector<uint8_t> &packet, uint16_t value) {
    packet.push_back(value >> 8);
    packet.push_back(value & 0xFF);
}

void DNS::CreateResponse::addUint32(std::vector<uint8_t> &packet, uint32_t value) {
    packet.push_back(value >> 24);
    packet.push_back((value >> 16) & 0xFF);
    packet.push_back((value >> 8) & 0xFF);
    packet.push_back(value & 0xFF);
}

std::string DNS::Log::bytesToHex(const std::vector<uint8_t> &bytes) {
    std::stringstream ss;
    for (auto byte: bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    return ss.str();
}

std::string DNS::Log::bytesToHex(const std::vector<uint16_t> &bytes) {
    std::stringstream ss;
    for (auto byte: bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    return ss.str();
}

std::vector<uint8_t> DNS::CreateResponse::ipToBytes(const std::string &ipAddress) {
    std::vector<uint8_t> bytes;
    std::istringstream stream(ipAddress);
    std::string segment;
    while (std::getline(stream, segment, '.')) {
        int byte = std::stoi(segment);
        if (byte < 0 || byte > 255) {
            throw std::out_of_range("Byte value out of range");
        }
        bytes.push_back(static_cast<uint8_t>(byte));
    }
    if (bytes.size() != 4) {
        throw std::invalid_argument("Invalid IP address format");
    }
    return bytes;
}

std::vector<uint8_t> DNS::CreateResponse::parseIPv6Address(const std::string &ipv6Address) {
    std::vector<uint8_t> rDataBytes;
    std::stringstream ss(ipv6Address);
    std::string byte;

    while (std::getline(ss, byte, ':')) {
        auto word = static_cast<uint16_t>(std::stoi(byte, nullptr, 16));
        addUint16(rDataBytes, word);
    }

    if (rDataBytes.size() != 16) {
        throw std::invalid_argument("Invalid IPv6 address format");
    }

    return rDataBytes;
}

std::vector<uint8_t> DNS::CreateResponse::createBody(
    const DnsRequestBody &requestBody,
    const std::pmr::list<QuestionSection> &questions_section,
    uint16_t flags,
    uint16_t answerCount
) {
    std::vector<uint8_t> responsePacket;
    addUint16(responsePacket, requestBody.transactionID); // Transaction ID
    addUint16(responsePacket, flags); // Flags
    addUint16(responsePacket, questions_section.size()); // Number of Questions
    addUint16(responsePacket, answerCount); // Number of Answer RRs
    addUint16(responsePacket, requestBody.authorityRRs); // Number of Authority RRs
    addUint16(responsePacket, requestBody.additionalRRs); // Number of Additional RRs

    // Questions Section
    for (const auto &section: questions_section) {
        addDomainName(responsePacket, section.query);
        addUint16(responsePacket, section.type);
        addUint16(responsePacket, section.queryClass);
    }

    return responsePacket;
}

DnsRequestBody DNS::ParseResponse::parseDnsRequest(const std::vector<uint8_t> &data) {
    DnsRequestBody body;

    if (data.size() < 12) {
        std::cerr << "Error: Data size too small." << std::endl;
        return body;
    }

    body.transactionID = (data[0] << 8) | data[1];
    body.flags = (data[2] << 8) | data[3];
    body.questions = (data[4] << 8) | data[5];
    body.answerRRs = (data[6] << 8) | data[7];
    body.authorityRRs = (data[8] << 8) | data[9];
    body.additionalRRs = (data[10] << 8) | data[11];

    uint16_t questionCount = body.questions;
    size_t queryStartIndex = 12;
    while (questionCount > 0) {
        std::string query;
        while (data[queryStartIndex] != 0) {
            uint8_t length = data[queryStartIndex];
            queryStartIndex++;
            query += std::string(data.begin() + queryStartIndex, data.begin() + queryStartIndex + length);
            queryStartIndex = queryStartIndex + length;
            if (data[queryStartIndex] != 0) query += ".";
        }
        queryStartIndex++;
        uint16_t queryType = (data[queryStartIndex] << 8) | data[queryStartIndex + 1];
        queryStartIndex += 2;
        uint16_t queryClass = (data[queryStartIndex] << 8) | data[queryStartIndex + 1];
        body.questionsSection.push_back(QuestionSection(query, queryType, queryClass));
        questionCount--;
    }

    return body;
}

void DNS::ParseResponse::splitDomain(const std::string &domain, std::string &subdomain, std::string &mainDomain) {
    size_t pos = domain.rfind('.');
    if (pos != std::string::npos) {
        size_t secondLastDot = domain.rfind('.', pos - 1);
        if (secondLastDot != std::string::npos) {
            subdomain = domain.substr(0, secondLastDot);
            mainDomain = domain.substr(secondLastDot + 1);
        } else {
            subdomain = "";
            mainDomain = domain;
        }
    } else {
        subdomain = "";
        mainDomain = domain;
    }
}
