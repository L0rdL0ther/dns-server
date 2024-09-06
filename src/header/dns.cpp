//
// Created by yusuf on 9/5/24.
//

#include "dns.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include "dnsEnum.h"
#include "dnsRequestBody.h"


std::vector<uint8_t> DNS::CreateResponse::createResponse(
    uint16_t flags,
    const std::pmr::list<AnswerSectionWithPriority> &answerWithPriority,
    const std::pmr::list<AnswerSection> &answerSection,
    const std::pmr::list<QuestionSection> &questions_section,
    const DnsRequestBody &requestBody
) {
    std::vector<uint8_t> responsePacket;

    uint16_t answerCount = 0;
    if (!answerWithPriority.empty()) {
        answerCount += answerWithPriority.size();
    }
    if (!answerSection.empty()) {
        answerCount += answerSection.size();
    }

    // Header
    addUint16(responsePacket, requestBody.transactionID);
    addUint16(responsePacket, flags);
    addUint16(responsePacket, questions_section.size());
    addUint16(responsePacket, answerCount);
    addUint16(responsePacket, requestBody.authorityRRs);
    addUint16(responsePacket, requestBody.additionalRRs);

    for (const auto &section: questions_section) {
        addDomainName(responsePacket, section.query);
        addUint16(responsePacket, section.type);
        addUint16(responsePacket, section.type);
    }

    auto addAnswerSection = [&responsePacket](const auto &section) {
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
        }
        addUint16(responsePacket, rDataBytes.size());
        responsePacket.insert(responsePacket.end(), rDataBytes.begin(), rDataBytes.end());
    };


    for (const auto &section: answerSection) {
        addDomainName(responsePacket, section.query);
        addUint16(responsePacket, static_cast<int>(section.queryType));
        addUint16(responsePacket, static_cast<int>(section.queryClass));
        addUint32(responsePacket, section.ttl);
        addAnswerSection(section);
    }

    for (const auto &section: answerWithPriority) {
        addDomainName(responsePacket, section.query);
        addUint16(responsePacket, section.queryType);
        addUint16(responsePacket, section.queryClass);
        addUint16(responsePacket, section.priority);
        addUint32(responsePacket, section.ttl);
        addAnswerSection(section);
    }



    return responsePacket;
}

void DNS::CreateResponse::addDomainName(std::vector<uint8_t> &packet, const std::string &domain) {
    // Domain adını DNS formatına dönüştür
    std::vector<std::string> labels;
    size_t start = 0, end;
    while ((end = domain.find('.', start)) != std::string::npos) {
        labels.push_back(domain.substr(start, end - start));
        start = end + 1;
    }
    labels.push_back(domain.substr(start));

    for (const auto &label: labels) {
        if (label.empty() || label.size() > 63) {
            throw std::runtime_error("Invalid domain label length");
        }
        packet.push_back(label.size());
        packet.insert(packet.end(), label.begin(), label.end());
    }
    packet.push_back(0);
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
    body.additionalRRs = (data[10] << 8) | data[11];;

    uint16_t questionCount = body.questions;
    size_t queryStartIndex = 12;
    while (questionCount > 0) {
        std::string query;
        while (data[queryStartIndex] != 0) {
            uint8_t lenght = data[queryStartIndex];
            queryStartIndex++;
            query += std::string(data.begin() + queryStartIndex, data.begin() + queryStartIndex + lenght);
            queryStartIndex = queryStartIndex + lenght;
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
