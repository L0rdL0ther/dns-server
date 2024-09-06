#include <iostream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT 53
#define MAXLINE 1024


// Hexadecimal veriyi ekrana yazdırma
void printHex(const std::vector<uint8_t>& data) {
    for (auto byte : data) {
        printf("%02x ", byte);
    }
    std::cout << std::endl;
}

// DNS isteğini çözümleme
void parseDNSRequest(const std::vector<uint8_t>& data) {
    if (data.size() < 12) {
        std::cerr << "Veri yetersiz!" << std::endl;
        return;
    }

    // Transaction ID
    uint16_t transactionID = (data[0] << 8) | data[1];
    std::cout << "\nTransaction ID: 0x" << std::hex << transactionID << '\n';

    // Flags
    uint16_t flags = (data[2] << 8) | data[3];
    std::cout << "Flags: 0x" << std::hex << flags << '\n';

    // Questions
    uint16_t questions = (data[4] << 8) | data[5];
    std::cout << "Questions: " << std::dec << questions << '\n';

    // Answer RRs
    uint16_t answerRRs = (data[6] << 8) | data[7];
    std::cout << "Answer RRs: " << std::dec << answerRRs <<'\n';

    // Authority RRs
    uint16_t authorityRRs = (data[8] << 8) | data[9];
    std::cout << "Authority RRs: " << std::dec << authorityRRs <<'\n';

    // Additional RRs
    uint16_t additionalRRs = (data[10] << 8) | data[11];
    std::cout << "Additional RRs: " << std::dec << additionalRRs << '\n';

    // Sorgu kısmı
    size_t index = 12;
    std::cout << "Query: ";
    while (data[index] != 0) {
        uint8_t length = data[index];
        index++;
        for (int i = 0; i < length; ++i) {
            std::cout << (char)data[index + i];
        }
        index += length;
        if (data[index] != 0) std::cout << ".";
    }
    index++; // Null byte
    std::cout << '\n';

    // Query Type
    uint16_t queryType = (data[index] << 8) | data[index + 1];
    std::cout << "Query Type: 0x" << std::hex << queryType << '\n';
    index += 2;

    // Query Class
    uint16_t queryClass = (data[index] << 8) | data[index + 1];
    std::cout << "Query Class: 0x" << std::hex << queryClass << '\n';
}

void create_dns_response(const char* request, char* response, int& response_length) {
    // Extract Transaction ID from request
    unsigned short transaction_id = (request[0] << 8) | request[1];

    // DNS Header
    unsigned char header[] = {
        (unsigned char)(transaction_id >> 8), (unsigned char)(transaction_id & 0xff), // Transaction ID
        0x81, 0x80, // Flags: Standard query response, no error
        0x00, 0x01, // Questions: 1
        0x00, 0x01, // Answer RRs: 1
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00  // Additional RRs: 0
    };

    // DNS Question Section (same as in request)
    const unsigned char question[] = {
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
        0x03, 0x63, 0x6f, 0x6d, // com
        0x00, // End of name
        0x00, 0x01, // Type: A (IPv4 address)
        0x00, 0x01  // Class: IN (Internet)
    };

    // DNS Answer Section
    const unsigned char answer[] = {
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
        0x03, 0x63, 0x6f, 0x6d, // com
        0x00, // End of name
        0x00, 0x01, // Type: A (IPv4 address)
        0x00, 0x01, // Class: IN (Internet)
        0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
        0x00, 0x04, // Data length: 4 bytes
        0x5d, 0xb8, 0xd8, 0x22  // IP Address: 93.184.216.34
    };

    // Construct the response
    response_length = sizeof(header) + sizeof(question) + sizeof(answer);
    memcpy(response, header, sizeof(header));
    memcpy(response + sizeof(header), question, sizeof(question));
    memcpy(response + sizeof(header) + sizeof(question), answer, sizeof(answer));
}


int main() {
    int sockfd;
    char buffer[MAXLINE];
    struct sockaddr_in server_addr, client_addr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "DNS Server listening on port 53" << '\n';

    while (true) {
        socklen_t len = sizeof(client_addr);
        int n = recvfrom(sockfd, (char*)buffer, MAXLINE, MSG_WAITALL, (struct sockaddr*)&client_addr, &len);
        if (n < 0) {
            perror("recvfrom failed");
            continue;
        }

        std::cout << "Received DNS request from client" << '\n';

        // Print received request (for debugging)
        std::cout << "DNS Request Content:" << '\n';
        for (int i = 0; i < n; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)buffer[i] << " ";
            if ((i + 1) % 16 == 0) std::cout << '\n';
        }

        parseDNSRequest(std::vector<uint8_t>(buffer, buffer + n));

        std::cout << std::dec << '\n';

        // Prepare DNS response
        char response[MAXLINE];
        int response_length;
        create_dns_response(buffer, response, response_length);

        // Print the response for debugging
        std::cout << "DNS Response Content:" << '\n';
        for (int i = 0; i < response_length; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)response[i] << " ";
            if ((i + 1) % 16 == 0) std::cout << '\n';
        }
        std::cout << std::dec << '\n';

        // Send DNS response
        sendto(sockfd, response, response_length, MSG_CONFIRM, (const struct sockaddr*)&client_addr, len);
        std::cout << "DNS response sent to client" << '\n';
    }

    close(sockfd);
    return 0;
}