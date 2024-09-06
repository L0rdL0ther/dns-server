#ifndef UDP_H
#define UDP_H

#include <iostream>
#include <iomanip>
#include <cstring>
#include <memory>
#include <unistd.h>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

namespace DNS {

    class UDP {
    public:

        static UDP& getInstance() {
            static UDP instance;
            return instance;
        }

        void setPort(int sPort) {
            port = sPort;
        }

        void bindUdp() {
            if (port == -1) {
                port = 53;
            }
            createSocket();
            if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("bind failed");
                exit(EXIT_FAILURE);
            }
        }


        void setMaxLine(int smaxline) {
            MAXLINE = smaxline;
        }

        void setDataCallback(void (*callback)(const char*, size_t, const sockaddr_in&)) {
            dataCallback = callback;
        }

        void listenForData() {
            char buffer[MAXLINE];
            while (true) {
                len = sizeof(client_addr);
                int n = recvfrom(sockfd, buffer, MAXLINE, MSG_WAITALL, (struct sockaddr*)&client_addr, &len);
                if (n < 0) {
                    perror("recvfrom failed");
                    continue;
                }

                if (dataCallback) {
                    dataCallback(buffer, n, client_addr);
                }
            }
        }

        void sendResponse(const char* response, int response_length, int flags) {
            if (sendto(sockfd, response, response_length, flags, (const struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
                perror("sendto failed");
            }
        }


        // Destructor
        ~UDP() {
            close(sockfd);
        }

        int getSocketFd() const { return sockfd; }
        const sockaddr_in& getServerAddr() const { return server_addr; }
        const sockaddr_in& getClientAddr() const { return client_addr; }

    private:

        UDP() : sockfd(-1), port(-1) {}

        void createSocket() {
            if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                perror("socket creation failed");
                exit(EXIT_FAILURE);
            }
            memset(&server_addr, 0, sizeof(server_addr));
            memset(&client_addr, 0, sizeof(client_addr));

            server_addr.sin_family = AF_INET;
            server_addr.sin_addr.s_addr = INADDR_ANY;
            server_addr.sin_port = htons(port);
        }

        int sockfd;
        int port;
        int MAXLINE;
        socklen_t len;
        void (*dataCallback)(const char*, size_t, const sockaddr_in&);
        sockaddr_in server_addr, client_addr;
        UDP(const UDP&) = delete;
        UDP& operator=(const UDP&) = delete;
    };

}

#endif // UDP_H
