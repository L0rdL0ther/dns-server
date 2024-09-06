cmake_minimum_required(VERSION 3.29)
project(DnsServer)

set(CMAKE_CXX_STANDARD 20)

add_executable(DnsServer src/main.cpp
        src/header/udp.h
        src/header/dnsRequestBody.h
        src/header/dns.cpp
        src/header/dns.h
        src/header/dnsEnum.h)
