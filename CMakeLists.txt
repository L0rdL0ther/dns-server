cmake_minimum_required(VERSION 3.29)
project(DnsServer)

set(CMAKE_CXX_STANDARD 20)


set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Kütüphane yollarını ayarlayın
set(CMAKE_PREFIX_PATH "/usr/local" CACHE PATH "Path to installed libraries")

# Kütüphanelerin dizinlerini ayarla
include_directories("/usr/include")
include_directories("/usr/local/include")
link_directories("/usr/lib")
link_directories("/usr/local/lib")

# Gerekli paketleri bul
find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(PQXX REQUIRED libpqxx)

add_executable(DnsServer src/main.cpp
        src/header/udp.h
        src/header/dnsRequestBody.h
        src/header/dns.cpp
        src/header/dns.h
        src/header/dnsEnum.h
        src/database/postegre.h)


# Kütüphaneleri bağla
target_link_libraries(DnsServer PRIVATE
        Boost::system
        OpenSSL::SSL
        OpenSSL::Crypto
        pthread
        ${PQXX_LIBRARIES}
)