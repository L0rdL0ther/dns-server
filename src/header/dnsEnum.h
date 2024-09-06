//
// Created by yusuf on 9/6/24.
//

#ifndef DNSENUM_H
#define DNSENUM_H


namespace DNS {

    class DnsEnum {
      public:
        enum class QueryType : uint16_t {
            A = 1,        // IPv4 Address
            NS = 2,       // Name Server
            CNAME = 5,    // Canonical Name (alias)
            SOA = 6,      // Start of Authority
            PTR = 12,     // Pointer (for reverse DNS lookups)
            MX = 15,      // Mail Exchange
            TXT = 16,     // Text Record
            AAAA = 28,    // IPv6 Address
            SRV = 33,     // Service Locator
            NAPTR = 35,   // Naming Authority Pointer
            CERT = 37,    // CERT
            DNAME = 39,   // DNAME
            ANY = 255     // Any Record
        };

        enum class ResponseFlags : uint16_t {
            QUERY = 0x0100,           // Standard query
            RESPONSE = 0x8180,        // Standard response, no error
            RECURSION_DESIRED = 0x0100,  // Recursion desired
            RECURSION_AVAILABLE = 0x0080, // Recursion available
            TRUNCATED = 0x0200,       // Truncated message
            AUTHENTICATED_DATA = 0x0020, // Authentic data (DNSSEC)
            CHECKING_DISABLED = 0x0010, // Checking disabled (DNSSEC)
            RESPONSE_NO_ERROR = 0x8180,  // Response with no error
            RESPONSE_FORMAT_ERROR = 0x8181,  // Format error in response
            RESPONSE_SERVER_FAILURE = 0x8182, // Server failure in response
            RESPONSE_NAME_ERROR = 0x8183,     // Name error (domain does not exist)
            RESPONSE_NOT_IMPLEMENTED = 0x8184, // Not implemented response
            RESPONSE_REFUSED = 0x8185      // Query refused
        };


        enum class QueryClass : uint16_t {
            IN = 1,       // Internet
            CS = 2,       // CSNET (Archaic)
            CH = 3,       // CHAOS
            HS = 4,       // Hesiod
            NONE = 254,   // QCLASS NONE
            ANY = 255     // QCLASS ANY
        };
    };

}

#endif //DNSENUM_H
