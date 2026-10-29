#include "http.h"
#include "protect.h"

#include <stdexcept>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

constexpr int CONNECT_TIMEOUT_SECONDS = 5;
constexpr int IO_TIMEOUT_SECONDS = 10;
constexpr int HTTPS_PORT = 443;

namespace
{
    VERIFY_NOT_INLINE void configureClient(httplib::SSLClient& cli)
    {
        VERIFY_VM_BEGIN;
        cli.set_connection_timeout(CONNECT_TIMEOUT_SECONDS, 0);
        cli.set_read_timeout(IO_TIMEOUT_SECONDS, 0);
        cli.set_write_timeout(IO_TIMEOUT_SECONDS, 0);
        cli.enable_server_certificate_verification(true);
        // Never forward encrypted credentials to a redirect destination.
        cli.enable_server_hostname_verification(true);
        cli.set_follow_location(false);
        cli.set_max_timeout(15000);
        cli.set_payload_max_length(1024 * 1024);
        VERIFY_VM_END;
    }
}

VERIFY_NOT_INLINE Dhv2HttpResponse dhv2Post(const std::string& host, const std::string& path, const std::string& body, const std::map<std::string, std::string>& headers)
{
    VERIFY_VM_BEGIN;

    httplib::SSLClient cli(host);
    configureClient(cli);

    httplib::Headers hdrs;
    hdrs.emplace("Content-Type", "application/json");
    hdrs.emplace("Accept", "*/*");
    for (const auto& h : headers) hdrs.emplace(h.first, h.second);

    httplib::Result res = cli.Post(path, hdrs, body, "application/json");


    if (!res) throw std::runtime_error("HTTPS请求失败: " + host + path + "，错误码=" + std::to_string(static_cast<int>(res.error())));

    VERIFY_VM_END;
    Dhv2HttpResponse response;
    response.status = res->status;
    response.body = res->body;
    return response;
}

VERIFY_NOT_INLINE int checkDhv2Endpoint(const std::string& host)
{
    try
    {
        return dhv2Post(host, "/api/dhv2/session", "{}", {}).status;
    }
    catch (...)
    {
        return -1;
    }
}