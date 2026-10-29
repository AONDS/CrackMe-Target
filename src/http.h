#ifndef VERIFY_HTTP_UTILS
#define VERIFY_HTTP_UTILS
#include <map>
#include <string>

struct Dhv2HttpResponse
{
    int status = 0;
    std::string body;
};

Dhv2HttpResponse dhv2Post(const std::string& host, const std::string& path, const std::string& body, const std::map<std::string, std::string>& headers);
int checkDhv2Endpoint(const std::string& host);

#endif