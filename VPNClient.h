//
// Created by yll20 on 2023/04/18.
//

#ifndef HUSTVPN_VPNCLIENT_H
#define HUSTVPN_VPNCLIENT_H

#include <string>

class VPNClient {
public:
    VPNClient(std::string server_ip, int server_port, std::string ca_path, std::string allow_ip_cidr);
    void Connect() const;

    std::string server_addr;
    int server_port;
    std::string ca_path;
    std::string allow_ip_cidr;
};


#endif //HUSTVPN_VPNCLIENT_H
