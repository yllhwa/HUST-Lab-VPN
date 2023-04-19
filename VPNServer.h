//
// Created by yll20 on 2023/04/18.
//

#ifndef HUSTVPN_VPNSERVER_H
#define HUSTVPN_VPNSERVER_H

#include <vector>

class VPNServer {
public:
    VPNServer(std::string bind_ip, int bind_port, std::string ca_path, std::string cert_path, std::string key_path, std::string virtual_ip_cidr);

    [[noreturn]] void Listen();

    ~VPNServer();

private:
    std::string bind_ip;
    int bind_port;
    std::string ca_path;
    std::string cert_path;
    std::string key_path;
    std::string virtual_ip_cidr;

    int setupTcpServer();

    int setupTunDevice();

    void initIPPool();

    void cleanPipes();
};


#endif //HUSTVPN_VPNSERVER_H
