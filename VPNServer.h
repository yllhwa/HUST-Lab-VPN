//
// Created by yll20 on 2023/04/18.
//

#ifndef HUSTVPN_VPNSERVER_H
#define HUSTVPN_VPNSERVER_H


class VPNServer {
public:
    VPNServer(std::string bind_ip, int bind_port, std::string ca_path, std::string cert_path, std::string key_path);

    [[noreturn]] void Listen();

    ~VPNServer();

private:
    std::string bind_ip;
    int bind_port;
    std::string ca_path;
    std::string cert_path;
    std::string key_path;
};


#endif //HUSTVPN_VPNSERVER_H
