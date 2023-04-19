#include "cmdline.h"
#include "VPNServer.h"
#include "VPNClient.h"

int main(int argc, char* argv[]) {
    cmdline::parser parser;
    parser.add<std::string>("mode", 'm', "mode(server/client)", true, "", cmdline::oneof<std::string>("server", "client", "ssh", "ftp"));
    parser.add<std::string>("server", 'h', "host", true);
    parser.add<int>("port", 'p', "port", false, 4433, cmdline::range(1, 65535));
    parser.add<std::string>("ca", 'C', "ca path", false, "/tmp/certs/ca.crt");
    parser.add<std::string>("cert", 'c', "cert path", false, "/tmp/certs/server.crt");
    parser.add<std::string>("key", 'k', "key path", false, "/tmp/certs/server.key");
    parser.add<std::string>("virtual", 'v', "tun virtual ip CIDR", false, "192.168.53.0/24");
    parser.add<std::string>("allow", 'a', "allow pass ip CIDR", false, "192.168.60.0/24");
    parser.parse_check(argc, argv);
    if (parser.get<std::string>("mode") == "server") {
        VPNServer vpnServer(parser.get<std::string>("server"), parser.get<int>("port"),
                            parser.get<std::string>("ca"), parser.get<std::string>("cert"), parser.get<std::string>("key"), parser.get<std::string>("virtual"));
        vpnServer.Listen();
    } else if (parser.get<std::string>("mode") == "client") {
        VPNClient vpnClient(parser.get<std::string>("server"), parser.get<int>("port"),parser.get<std::string>("ca"), parser.get<std::string>("allow"));
        vpnClient.Connect();
    }
    return 0;
}
