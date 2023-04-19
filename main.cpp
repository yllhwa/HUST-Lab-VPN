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
    parser.parse_check(argc, argv);
    if (parser.get<std::string>("mode") == "server") {
        VPNServer vpnServer(parser.get<std::string>("server"), parser.get<int>("port"),
                            parser.get<std::string>("ca"), parser.get<std::string>("cert"), parser.get<std::string>("key"));
        vpnServer.Listen();
    } else if (parser.get<std::string>("mode") == "client") {
        VPNClient vpnClient(parser.get<std::string>("server"), parser.get<int>("port"),parser.get<std::string>("ca"));
        vpnClient.Connect();
    }
    return 0;
}
