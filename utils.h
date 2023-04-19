//
// Created by yll20 on 2023/04/19.
//

#ifndef HUSTVPN_UTILS_H
#define HUSTVPN_UTILS_H

#include <string>
#include <vector>

#define CHK_ERR(err, s) if ((err)==-1) { perror(s); exit(1); }
#define BUFFER_SIZE 4096

std::string get_ip_by_cidr(const std::string& cidr, int index);
std::string int_to_ip(uint32_t ip_addr);

std::string allocIPAddr();
std::string releaseIPAddr(const std::string &ip);
void init_ip_pool(const std::string& virtual_ip_cidr);

#endif //HUSTVPN_UTILS_H
