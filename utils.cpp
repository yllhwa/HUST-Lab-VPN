//
// Created by yll20 on 2023/04/19.
//

#include "utils.h"

std::string int_to_ip(uint32_t ip_addr)
{
    std::string result;
    for (int i = 0; i < 4; ++i)
    {
        result += std::to_string((ip_addr >> ((3 - i) * 8)) & 0xFF); // 右移和位运算提取每个八位
        if (i < 3)
        {
            result += ".";
        }
    }
    return result;
}

int cidr_to_ip_and_mask(const char *cidr, uint32_t *ip, uint32_t *mask)
{
    uint8_t a, b, c, d, bits;
    if (sscanf(cidr, "%hhu.%hhu.%hhu.%hhu/%hhu", &a, &b, &c, &d, &bits) < 5)
    {
        return -1; /* didn't convert enough of CIDR */
    }
    if (bits > 32)
    {
        return -1; /* Invalid bit count */
    }
    *ip =
            (a << 24UL) |
            (b << 16UL) |
            (c << 8UL) |
            (d);
    *mask = (0xFFFFFFFFUL << (32 - bits)) & 0xFFFFFFFFUL;
    return 0;
}

std::string get_ip_by_cidr(const std::string& cidr, int index)
{
    uint32_t ip;
    uint32_t mask;
    uint32_t first_ip;
    uint32_t last_ip;
    if (cidr_to_ip_and_mask(cidr.c_str(), &ip, &mask) < 0)
    {
        return "";
    }
    first_ip = ip & mask;
    last_ip = first_ip | (~mask);
    if (index == -1)
    {
        return int_to_ip(last_ip);
    }
    if (index < 0 || index > last_ip - first_ip)
    {
        return "";
    }
    return int_to_ip(first_ip + index) + cidr.substr(cidr.find_last_of('/'), -1);
}