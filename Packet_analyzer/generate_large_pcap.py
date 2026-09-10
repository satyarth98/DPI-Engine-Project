#!/usr/bin/env python3
"""
Generate a much larger PCAP file by replaying the traffic patterns from
generate_test_pcap.py many times over, with randomized source ports/IPs
so each "session" looks like a distinct flow.
"""

import random
import sys
from generate_test_pcap import (
    PCAPWriter, create_ethernet_header, create_ip_header, create_tcp_header,
    create_udp_header, create_tls_client_hello, create_http_request, create_dns_query
)

NUM_ROUNDS = int(sys.argv[1]) if len(sys.argv) > 1 else 500

def random_user_ip():
    return f"192.168.{random.randint(1, 20)}.{random.randint(2, 250)}"

def main():
    writer = PCAPWriter('large_test.pcap')
    gateway_mac = 'aa:bb:cc:dd:ee:ff'

    tls_connections = [
        ('142.250.185.206', 'www.google.com', 443),
        ('142.250.185.110', 'www.youtube.com', 443),
        ('157.240.1.35', 'www.facebook.com', 443),
        ('157.240.1.174', 'www.instagram.com', 443),
        ('104.244.42.65', 'twitter.com', 443),
        ('52.94.236.248', 'www.amazon.com', 443),
        ('23.52.167.61', 'www.netflix.com', 443),
        ('140.82.114.4', 'github.com', 443),
        ('104.16.85.20', 'discord.com', 443),
        ('35.186.224.25', 'zoom.us', 443),
        ('35.186.227.140', 'web.telegram.org', 443),
        ('99.86.0.100', 'www.tiktok.com', 443),
        ('35.186.224.47', 'open.spotify.com', 443),
        ('192.0.78.24', 'www.cloudflare.com', 443),
        ('13.107.42.14', 'www.microsoft.com', 443),
        ('17.253.144.10', 'www.apple.com', 443),
    ]
    http_connections = [
        ('93.184.216.34', 'example.com', 80),
        ('185.199.108.153', 'httpbin.org', 80),
    ]
    dns_queries = [
        'www.google.com', 'www.youtube.com', 'www.facebook.com', 'api.twitter.com',
    ]

    seq_base = 1000
    blocked_source_ip = '192.168.1.50'

    for _ in range(NUM_ROUNDS):
        user_mac = '00:11:22:33:44:55'
        user_ip = random_user_ip()

        for dst_ip, sni, dst_port in tls_connections:
            src_port = random.randint(49152, 65535)

            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)

            tcp = create_tcp_header(dst_port, src_port, seq_base + 1000, seq_base + 1, 0x12)
            ip = create_ip_header(dst_ip, user_ip, 6, len(tcp))
            eth_r = create_ethernet_header(gateway_mac, user_mac)
            writer.write_packet(eth_r + ip + tcp)

            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x10)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)

            tls_data = create_tls_client_hello(sni)
            tcp = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x18)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(tls_data))
            writer.write_packet(eth + ip + tcp + tls_data)

            seq_base += 10000

        for dst_ip, host, dst_port in http_connections:
            src_port = random.randint(49152, 65535)
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)

            http_data = create_http_request(host)
            tcp = create_tcp_header(src_port, dst_port, seq_base + 1, 1, 0x18)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(http_data))
            writer.write_packet(eth + ip + tcp + http_data)

            seq_base += 10000

        dns_server = '8.8.8.8'
        for domain in dns_queries:
            src_port = random.randint(49152, 65535)
            dns_data = create_dns_query(domain)
            eth = create_ethernet_header(user_mac, gateway_mac)
            udp = create_udp_header(src_port, 53, len(dns_data))
            ip = create_ip_header(user_ip, dns_server, 17, len(udp) + len(dns_data))
            writer.write_packet(eth + ip + udp + dns_data)

        for i in range(5):
            src_port = random.randint(49152, 65535)
            dst_ip = '172.217.0.100'
            eth = create_ethernet_header('00:11:22:33:44:56', gateway_mac)
            tcp = create_tcp_header(src_port, 443, seq_base, 0, 0x02)
            ip = create_ip_header(blocked_source_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
            seq_base += 1000

    writer.close()
    total_per_round = len(tls_connections) * 4 + len(http_connections) * 2 + len(dns_queries) + 5
    print(f"Created large_test.pcap with {NUM_ROUNDS} rounds (~{total_per_round * NUM_ROUNDS} packets)")


if __name__ == '__main__':
    main()
