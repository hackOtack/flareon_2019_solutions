from dnslib import DNSRecord
import binascii
import array
from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR
from kaitaistruct import KaitaiStream, BytesIO

import dns_packet

from dns_packet import DnsPacket


packets = rdpcap('/home/zerogravity/malware/flare-on/4 - Dnschess/capture.pcap')

res_ips = {}

for pkt in packets:
    #print(pkt)
    pkt_time = pkt.sprintf('%sent.time%')


    # process queries
    '''
    # ------ SELECT/FILTER DNS MSGS
    if DNSQR in pkt and pkt.dport == 53:
    # queries
       print('[**] Detected DNS QR Message at: ' + pkt_time)
       print(pkt.qd.qname)
       print(".......................")
    '''
    # process responses only
    if DNSRR in pkt and pkt.sport == 53:
       res_ips[pkt.an.rdata] = pkt.qd.qname

byte_array = []
byte_array_hex = ["79", "5A", "0B8", "0BC", "0EC", "0D3", "0DF", "0DD", "99", "0A5", "0B6", "0AC", "15", "36", "85", "8D", "9", "8", "77", "52", "4D", "71", "54", "7D", "0A7", "0A7", "8", "16", "0FD", "0D7"]

magicStr = [0] * 60
for hex in byte_array_hex:
    i = int(hex, 16)
    byte_array.append(i)

print(byte_array)
print(len(byte_array))
i = -1
while i < 61:
    i = i + 1
    for ip, domain in res_ips.items():
        ip_array = ip.split('.')
        ip_array_int = []
        for item in ip_array:
            ip_array_int.append(int(item))
        if ip_array_int[0] == 127:
            if (ip_array_int[3] & 1) == 0:
                if (ip_array_int[2] & 15) == i:
                    try:
                        print(str(i) + ip + str(domain))
                        magicStr[2 * i] = ip_array_int[1] ^ byte_array[2 * i]
                        magicStr[2 * i + 1] = ip_array_int[1] ^ byte_array[2 * i + 1]
                    except Exception as e:
                        print(e)
magicString = ""
print(magicStr)
for item in magicStr:
    magicString = magicString + chr(item)
print(magicString)
