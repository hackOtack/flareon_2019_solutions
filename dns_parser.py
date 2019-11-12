from scapy.all import *
from scapy.layers.dns import DNSRR

packets = rdpcap('/home/zerogravity/malware/flare-on/4 - Dnschess/capture.pcap')
res_ips = []

for pkt in packets:
    pkt_time = pkt.sprintf('%sent.time%')
    # process DNS responses only
    if DNSRR in pkt and pkt.sport == 53:
    # responses
       print('[**] Detected DNS RR Message at: ' + pkt_time)
       print(pkt.an.rdata)
       print(pkt.qd.qname)
       res_ips.append(pkt.an.rdata)
       print("*********************************************")


for ip in res_ips:
    ip_array = ip.split('.')
    ip_array_int = []
    for item in ip_array:
        ip_array_int.append(int(item))
    if (ip_array_int[0] == 127) and not (ip_array_int[3] & 1) and not (ip_array_int[2] & 1):
        print(ip)