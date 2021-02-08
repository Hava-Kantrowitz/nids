#!/usr/bin/env python3

import json 
import argparse 
import dpkt
import binascii
import socket
import scapy.all as scapy
import copy

AT1 = "iOwIVM5mu1Qc5QsUR11iFhgc3aB//ITN8hivvCrfSn8=".encode('utf-8')
AT2 = "GtV6G6z3BWTvxqd0Eh4zD81UZ1sDtOWQtF1/9kGRBTc=".encode('utf-8')
AT3 = "8DJNxln1Gv65fYpjwat2fYkRTCz023YUT1yKZWCfFWI=".encode('utf-8')

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    args = parser.parse_args()
    pcap_file = args.pcap
    return pcap_file

#THIS CODE IS ADAPTED FROM SURAJ SINGH'S ARTICLE ON PYTHON CODES TO CALCULATE IPV4 CHECKSUMS FROM BITFORESTINFO.COM
def calc_cksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg): 
            a = ord(msg[i])
            b = ord(msg[i+1])
            s = s + (a + (b << 8))
        elif (i + 1) == len(msg):
            s += ord(msg[i])
        else:
            print("Error!")
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s

def inet_to_str(inet):
    return socket.inet_ntop(socket.AF_INET, inet)

def parse_pcap(pcap_file): 
    packets = scapy.PcapReader(pcap_file)
    frags = {}
    for pkt in packets: 
        if getattr(pkt["IP"], "proto") == 6:
            check = getattr(pkt["IP"], "chksum")
            new_pack = copy.deepcopy(pkt)
            del new_pack["IP"].chksum 
            new_pack = new_pack.__class__(bytes(new_pack))
            check2 = getattr(new_pack["IP"], "chksum")
            if check == check2: 
                idv = getattr(pkt["IP"], "id")
                if idv in frags.keys():
                    frags[idv].append(pkt)
                else: 
                    frags[idv] = [pkt] 
    print(len(frags)) 
    for key in frags.keys(): 
        off_list = {}
        for val in frags[key]: 
            if val.haslayer("Raw"):
                off = getattr(val["IP"], "frag")
                data = val["Raw"]
                off_list[off] = data
        highest_val = sorted(off_list)[-1]
        prev_i = 0
        data = ""
        for i in range(0, highest_val+1):
            full_data = off_list[i]
            data = full_data[prev_i:i]
        print(data)


def parse_pcap2(pcap_file):
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)  
    packets = {}
    for ts, buf in pcap: 
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        print(type(ip))
        calc_cksum(ip)
        if ip.p == 6: 
            print(repr(eth))
            df = bool(ip.off & dpkt.ip.IP_DF)
            mf = bool(ip.off & dpkt.ip.IP_MF)
            offset = ip.off & dpkt.ip.IP_OFFMASK
            if ip.id in packets.keys():
                packets[ip.id].append(ip)
            else: 
                packets[ip.id] = []
                packets[ip.id].append(ip)

    del packets[14736]
    for key in packets.keys():
        #print(key)
        off_dict = {}
        data = ""
        for val in packets[key]:
            offset = val.off & dpkt.ip.IP_OFFMASK
            data = val.data
            off_dict[offset] = data
        highest_val = sorted(off_dict)[-1]
        prev_i = 0
        for i in range(0, highest_val+1):
            full_data = off_dict[i] 
            data = data + full_data[prev_i:i]
        #print(data) 
        if AT1 in data: 
            print("attack 1 found!")
        if AT2 in data:
            print("attack 2 found!")
        if AT3 in data:
            print("attack 3 found!") 

    #print("AT1 is ", AT1)
                
            #print('IP: %s -> %s   (id=%d ttl=%d DF=%d MF=%d offset=%d)' % (inet_to_str(ip.src), inet_to_str(ip.dst), ip.id, ip.ttl, df, mf, offset))

def main():
    pcap_file = parse_args()
    parse_pcap(pcap_file)

main()
