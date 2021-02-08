#!/usr/bin/env python3

import json 
import argparse 
import dpkt
import binascii
import socket
import scapy.all as scapy
import copy
import base64

AT1 = "iOwIVM5mu1Qc5QsUR11iFhgc3aB//ITN8hivvCrfSn8="
AT2 = "GtV6G6z3BWTvxqd0Eh4zD81UZlsDtOWQtF1/9kGRBTc="
AT3 = "8DJNxln1Gv65fYpjwat2fYkRTCz023YUT1yKZWCfFWI="

AT1 = base64.b64decode(AT1)
AT2 = base64.b64decode(AT2)
AT3 = base64.b64decode(AT3)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    args = parser.parse_args()
    pcap_file = args.pcap
    return pcap_file

def find_attack(data):
    if AT1 in data:
        print("attack 1 found")
    if AT2 in data:
        print("attack 2 found")
    if AT3 in data:
        print("attack 3 found") 

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
    for key in frags.keys(): 
        off_list = {}
        for val in frags[key]: 
            if val.haslayer("Raw"):
                off = getattr(val["IP"], "frag")
                data = val["Raw"].load
                off_list[off] = data
        if len(off_list) == 1:
            find_attack(off_list[0])
        else:
            highest_val = sorted(off_list)[-1]
            data = b''
            for i in range(1, highest_val+1):
                data = data + off_list[i]
            print(data)
            find_attack(data)


def main():
    pcap_file = parse_args()
    parse_pcap(pcap_file)

main()
