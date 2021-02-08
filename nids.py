#!/usr/bin/env python3

import json 
import argparse 
import binascii
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

def write_json(atk, pkt):
    vals = {
        "timestamp": int(pkt.time),
        "source": {
            "mac_address": getattr(pkt["Ethernet"], "src"),
            "ipv4_address": getattr(pkt["IP"], "src"),
            "tcp_port": getattr(pkt["TCP"], "sport")
        },
        "target": {
            "mac_address": getattr(pkt["Ethernet"], "dst"),
            "ipv4_address": getattr(pkt["IP"], "src"),
            "tcp_port": getattr(pkt["TCP"], "dport")
        },
        "attack": atk
    }
    json_vals = json.dumps(vals)
    print(json_vals)

def find_attack(data, pkt):
    if AT1 in data:
        write_json(1, pkt)
    if AT2 in data:
        write_json(2, pkt)
    if AT3 in data:
        write_json(3, pkt)

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
                off_list[off] = [data, val]
        if len(off_list) == 1:
            find_attack(off_list[0][0], off_list[0][1])
        else:
            highest_val = sorted(off_list)[-1]
            data = b''
            for i in range(1, highest_val+1):
                data = data + off_list[i][0]
            find_attack(data, off_list[1][1])


def main():
    pcap_file = parse_args()
    parse_pcap(pcap_file)

main()
