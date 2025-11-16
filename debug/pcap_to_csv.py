#!/usr/bin/env python3
"""
Extract per-packet metadata from capture.pcap → capture_packets.csv
Just place this script in the same folder as capture.pcap and run:

    python pcap_to_csv.py

Output: capture_packets.csv
"""

from scapy.all import *
import pandas as pd
import os
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.packet import Raw


PCAP_FILE = "capture.pcap"
OUT_CSV = "capture_packets.csv"

def decode_tcp_flags(pkt):
    flags = []
    if pkt.flags & 0x02: flags.append("SYN")
    if pkt.flags & 0x10: flags.append("ACK")
    if pkt.flags & 0x01: flags.append("FIN")
    if pkt.flags & 0x04: flags.append("RST")
    if pkt.flags & 0x08: flags.append("PSH")
    if pkt.flags & 0x20: flags.append("URG")
    if pkt.flags & 0x40: flags.append("ECE")
    if pkt.flags & 0x80: flags.append("CWR")
    return "|".join(flags) if flags else ""

def decode_mqtt(pkt):
    try:
        layer = pkt.getlayer("MQTT")
        if layer is None:
            return ""
        if hasattr(layer, "msgtype"):
            return str(layer.msgtype)
        return str(layer)
    except:
        return ""

def analyze_pcap(input_pcap, output_csv):
    if not os.path.exists(input_pcap):
        print(f"[ERROR] PCAP file not found: {input_pcap}")
        return

    print(f"[INFO] Loading: {input_pcap}")
    rows = []

    pkts = PcapReader(input_pcap)

    for i, pkt in enumerate(pkts):
        row = {
            "index": i,
            "time": pkt.time,
            "pkt_len": len(pkt),
            "src_ip": "",
            "dst_ip": "",
            "src_port": "",
            "dst_port": "",
            "protocol": "",
            "tcp_flags": "",
            "udp_len": "",
            "icmp_type": "",
            "icmp_code": "",
            "mqtt_type": "",
        }

        # -------------------------
        # IPv4
        # -------------------------
        if IP in pkt:
            row["src_ip"] = pkt[IP].src
            row["dst_ip"] = pkt[IP].dst
            row["protocol"] = pkt[IP].proto

        # -------------------------
        # TCP
        # -------------------------
        if TCP in pkt:
            row["src_port"] = pkt[TCP].sport
            row["dst_port"] = pkt[TCP].dport
            row["tcp_flags"] = decode_tcp_flags(pkt[TCP])

        # -------------------------
        # UDP
        # -------------------------
        if UDP in pkt:
            row["src_port"] = pkt[UDP].sport
            row["dst_port"] = pkt[UDP].dport
            row["udp_len"] = pkt[UDP].len

        # -------------------------
        # ICMP
        # -------------------------
        if ICMP in pkt:
            row["icmp_type"] = pkt[ICMP].type
            row["icmp_code"] = pkt[ICMP].code

        # -------------------------
        # MQTT
        # -------------------------
        mqtt_type = decode_mqtt(pkt)
        if mqtt_type:
            row["mqtt_type"] = mqtt_type

        rows.append(row)

    df = pd.DataFrame(rows)
    df.to_csv(output_csv, index=False)

    print(f"[OK] Saved: {output_csv}   ({len(df)} packets)")

if __name__ == "__main__":
    analyze_pcap(PCAP_FILE, OUT_CSV)
