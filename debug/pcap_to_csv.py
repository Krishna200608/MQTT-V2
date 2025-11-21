#!/usr/bin/env python3
"""
pcap_to_csv.py — Convert ALL PCAP files in pcap_files/ → CSV

Usage:
    python pcap_to_csv.py

Output:
    pcap_files/<filename>.csv
"""

import os
import pandas as pd
from pathlib import Path
from scapy.all import PcapReader, IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP


# ------------------------------------------
# TCP flag decoding for readability
# ------------------------------------------
def decode_tcp_flags(pkt):
    flags = []
    if pkt.flags & 0x02: flags.append("SYN")
    if pkt.flags & 0x10: flags.append("ACK")
    if pkt.flags & 0x01: flags.append("FIN")
    if pkt.flags & 0x04: flags.append("RST")
    if pkt.flags & 0x08: flags.append("PSH")
    if pkt.flags & 0x20: flags.append("URG")
    return "|".join(flags) if flags else ""


# ------------------------------------------
# Convert one PCAP → CSV
# ------------------------------------------
def convert_pcap_to_csv(pcap_path):
    out_csv = str(pcap_path) + ".csv"
    print(f"[INFO] Processing {pcap_path.name} → {pcap_path.name}.csv")

    rows = []
    reader = PcapReader(str(pcap_path))

    for idx, pkt in enumerate(reader):
        row = {
            "index": idx,
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
        }

        # -------------- IP --------------
        if IP in pkt:
            row["src_ip"] = pkt[IP].src
            row["dst_ip"] = pkt[IP].dst
            row["protocol"] = pkt[IP].proto

        # -------------- TCP --------------
        if TCP in pkt:
            row["src_port"] = pkt[TCP].sport
            row["dst_port"] = pkt[TCP].dport
            row["tcp_flags"] = decode_tcp_flags(pkt[TCP])

        # -------------- UDP --------------
        if UDP in pkt:
            row["src_port"] = pkt[UDP].sport
            row["dst_port"] = pkt[UDP].dport
            row["udp_len"] = pkt[UDP].len

        # -------------- ICMP --------------
        if ICMP in pkt:
            row["icmp_type"] = pkt[ICMP].type
            row["icmp_code"] = pkt[ICMP].code

        rows.append(row)

    df = pd.DataFrame(rows)
    df.to_csv(out_csv, index=False)
    print(f"[OK] Saved CSV → {out_csv}   ({len(df)} packets)\n")


# ------------------------------------------
# Main Wrapper
# ------------------------------------------
if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    pcap_dir = root.parent / "pcap_files"   # adjust if script is elsewhere

    if not pcap_dir.exists():
        print(f"[ERROR] pcap_files folder not found at: {pcap_dir}")
        exit(1)

    pcaps = list(pcap_dir.glob("*.pcap"))

    if not pcaps:
        print("[WARN] No .pcap files found inside pcap_files/")
        exit(0)

    print(f"[INFO] Found {len(pcaps)} PCAP files.")
    for pcap in pcaps:
        convert_pcap_to_csv(pcap)

    print("[DONE] All PCAPs converted.")
