#!/usr/bin/env python3
"""
analyse_pcap.py — Improved PCAP summary tool

Enhancements:
 - Count TCP, UDP, ICMP
 - Combine flows bidirectionally (A→B and B→A = 1 flow)
 - Track TCP ports and UDP ports separately
 - Compute accurate PPS
 - Reads from project's pcap_files/ folder
 - Outputs clean summary CSV
"""

import os
from pathlib import Path
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
import pandas as pd


def flow_key(src, dst, sport, dport, proto):
    """Create direction-independent flow key."""
    if (src, sport) < (dst, dport):
        return (src, dst, sport, dport, proto)
    else:
        return (dst, src, dport, sport, proto)


def analyze_pcap(filepath):
    
    if filepath.stat().st_size < 64:
        print(f"[WARN] Skipping tiny or empty PCAP: {filepath.name}")
        return None
    
    try:
        packets = rdpcap(str(filepath))
    except Exception as e:
        print(f"[ERROR] Failed to read {filepath}: {e}")
        return None

    total = len(packets)
    tcp = 0
    udp = 0
    icmp = 0

    flows = set()
    tcp_ports = {}
    udp_ports = {}

    timestamps = []

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        timestamps.append(float(pkt.time))
        src = ip.src
        dst = ip.dst

        # TCP
        if pkt.haslayer(TCP):
            tcp += 1
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            flows.add(flow_key(src, dst, sport, dport, "TCP"))
            tcp_ports[dport] = tcp_ports.get(dport, 0) + 1

        # UDP
        elif pkt.haslayer(UDP):
            udp += 1
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
            flows.add(flow_key(src, dst, sport, dport, "UDP"))
            udp_ports[dport] = udp_ports.get(dport, 0) + 1

        # ICMP
        elif pkt.haslayer(ICMP):
            icmp += 1

    # Compute stats
    if timestamps:
        start = min(timestamps)
        end = max(timestamps)
        duration = max(end - start, 0.000001)
        pps = total / duration
    else:
        duration = pps = 0

    top_tcp = sorted(tcp_ports.items(), key=lambda x: x[1], reverse=True)[:5]
    top_udp = sorted(udp_ports.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "filename": os.path.basename(filepath),
        "total_packets": total,
        "tcp_packets": tcp,
        "udp_packets": udp,
        "icmp_packets": icmp,
        "unique_flows_bidir": len(flows),
        "duration_sec": round(duration, 3),
        "pps": round(pps, 2),
        "top_tcp_ports": str(top_tcp),
        "top_udp_ports": str(top_udp)
    }


def main():
    # project_root/scripts/analyse_pcap.py
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    pcap_dir = project_root / "pcap_files"

    print(f"\n===== Analyzing PCAP Files in: {pcap_dir} =====\n")

    if not pcap_dir.exists():
        print("[ERROR] pcap_files directory not found.")
        return

    results = []

    for file in sorted(pcap_dir.glob("*.pcap")):
        if not file.is_file():
            continue
        print(f"[INFO] Processing: {file.name}")
        data = analyze_pcap(file)
        if data:
            results.append(data)

    if not results:
        print("[WARN] No PCAPs analyzed.")
        return

    df = pd.DataFrame(results)
    out = script_dir / "pcap_analysis_summary.csv"
    df.to_csv(out, index=False)

    print("\n===== SUMMARY GENERATED =====")
    print(f"Saved summary → {out}")
    print(df.to_string(index=False))


if __name__ == "__main__":
    main()
