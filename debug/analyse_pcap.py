import os
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd

def analyze_pcap(filepath):
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"[ERROR] Failed to read {filepath}: {e}")
        return None

    total = len(packets)
    tcp = 0
    udp = 0
    icmp = 0

    flows = set()
    ports = {}

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
            flows.add((src, dst, sport, dport, 'TCP'))
            ports[dport] = ports.get(dport, 0) + 1

        # UDP
        elif pkt.haslayer(UDP):
            udp += 1
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
            flows.add((src, dst, sport, dport, 'UDP'))
            ports[dport] = ports.get(dport, 0) + 1

    # time stats
    if timestamps:
        start = min(timestamps)
        end = max(timestamps)
        duration = end - start if end > start else 0.000001
        pps = total / duration
    else:
        start = end = duration = pps = 0

    top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "filename": os.path.basename(filepath),
        "total_packets": total,
        "tcp_packets": tcp,
        "udp_packets": udp,
        "unique_flows": len(flows),
        "duration_sec": duration,
        "packet_rate_pps": round(pps, 2),
        "top_ports": str(top_ports)
    }


def main():
    folder = os.path.dirname(os.path.abspath(__file__))

    results = []
    print("\n===== Analyzing PCAP Files =====\n")

    for file in sorted(os.listdir(folder)):
        if file.endswith(".pcap"):
            path = os.path.join(folder, file)
            print(f"[INFO] Processing: {file}")
            data = analyze_pcap(path)

            if data:
                results.append(data)

    if results:
        df = pd.DataFrame(results)
        output_path = os.path.join(folder, "pcap_analysis_summary.csv")
        df.to_csv(output_path, index=False)

        print("\n===== SUMMARY GENERATED =====")
        print(f"Saved summary to: {output_path}")
        print(df.to_string(index=False))
    else:
        print("[WARN] No pcap files analyzed.")


if __name__ == "__main__":
    main()
