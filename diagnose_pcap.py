#!/usr/bin/env python3
# diagnose_pcap.py — run locally where scapy is installed

from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict, Counter
import sys
p = r"D:\Research\Code\MQTT V2\pcap_files\capture_00009_20251115004512.pcap"
try:
    pkts = rdpcap(p)
except Exception as e:
    print("ERROR reading pcap:", e); sys.exit(1)

print(f"Total packets: {len(pkts)}\n")

# counts
src_counts = Counter()
dst_counts = Counter()
proto_counts = Counter()
flows = defaultdict(lambda: {"fwd":0,"bwd":0,"fwd_pkts":[], "bwd_pkts": []})

for i,pkt in enumerate(pkts):
    if not pkt.haslayer(IP):
        continue
    ip = pkt[IP]
    src = ip.src; dst = ip.dst
    src_counts[src]+=1; dst_counts[dst]+=1
    if pkt.haslayer(TCP):
        proto='TCP'; sport=int(pkt[TCP].sport); dport=int(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        proto='UDP'; sport=int(pkt[UDP].sport); dport=int(pkt[UDP].dport)
    else:
        proto='OTHER'; sport=0; dport=0
    proto_counts[proto]+=1
    key_fwd = (src, dst, sport, dport, proto)
    key_bwd = (dst, src, dport, sport, proto)
    if key_fwd in flows:
        flows[key_fwd]["fwd"] += 1
        flows[key_fwd]["fwd_pkts"].append(i)
    elif key_bwd in flows:
        flows[key_bwd]["bwd"] += 1
        flows[key_bwd]["bwd_pkts"].append(i)
    else:
        flows[key_fwd]["fwd"] += 1
        flows[key_fwd]["fwd_pkts"].append(i)

print("Top source IPs:")
for ip,c in src_counts.most_common(10):
    print(f"  {ip}: {c}")
print("\nTop dest IPs:")
for ip,c in dst_counts.most_common(10):
    print(f"  {ip}: {c}")
print("\nProto counts:", dict(proto_counts))

# Inspect flows involving attacker IP
ATT="192.168.0.101"
BROKER="192.168.0.100"
count_total=0
print("\nFlows involving attacker or broker (sample):")
for k,v in list(flows.items())[:400]:
    s,d,sp,dp,pr = k
    if ATT in (s,d) or BROKER in (s,d):
        count_total+=1
        fcnt, bcnt = v["fwd"], v["bwd"]
        print(f"{s}:{sp} -> {d}:{dp} ({pr})  fwd={fcnt} bwd={bcnt}")
print(f"\nTotal flows examined involving attacker/broker: {count_total}")

# Show flows that are strictly unidirectional (likely scans)
uni=0; bi=0
for k,v in flows.items():
    if (v["fwd"]>0 and v["bwd"]==0) or (v["bwd"]>0 and v["fwd"]==0):
        uni+=1
    else:
        bi+=1
print(f"\nUni-directional flows: {uni}, Bi-directional flows: {bi}")

# Print 20 largest flows by total pkt count
top = sorted(flows.items(), key=lambda kv: kv[1]["fwd"]+kv[1]["bwd"], reverse=True)[:20]
print("\nTop flows (by packet count):")
for k,v in top:
    s,d,sp,dp,pr=k
    print(f"{s}:{sp}->{d}:{dp} {pr} total={v['fwd']+v['bwd']} (f={v['fwd']} b={v['bwd']})")
