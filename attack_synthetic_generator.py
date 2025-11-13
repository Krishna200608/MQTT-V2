#!/usr/bin/env python3
"""
Offline attack traffic *simulator* producing PCAP(s) and logs to mimic the dataset's
high-level statistics. THIS SCRIPT DOES NOT SEND PACKETS ON THE NETWORK BY DEFAULT.

Usage:
python attack_synthetic_generator.py --scenario scan_a --duration 60 --write out_scanA.pcap

Scenarios supported: scan_a, scan_su, sparta, mqtt_bf
Default is dry-run (prints stats). Use --write to write PCAP/log files.
"""
import argparse, random, time
from scapy.all import Ether, IP, TCP, UDP, wrpcap
import math

SCENARIOS = ["scan_a","scan_su","sparta","mqtt_bf"]

def generate_scan_a(duration, pkt_rate):
    # Aggressive TCP scan-like packets: SYN packets to many ports
    packets = []
    total_pkts = int(duration * pkt_rate)
    dst_ip = "10.0.0.50"
    base_ports = list(range(20, 2000))[:200]  # reduce to 200 ports as example
    for i in range(total_pkts):
        sport = random.randint(1024, 65535)
        dport = random.choice(base_ports)
        p = Ether()/IP(dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S")
        packets.append(p)
    return packets

def generate_scan_su(duration, pkt_rate):
    packets = []
    total_pkts = int(duration * pkt_rate)
    dst_ip = "10.0.0.50"
    base_ports = list(range(1, 1024))[:150]
    for i in range(total_pkts):
        sport = random.randint(1024, 65535)
        dport = random.choice(base_ports)
        payload = bytes(random.getrandbits(8) for _ in range(random.randint(10,50)))
        p = Ether()/IP(dst=dst_ip)/UDP(sport=sport, dport=dport)/payload
        packets.append(p)
    return packets

def generate_sparta(duration, attempts_per_sec):
    # Simulate SSH connection attempts with SYN followed by RST or no reply
    packets = []
    dst_ip = "10.0.0.50"
    for t in range(int(duration*attempts_per_sec)):
        sport = random.randint(1024,65535)
        p = Ether()/IP(dst=dst_ip)/TCP(sport=sport, dport=22, flags="S")
        packets.append(p)
    return packets

def generate_mqtt_bf(duration, attempts_per_sec):
    # Simulate MQTT login attempts recorded as TCP connections with small payloads
    packets = []
    dst_ip = "10.0.0.50"
    for t in range(int(duration*attempts_per_sec)):
        sport = random.randint(1024,65535)
        # craft a small MQTT CONNECT-like payload (not full implementation)
        payload = b"\x10" + bytes([random.randint(0,255)])*10
        p = Ether()/IP(dst=dst_ip)/TCP(sport=sport, dport=1883, flags="PA")/payload
        packets.append(p)
    return packets

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", choices=SCENARIOS, required=True)
    p.add_argument("--duration", type=int, default=60, help="seconds")
    p.add_argument("--pkt-rate", type=float, default=50.0)
    p.add_argument("--attempts-per-sec", type=float, default=5.0)
    p.add_argument("--write", help="Write output PCAP file")
    p.add_argument("--dry-run", action="store_true", default=False)
    args = p.parse_args()

    if args.scenario=="scan_a":
        packets = generate_scan_a(args.duration, args.pkt_rate)
    elif args.scenario=="scan_su":
        packets = generate_scan_su(args.duration, args.pkt_rate)
    elif args.scenario=="sparta":
        packets = generate_sparta(args.duration, args.attempts_per_sec)
    elif args.scenario=="mqtt_bf":
        packets = generate_mqtt_bf(args.duration, args.attempts_per_sec)
    else:
        raise SystemExit("Unknown scenario")

    print(f"Generated {len(packets)} packets for {args.scenario}. Approx duration {args.duration}s.")
    # summarize sizes & timestamps (simple)
    sizes = [len(bytes(p)) for p in packets]
    print("Packet count:", len(packets))
    print("Avg packet size:", sum(sizes)/len(sizes) if sizes else 0)
    if args.write:
        print(f"Writing PCAP to {args.write} (offline)")
        wrpcap(args.write, packets)
        print("Done.")
    else:
        if args.dry_run:
            print("Dry run mode: not writing files. Use --write <file> to write PCAP locally.")
        else:
            print("No write requested. Run with --write to persist PCAP.")

if __name__ == "__main__":
    main()
