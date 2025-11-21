#!/usr/bin/env python3
"""
new_extractor.py (legacy-compatible outputs for packet / uniflow / biflow)

Produces:
 - data/packet_features/packet_<basename>.csv  (legacy packet schema with timestamp)
 - data/uniflow_features/uniflow_<basename>.csv (legacy uniflow schema with ip_src/ip_dst)
 - data/biflow_features/biflow_<basename>.csv   (legacy biflow schema with ip_src/ip_dst)

Behavior:
 - Timestamp format: "MM/DD/YYYY, HH:MM:SS:microseconds" (single quoted by CSV writer)
 - MQTT flag fields: numeric when present, empty when absent (matches your old CSV)
 - Uses existing live_scripts/extractor.py helpers when available.
"""
import argparse
import importlib.util
import sys
from pathlib import Path
from datetime import datetime, timezone
import csv

# Optional dependencies
try:
    import pandas as pd
except Exception:
    pd = None

# scapy optional (used for packet-level fallback)
try:
    from scapy.all import rdpcap
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.packet import Raw
except Exception:
    rdpcap = None
    IP = TCP = UDP = Raw = None

# ---------------------------------------------------------------------
# dynamic import of extractor.py (search common repo locations)
# ---------------------------------------------------------------------
def import_extractor_module():
    here = Path(__file__).resolve().parent
    candidates = [
        here / "extractor.py",
        here.parent / "extractor.py",
        here.parent / "live_scripts" / "extractor.py",
        here.parent.parent / "live_scripts" / "extractor.py",
        Path("/mnt/data/extractor.py"),
    ]
    for cand in candidates:
        if cand.exists():
            spec = importlib.util.spec_from_file_location("extractor_module", str(cand))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            return mod, cand
    return None, None

# ---------------------------------------------------------------------
# legacy timestamp format helper (UTC)
# returns string without extra quotes (CSV writer will quote)
# ---------------------------------------------------------------------
def format_legacy_ts(ts):
    dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    return f'{dt.month:02}/{dt.day:02}/{dt.year}, {dt.hour:02}:{dt.minute:02}:{dt.second:02}:{dt.microsecond:06}'

# ---------------------------------------------------------------------
# helpers to convert mqtt flag values: return numeric if present, else empty string
# ---------------------------------------------------------------------
def maybe_int_field(val):
    if val is None:
        return ""
    # allow bools and ints
    if isinstance(val, bool):
        return 1 if val else 0
    try:
        return int(val)
    except Exception:
        return ""

# ---------------------------------------------------------------------
# Build packet-level rows in legacy schema
# ---------------------------------------------------------------------
def extract_packet_legacy_rows(pcap_path, extractor_mod):
    if rdpcap is None:
        raise RuntimeError("scapy/rdpcap not available - ensure scapy is installed")

    pkts = rdpcap(str(pcap_path))
    rows = []

    # optional helpers from extractor module
    _MQTT_OK = getattr(extractor_mod, "_MQTT_OK", False)
    _parse_mqtt_connect_flags = getattr(extractor_mod, "_parse_mqtt_connect_flags", None)
    _mqtt_control_type_from_first_byte = getattr(extractor_mod, "_mqtt_control_type_from_first_byte", None)
    MQTT_layer = getattr(extractor_mod, "MQTT", None)

    for p in pkts:
        if not p.haslayer(IP):
            continue
        ip = p[IP]
        ts = getattr(p, "time", 0.0)
        timestamp = format_legacy_ts(ts)

        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
        proto_num = int(getattr(ip, "proto", 0))

        # ip flags best-effort
        ip_flags = int(getattr(ip, "flags", 0) or 0)
        ip_flag_df = 1 if (ip_flags & 0x2) else 0
        ip_flag_mf = 1 if (ip_flags & 0x1) else 0
        ip_flag_rb = 1 if (ip_flags & 0x4) else 0

        protocol_str = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else "OTHER")

        # transport defaults
        src_port = ""
        dst_port = ""
        tcp_flag_res = ""
        tcp_flag_ns = ""
        tcp_flag_cwr = ""
        tcp_flag_ecn = ""
        tcp_flag_urg = ""
        tcp_flag_ack = ""
        tcp_flag_push = ""
        tcp_flag_reset = ""
        tcp_flag_syn = ""
        tcp_flag_fin = ""

        mqtt_messagetype = ""
        mqtt_messagelength = ""
        mqtt_flag_uname = ""
        mqtt_flag_passwd = ""
        mqtt_flag_retain = ""
        mqtt_flag_qos = ""
        mqtt_flag_willflag = ""
        mqtt_flag_clean = ""
        mqtt_flag_reserved = ""

        if p.haslayer(TCP):
            t = p[TCP]
            src_port = int(t.sport)
            dst_port = int(t.dport)
            flags = int(t.flags)
            tcp_flag_cwr = 1 if (flags & 0x80) else 0
            tcp_flag_ecn = 1 if (flags & 0x40) else 0
            tcp_flag_urg = 1 if (flags & 0x20) else 0
            tcp_flag_ack = 1 if (flags & 0x10) else 0
            tcp_flag_push = 1 if (flags & 0x08) else 0
            tcp_flag_reset = 1 if (flags & 0x04) else 0
            tcp_flag_syn = 1 if (flags & 0x02) else 0
            tcp_flag_fin = 1 if (flags & 0x01) else 0
        elif p.haslayer(UDP):
            u = p[UDP]
            src_port = int(u.sport)
            dst_port = int(u.dport)

        # MQTT detection: prefer extractor module layer, then Raw fallback
        try:
            mqtt_found = False
            if _MQTT_OK and MQTT_layer is not None and p.haslayer(MQTT_layer):  # type: ignore
                m = p[MQTT_layer]  # type: ignore
                mqtt_messagetype = maybe_int_field(getattr(m, "type", None) or getattr(m, "msgtype", None))
                mqtt_messagelength = maybe_int_field(getattr(m, "length", None))
                # parse connect flags if present
                try:
                    mqtt_flag_uname = maybe_int_field(getattr(m, "username", None) is not False)
                except Exception:
                    mqtt_flag_uname = ""
                try:
                    mqtt_flag_passwd = maybe_int_field(getattr(m, "password", None) is not False)
                except Exception:
                    mqtt_flag_passwd = ""
                mqtt_found = mqtt_messagetype != ""
            else:
                if p.haslayer(Raw):
                    raw = bytes(p[Raw].load)
                    if _mqtt_control_type_from_first_byte is not None:
                        ctl = _mqtt_control_type_from_first_byte(raw)
                    else:
                        ctl = (raw[0] >> 4) & 0x0F if raw and len(raw) > 0 else 0
                    if ctl == 1:
                        mqtt_messagetype = 1
                        mqtt_messagelength = len(raw)
                        if _parse_mqtt_connect_flags is not None:
                            has_u, has_p = _parse_mqtt_connect_flags(raw)
                            mqtt_flag_uname = maybe_int_field(has_u)
                            mqtt_flag_passwd = maybe_int_field(has_p)
                        mqtt_found = True
                    elif ctl == 2:
                        mqtt_messagetype = 2
                        mqtt_messagelength = len(raw)
                        mqtt_found = True
                    elif ctl in (3,4,8):
                        mqtt_messagetype = ctl
                        mqtt_messagelength = len(raw)
                        mqtt_found = True
            if mqtt_found:
                protocol_str = "MQTT"
        except Exception:
            # ignore parsing errors - leave mqtt fields empty
            pass

        ttl = int(getattr(ip, "ttl", 0))
        ip_len = int(getattr(ip, "len", len(p)))

        is_attack = 0

        # Build row with exact legacy header names and ordering.
        row = {
            "timestamp": format_legacy_ts(ts),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol_str,
            "ttl": ttl,
            "ip_len": ip_len,
            "ip_flag_df": ip_flag_df,
            "ip_flag_mf": ip_flag_mf,
            "ip_flag_rb": ip_flag_rb,
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_flag_res": tcp_flag_res,
            "tcp_flag_ns": tcp_flag_ns,
            "tcp_flag_cwr": tcp_flag_cwr,
            "tcp_flag_ecn": tcp_flag_ecn,
            "tcp_flag_urg": tcp_flag_urg,
            "tcp_flag_ack": tcp_flag_ack,
            "tcp_flag_push": tcp_flag_push,
            "tcp_flag_reset": tcp_flag_reset,
            "tcp_flag_syn": tcp_flag_syn,
            "tcp_flag_fin": tcp_flag_fin,
            "mqtt_messagetype": mqtt_messagetype,
            "mqtt_messagelength": mqtt_messagelength,
            "mqtt_flag_uname": mqtt_flag_uname,
            "mqtt_flag_passwd": mqtt_flag_passwd,
            "mqtt_flag_retain": mqtt_flag_retain,
            "mqtt_flag_qos": mqtt_flag_qos,
            "mqtt_flag_willflag": mqtt_flag_willflag,
            "mqtt_flag_clean": mqtt_flag_clean,
            "mqtt_flag_reserved": mqtt_flag_reserved,
            "is_attack": is_attack
        }

        rows.append(row)

    return rows

# ---------------------------------------------------------------------
# Construct legacy uniflow rows from biflow_rows + biflow_meta
# ---------------------------------------------------------------------
def build_uniflow_legacy_rows(biflow_rows, biflow_meta):
    urows = []
    for feat, meta in zip(biflow_rows, biflow_meta):
        # forward
        fwd = {
            "ip_src": meta.get("src", ""),
            "ip_dst": meta.get("dst", ""),
            "prt_src": int(feat.get("prt_src", 0)),
            "prt_dst": int(feat.get("prt_dst", 0)),
            "proto": int(feat.get("proto", 0)),
            "num_pkts": int(feat.get("fwd_num_pkts", 0)),
            "mean_iat": float(feat.get("fwd_mean_iat", 0.0)),
            "std_iat": float(feat.get("fwd_std_iat", 0.0)),
            "min_iat": float(feat.get("fwd_min_iat", 0.0)),
            "max_iat": float(feat.get("fwd_max_iat", 0.0)),
            "mean_pkt_len": float(feat.get("fwd_mean_pkt_len", 0.0)),
            "num_bytes": int(feat.get("fwd_num_bytes", 0)),
            "num_psh_flags": int(feat.get("fwd_num_psh_flags", 0)),
            "num_rst_flags": int(feat.get("fwd_num_rst_flags", 0)),
            "num_urg_flags": int(feat.get("fwd_num_urg_flags", 0)),
            "std_pkt_len": float(feat.get("fwd_std_pkt_len", 0.0)),
            "min_pkt_len": float(feat.get("fwd_min_pkt_len", 0.0)),
            "max_pkt_len": float(feat.get("fwd_max_pkt_len", 0.0)),
            "is_attack": int(feat.get("is_attack", 0))
        }
        urows.append(fwd)

        # backward (reverse)
        bwd = {
            "ip_src": meta.get("dst", ""),
            "ip_dst": meta.get("src", ""),
            "prt_src": int(feat.get("prt_dst", 0)),
            "prt_dst": int(feat.get("prt_src", 0)),
            "proto": int(feat.get("proto", 0)),
            "num_pkts": int(feat.get("bwd_num_pkts", 0)),
            "mean_iat": float(feat.get("bwd_mean_iat", 0.0)),
            "std_iat": float(feat.get("bwd_std_iat", 0.0)),
            "min_iat": float(feat.get("bwd_min_iat", 0.0)),
            "max_iat": float(feat.get("bwd_max_iat", 0.0)),
            "mean_pkt_len": float(feat.get("bwd_mean_pkt_len", 0.0)),
            "num_bytes": int(feat.get("bwd_num_bytes", 0)),
            "num_psh_flags": int(feat.get("bwd_num_psh_flags", 0)),
            "num_rst_flags": int(feat.get("bwd_num_rst_flags", 0)),
            "num_urg_flags": int(feat.get("bwd_num_urg_flags", 0)),
            "std_pkt_len": float(feat.get("bwd_std_pkt_len", 0.0)),
            "min_pkt_len": float(feat.get("bwd_min_pkt_len", 0.0)),
            "max_pkt_len": float(feat.get("bwd_max_pkt_len", 0.0)),
            "is_attack": int(feat.get("is_attack", 0))
        }
        urows.append(bwd)
    return urows

# ---------------------------------------------------------------------
# Construct legacy biflow rows (with ip_src, ip_dst first)
# ---------------------------------------------------------------------
def build_biflow_legacy_rows(biflow_rows, biflow_meta):
    brows = []
    for feat, meta in zip(biflow_rows, biflow_meta):
        row = {
            "ip_src": meta.get("src", ""),
            "ip_dst": meta.get("dst", ""),
            "prt_src": int(feat.get("prt_src", 0)),
            "prt_dst": int(feat.get("prt_dst", 0)),
            "proto": int(feat.get("proto", 0)),
            "fwd_num_pkts": int(feat.get("fwd_num_pkts", 0)),
            "bwd_num_pkts": int(feat.get("bwd_num_pkts", 0)),
            "fwd_mean_iat": float(feat.get("fwd_mean_iat", 0.0)),
            "bwd_mean_iat": float(feat.get("bwd_mean_iat", 0.0)),
            "fwd_std_iat": float(feat.get("fwd_std_iat", 0.0)),
            "bwd_std_iat": float(feat.get("bwd_std_iat", 0.0)),
            "fwd_min_iat": float(feat.get("fwd_min_iat", 0.0)),
            "bwd_min_iat": float(feat.get("bwd_min_iat", 0.0)),
            "fwd_max_iat": float(feat.get("fwd_max_iat", 0.0)),
            "bwd_max_iat": float(feat.get("bwd_max_iat", 0.0)),
            "fwd_mean_pkt_len": float(feat.get("fwd_mean_pkt_len", 0.0)),
            "bwd_mean_pkt_len": float(feat.get("bwd_mean_pkt_len", 0.0)),
            "fwd_std_pkt_len": float(feat.get("fwd_std_pkt_len", 0.0)),
            "bwd_std_pkt_len": float(feat.get("bwd_std_pkt_len", 0.0)),
            "fwd_min_pkt_len": float(feat.get("fwd_min_pkt_len", 0.0)),
            "bwd_min_pkt_len": float(feat.get("bwd_min_pkt_len", 0.0)),
            "fwd_max_pkt_len": float(feat.get("fwd_max_pkt_len", 0.0)),
            "bwd_max_pkt_len": float(feat.get("bwd_max_pkt_len", 0.0)),
            "fwd_num_bytes": int(feat.get("fwd_num_bytes", 0)),
            "bwd_num_bytes": int(feat.get("bwd_num_bytes", 0)),
            "fwd_num_psh_flags": int(feat.get("fwd_num_psh_flags", 0)),
            "bwd_num_psh_flags": int(feat.get("bwd_num_psh_flags", 0)),
            "fwd_num_rst_flags": int(feat.get("fwd_num_rst_flags", 0)),
            "bwd_num_rst_flags": int(feat.get("bwd_num_rst_flags", 0)),
            "fwd_num_urg_flags": int(feat.get("fwd_num_urg_flags", 0)),
            "bwd_num_urg_flags": int(feat.get("bwd_num_urg_flags", 0)),
            "is_attack": int(feat.get("is_attack", 0))
        }
        brows.append(row)
    return brows

# ---------------------------------------------------------------------
# main
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--out-dir", default="data")
    args = parser.parse_args()

    pcap_path = Path(args.pcap).resolve()
    if not pcap_path.exists():
        print("[ERROR] pcap not found:", pcap_path)
        sys.exit(1)

    out_root = Path(args.out_dir).resolve()
    packet_dir = out_root / "packet_features"
    uniflow_dir = out_root / "uniflow_features"
    biflow_dir = out_root / "biflow_features"
    for d in (packet_dir, uniflow_dir, biflow_dir):
        d.mkdir(parents=True, exist_ok=True)

    extractor_mod, extractor_path = import_extractor_module()
    if extractor_mod is None:
        print("[ERROR] extractor.py not found in expected locations.")
        sys.exit(1)
    print(f"[INFO] Loaded extractor module from: {extractor_path}")

    base = pcap_path.stem.replace(".", "_")

    # 1) produce raw biflow rows (using existing extractor)
    try:
        biflow_rows, biflow_meta = extractor_mod.extract_biflow_29(pcap_path)
    except Exception as e:
        print("[ERROR] extract_biflow_29 failed:", e)
        raise

    if not biflow_rows:
        (biflow_dir / f"biflow_{base}.csv").write_text("")
        (uniflow_dir / f"uniflow_{base}.csv").write_text("")
    else:
        # build legacy biflow rows and write CSV
        biflow_legacy = build_biflow_legacy_rows(biflow_rows, biflow_meta)
        biflow_out = biflow_dir / f"biflow_{base}.csv"
        biflow_header = [
            "ip_src","ip_dst","prt_src","prt_dst","proto","fwd_num_pkts","bwd_num_pkts",
            "fwd_mean_iat","bwd_mean_iat","fwd_std_iat","bwd_std_iat","fwd_min_iat","bwd_min_iat",
            "fwd_max_iat","bwd_max_iat","fwd_mean_pkt_len","bwd_mean_pkt_len","fwd_std_pkt_len","bwd_std_pkt_len",
            "fwd_min_pkt_len","bwd_min_pkt_len","fwd_max_pkt_len","bwd_max_pkt_len","fwd_num_bytes","bwd_num_bytes",
            "fwd_num_psh_flags","bwd_num_psh_flags","fwd_num_rst_flags","bwd_num_rst_flags","fwd_num_urg_flags","bwd_num_urg_flags","is_attack"
        ]
        if pd is not None:
            pd.DataFrame(biflow_legacy).to_csv(biflow_out, index=False, columns=biflow_header)
        else:
            with open(biflow_out, "w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=biflow_header, extrasaction="ignore")
                w.writeheader()
                for r in biflow_legacy:
                    w.writerow(r)
        print(f"[OK] Wrote biflow CSV: {biflow_out} (rows: {len(biflow_legacy)})")

        # build legacy uniflow rows and write CSV
        uniflow_legacy = build_uniflow_legacy_rows(biflow_rows, biflow_meta)
        uniflow_out = uniflow_dir / f"uniflow_{base}.csv"
        uniflow_header = [
            "ip_src","ip_dst","prt_src","prt_dst","proto","num_pkts","mean_iat","std_iat","min_iat","max_iat",
            "mean_pkt_len","num_bytes","num_psh_flags","num_rst_flags","num_urg_flags","std_pkt_len","min_pkt_len","max_pkt_len","is_attack"
        ]
        if pd is not None:
            pd.DataFrame(uniflow_legacy).to_csv(uniflow_out, index=False, columns=uniflow_header)
        else:
            with open(uniflow_out, "w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=uniflow_header, extrasaction="ignore")
                w.writeheader()
                for r in uniflow_legacy:
                    w.writerow(r)
        print(f"[OK] Wrote uniflow CSV: {uniflow_out} (rows: {len(uniflow_legacy)})")

    # 2) packet-level legacy CSV (per-packet)
    pkt_rows = extract_packet_legacy_rows(pcap_path, extractor_mod)
    packet_out = packet_dir / f"packet_{base}.csv"
    packet_header = [
        "timestamp","src_ip","dst_ip","protocol","ttl","ip_len",
        "ip_flag_df","ip_flag_mf","ip_flag_rb",
        "src_port","dst_port",
        "tcp_flag_res","tcp_flag_ns","tcp_flag_cwr","tcp_flag_ecn","tcp_flag_urg",
        "tcp_flag_ack","tcp_flag_push","tcp_flag_reset","tcp_flag_syn","tcp_flag_fin",
        "mqtt_messagetype","mqtt_messagelength",
        "mqtt_flag_uname","mqtt_flag_passwd","mqtt_flag_retain","mqtt_flag_qos",
        "mqtt_flag_willflag","mqtt_flag_clean","mqtt_flag_reserved","is_attack"
    ]
    with open(packet_out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=packet_header, extrasaction="ignore")
        w.writeheader()
        for r in pkt_rows:
            w.writerow(r)
    print(f"[OK] Wrote packet CSV (legacy schema): {packet_out} (rows: {len(pkt_rows)})")

    print("\n[COMPLETE] Extraction finished.")
    print(f"  Biflow CSV:  {biflow_out}")
    print(f"  Uniflow CSV: {uniflow_out}")
    print(f"  Packet CSV:  {packet_out}")
    print("\nNext: append each CSV into your *_normal.csv files WITHOUT the header.")
    print(f"PowerShell examples:")
    print(f"  (Get-Content {packet_out})[1..-1] | Add-Content {packet_dir / 'normal.csv'}")
    print(f"  (Get-Content {uniflow_out})[1..-1] | Add-Content {uniflow_dir / 'uniflow_normal.csv'}")
    print(f"  (Get-Content {biflow_out})[1..-1] | Add-Content {biflow_dir / 'biflow_normal.csv'}")

if __name__ == "__main__":
    main()
