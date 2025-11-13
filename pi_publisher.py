#!/usr/bin/env python3
"""
Lightweight Raspberry Pi publisher for MQTT message simulation.
Usage:
python pi_publisher.py --broker 192.168.1.100 --port 1883 --topic sensors/1 --qos 0 --rate 5 --messages-file patterns.csv
python pi_publisher.py --broker 192.168.0.100 --port 1883 --topic sensors/1 --qos 0 --rate 5 --messages-file patterns.csv
"""
import argparse, csv, time
import paho.mqtt.client as mqtt

def load_patterns(csv_path):
    rows = []
    with open(csv_path) as fh:
        r = csv.DictReader(fh)
        for rr in r:
            rows.append(rr.get("message",""))
    return rows

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--broker", required=True)
    p.add_argument("--port", type=int, default=1883)
    p.add_argument("--topic", default="sensors/1")
    p.add_argument("--qos", type=int, default=0)
    p.add_argument("--rate", type=float, default=1.0, help="messages per second")
    p.add_argument("--messages-file", help="CSV file with 'message' column")
    args = p.parse_args()
    client = mqtt.Client()
    client.connect(args.broker, args.port)
    messages = ["hello"] if not args.messages_file else load_patterns(args.messages_file)
    interval = 1.0 / max(args.rate, 1e-6)
    i = 0
    try:
        while True:
            payload = messages[i % len(messages)]
            client.publish(args.topic, payload=payload, qos=args.qos)
            i += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        client.disconnect()

if __name__ == "__main__":
    main()
