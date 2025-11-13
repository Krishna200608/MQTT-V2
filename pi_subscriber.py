#!/usr/bin/env python3
"""
Minimal subscriber to record messages to CSV (for dataset collection).
Usage:
python pi_subscriber.py --broker 192.168.0.100 --topic sensors/# --out messages.csv
"""
import argparse, csv, time
import paho.mqtt.client as mqtt

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--broker", required=True)
    p.add_argument("--port", type=int, default=1883)
    p.add_argument("--topic", default="#")
    p.add_argument("--out", default="messages.csv")
    args = p.parse_args()
    outfh = open(args.out, "w", newline="")
    writer = csv.writer(outfh)
    writer.writerow(["timestamp","topic","payload"])
    def on_connect(client, userdata, flags, rc):
        client.subscribe(args.topic)
    def on_message(client, userdata, msg):
        writer.writerow([time.time(), msg.topic, msg.payload.decode(errors="ignore")])
        outfh.flush()
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(args.broker, args.port)
    try:
        client.loop_forever()
    finally:
        outfh.close()

if __name__ == "__main__":
    main()
