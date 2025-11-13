#!/usr/bin/env python3
"""
Subscriber for recording MQTT IoT sensor data into CSV.
"""

import argparse
import csv
import time
import paho.mqtt.client as mqtt

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--broker", required=True)
    p.add_argument("--port", type=int, default=1883)
    p.add_argument("--topic", default="sensors/#")
    p.add_argument("--out", default="iot_messages.csv")
    args = p.parse_args()

    outfh = open(args.out, "w", newline="")
    writer = csv.writer(outfh)
    writer.writerow(["timestamp","topic","payload"])

    def on_connect(client, userdata, flags, rc):
        client.subscribe(args.topic)
        print(f"Subscribed to {args.topic} on {args.broker}:{args.port}")

    def on_message(client, userdata, msg):
        writer.writerow([time.time(), msg.topic, msg.payload.decode(errors="ignore")])
        outfh.flush()
        print(f"Received → {msg.topic}: {msg.payload.decode(errors='ignore')}")

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
