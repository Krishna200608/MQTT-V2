#!/usr/bin/env python3
"""
Enhanced MQTT Subscriber
Matches the structure & conventions of the Enhanced MQTT Publisher.

This script:
 - subscribes to sensors/# topics
 - logs incoming IoT sensor messages into CSV
 - prints clean real-time updates
"""

import argparse
import csv
import time
import paho.mqtt.client as mqtt


def init_csv(path):
    """Create/open a CSV file and write header."""
    fh = open(path, "w", newline="")
    writer = csv.writer(fh)
    writer.writerow(["timestamp", "topic", "value"])
    return fh, writer


def on_connect(client, userdata, flags, rc):
    topic = userdata["topic"]
    broker = userdata["broker"]
    port = userdata["port"]

    client.subscribe(topic)
    print(f"Connected → Subscribed to '{topic}' at {broker}:{port}\n")


def on_message(client, userdata, msg):
    writer = userdata["writer"]
    fh = userdata["fh"]

    try:
        payload = msg.payload.decode("utf-8", errors="ignore")
    except Exception:
        payload = "<decode_error>"

    ts = round(time.time(), 3)
    writer.writerow([ts, msg.topic, payload])
    fh.flush()

    print(f"Received → {msg.topic}: {payload}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--broker", required=True, help="MQTT broker IP/hostname")
    p.add_argument("--port", type=int, default=1883)
    p.add_argument("--topic", default="sensors/#", help="Topic filter")
    p.add_argument("--out", default="iot_messages.csv", help="Output CSV file")
    args = p.parse_args()

    fh, writer = init_csv(args.out)

    userdata = {
        "topic": args.topic,
        "writer": writer,
        "fh": fh,
        "broker": args.broker,
        "port": args.port,
    }

    client = mqtt.Client(userdata=userdata)
    client.on_connect = on_connect
    client.on_message = on_message

    print(f"Listening for IoT sensor messages on {args.topic}...\n")

    client.connect(args.broker, args.port)

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("\nSubscriber stopped.")
    finally:
        fh.close()


if __name__ == "__main__":
    main()
