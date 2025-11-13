#!/usr/bin/env python3
"""
Enhanced MQTT Publisher
Simulates multiple IoT sensor readings:
 - temperature (°C)
 - humidity (%)
 - pressure (hPa)
 - light (lux)
 - motion (0/1)
 - CO2 ppm
"""

import argparse
import time
import random
import paho.mqtt.client as mqtt

def generate_sensor_payload():
    """Generate multiple IoT sensor readings."""
    data = {
        "temperature": round(random.uniform(20.0, 30.0), 2),
        "humidity": round(random.uniform(30.0, 80.0), 2),
        "pressure": round(random.uniform(990, 1020), 2),
        "light": random.randint(100, 900),
        "motion": random.randint(0, 1),
        "co2": random.randint(400, 1200)
    }
    return data

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--broker", required=True)
    p.add_argument("--port", type=int, default=1883)
    p.add_argument("--rate", type=float, default=2.0, help="messages per second")
    args = p.parse_args()

    client = mqtt.Client()
    client.connect(args.broker, args.port)

    interval = 1 / args.rate

    print(f"Publishing IoT sensor data to MQTT broker {args.broker}:{args.port}")
    print("Press CTRL+C to stop...\n")

    try:
        while True:
            reading = generate_sensor_payload()

            # Publish one topic per sensor (realistic)
            for sensor, value in reading.items():
                topic = f"sensors/{sensor}"
                message = str(value)
                client.publish(topic, message)
                print(f"Published → {topic}: {value}")

            time.sleep(interval)

    except KeyboardInterrupt:
        print("Publisher stopped.")

if __name__ == "_main_":
    main()