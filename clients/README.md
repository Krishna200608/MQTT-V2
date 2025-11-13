# 📘 **README — MQTT Clients (Publisher & Subscriber)**

This folder contains the **MQTT client scripts** used to generate **benign IoT traffic** for the MQTT IDS Lab setup.
Two laptops are used:

* **Client 1:** MQTT Publisher (simulates IoT sensors)
* **Client 2:** MQTT Subscriber (records messages into CSV)

Both clients connect to the broker at:

```
192.168.0.100
```

---

## 📦 **1. Dependencies**

Install Python 3.8+ and the required module:

```bash
pip install paho-mqtt
```

Optional (for debugging):

```bash
pip install rich
```

---

## 📂 **2. Files in this folder**

| File                 | Purpose                                                                      |
| -------------------- | ---------------------------------------------------------------------------- |
| `pi_publisher.py`    | Publishes multiple IoT sensor values (temperature, humidity, pressure, etc.) |
| `pi_subscriber.py`   | Subscribes to sensor topics and logs messages to CSV                         |
| `run_publisher.bat`  | One-click launcher for publisher                                             |
| `run_subscriber.bat` | One-click launcher for subscriber                                            |

---

## 🖥️ **3. Usage Instructions**

### ✔ **A. Client Laptop #1 — Publisher**

Runs continuous IoT sensor readings.

**Windows (recommended):**
Double-click:

```
run_publisher.bat
```

Or via command line:

```bash
python pi_publisher.py --broker 192.168.0.100 --rate 5
```

Publishes values to topics:

```
sensors/temperature
sensors/humidity
sensors/pressure
sensors/light
sensors/motion
sensors/co2
```

---

### ✔ **B. Client Laptop #2 — Subscriber**

Records all published messages into `iot_messages.csv`.

Double-click:

```
run_subscriber.bat
```

Or via command line:

```bash
python pi_subscriber.py --broker 192.168.0.100 --topic sensors/# --out iot_messages.csv
```

The CSV will contain:

```
timestamp, topic, payload
```

---

## 📡 **4. Network Requirements**

* Both client laptops must be connected to the same router as the broker:

  ```
  192.168.0.x
  ```
* Broker must be reachable at:

  ```
  192.168.0.100:1883
  ```

---

## 🛠 **5. Stopping the Clients**

Press **CTRL + C** in the console window
or simply close the terminal.

---

## 🎯 **6. Purpose**

These clients generate **realistic IoT MQTT traffic**, required for:

* Benign traffic in IDS testing
* MQTT-IoT-IDS2020 dataset reproduction
* Lab demonstration of attack detection
