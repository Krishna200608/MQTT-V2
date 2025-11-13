# 📘 **README.md — MQTT-Based Intrusion Detection System (IDS) Lab**

This project implements a **complete MQTT Intrusion Detection System (IDS)** environment modeled after the **MQTT-IoT-IDS2020 dataset**, including:

* ✔ Machine Learning classification (packet, uniflow, biflow)
* ✔ Real-time IDS on live network traffic
* ✔ Automated attack generation (ScanA, Scan sU, Sparta, MQTT brute-force)
* ✔ 2 simulated IoT clients (publisher + subscriber)
* ✔ Full Windows automation (start/stop scripts, dashboards)
* ✔ Real-time PCAP capture + feature extraction + alerts

The entire system runs on a local isolated router-based testbed across **4 laptops** (broker, attacker, and 2 IoT clients).

---

# 🧩 **1. Python Virtual Environment Setup (Python 3.12)**

This project requires **Python 3.12** for full compatibility with Scikit-learn, Scapy, and custom scripts.

### ✔ Step 1 — Create a virtual environment (Windows)

Open terminal inside project root:

```cmd
python3.12 -m venv .venv
```

### ✔ Step 2 — Activate the environment

```cmd
.\.venv\Scripts\activate
```

Your terminal should now show:

```
(.venv)
```

---

# 📦 **2. Install Dependencies**

Once your virtual environment is activated:

```cmd
pip install -r requirements.txt
```

This installs all components needed for:

* Model training/evaluation
* Live IDS processing
* Dashboard visualization
* MQTT communication
* Scapy packet parsing
* TShark/PyShark compatibility
* Attack simulation

---

# 📄 **3. Updated requirements.txt**

You provided a base set, but your project now includes:

* **rich** → for real-time dashboard
* **colorama** → for colored output in terminals
* **pywin32** (optional but recommended) → for better Windows CMD handling
* **packaging** → required by some sklearn/scapy installs

Below is the **updated final requirements.txt**:

```txt
numpy>=1.26.4
pandas>=2.2.3
scikit-learn>=1.3.2,<1.5
joblib==1.3.2
paho-mqtt==1.6.1
scapy>=2.5.0
pyshark>=0.4.3.post1
tqdm==4.66.1
setuptools<81
psutil
matplotlib
seaborn
rich>=13.7.1
colorama>=0.4.6
pywin32>=306
packaging>=24.0
```

### Optional (only if you want advanced dashboard plotting):

```
plotly
```

---

# 🧭 **4. Repository Structure (Overview)**

```
MQTT V2
│
├── commands/                # Start/Stop scripts for broker environment
│   ├── start_broker_env.bat
│   ├── stop_broker_env.bat
│   └── run_full_demo.bat
│
├── attacks/                 # Attacker laptop scripts
│   ├── scan_A.bat
│   ├── scan_sU.bat
│   ├── ssh_bruteforce_nmap.bat
│   ├── mqtt_bruteforce.py
│   └── run_full_attacks.bat
│
├── clients/                 # IoT client laptops
│   ├── pi_publisher.py
│   ├── pi_subscriber.py
│   ├── run_publisher.bat
│   └── run_subscriber.bat
│
├── live_ids.py              # Real-time IDS engine
├── live_ids_dashboard.py    # Console dashboard for alerts
│
├── model_outputs/           # Trained ML models + metadata
├── data/                    # Dataset CSVs + PCAPs
├── scripts/                 # Training/evaluation utilities
│
└── requirements.txt         # Dependencies
```

---

# 🚀 **5. Core Components (Short)**

### 🔹 Broker Laptop

* Runs Mosquitto (MQTT Broker)
* Runs TShark rotating capture
* Runs live IDS analysis (`live_ids.py`)
* Runs dashboard (`live_ids_dashboard.py`)

### 🔹 Attacker Laptop

* Nmap scan attacks (ScanA, Scan sU)
* SSH brute-force simulation (Sparta-like)
* MQTT brute-force script
* Loop automation (`run_full_attacks.bat`)

### 🔹 Client #1 (Publisher)

* Sends multiple IoT sensor readings continuously

### 🔹 Client #2 (Subscriber)

* Listens to all MQTT topics
* Logs messages into CSV

### 🔹 Machine Learning

* Packet, Uniflow, Biflow models trained using Scikit-Learn
* Biflow Random Forest = best performance (MQTT-BF detection)

---

# 🎯 **6. How To Run The SYSTEM (Short)**

## 🟢 **1. On Broker Laptop**

```
commands\start_broker_env.bat
```

Starts:

* TShark capture
* Live IDS processing
* Dashboard
* PCAP directory

## 🔵 **2. On Attacker Laptop**

```
attacks\run_full_attacks.bat
```

Offers:

1. Run attacks once
2. 25-cycle attack loop

## 🟡 **3. On Client Laptop #1 (Publisher)**

```
clients\run_publisher.bat
```

## 🟠 **4. On Client Laptop #2 (Subscriber)**

```
clients\run_subscriber.bat
```

---

# 🎉 Conclusion

You now have a **fully automated, reproducible, multi-machine MQTT IDS testbed** ready for:

* Research experimentation
* Dataset reproduction
* Machine learning benchmarking
* Real-time attack demonstration
* Academic demonstration / presentation
