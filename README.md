# 📘 **README.md — MQTT-Based Intrusion Detection System (IDS)**

A complete Machine Learning + Real-Time Intrusion Detection System for **MQTT networks**, built using:

* **Packet-level**, **Uniflow**, and **Biflow** features
* **Decision Tree** (packet) + **Random Forest** (flows)
* **Real-time packet capture** with TShark
* **Live feature extraction** (packet → uniflow → biflow)
* **Real-time IDS pipeline**
* **Dashboard visualization**
* **Controlled attack environment** (Nmap scans, MQTT brute force, SSH brute force)
* **IoT client device simulation**

This project recreates and extends ideas from the **MQTT-IoT-IDS2020** research dataset, adapted for a real practical environment.

---

# 🧭 **Project Folder Structure (High-Level)**

```
MQTT V2
├── attacks/                 ← Nmap + MQTT brute-force attack scripts
├── clients/                 ← IoT publisher & subscriber
├── commands/                ← Start/stop broker + Live IDS environment
├── configs/                 ← Network & model configuration files
├── data/                    ← All datasets (raw, features, combined)
├── debug/                   ← Experimental utilities, pcap debugging
├── helper/                  ← Documentation for feature types
├── live_scripts/            ← Real-time IDS + dashboard + feature extraction
├── model_outputs/           ← Trained ML models + evaluation results
├── pcap_files/              ← Live TShark capture directory
├── scripts/                 ← ML pipeline scripts (train/eval/combine)
└── requirements.txt
```

---

# 🚀 **System Overview**

This project builds a **complete distributed IDS testbed**, typically run on:

* **Broker Laptop** → Mosquitto + Live IDS + Dashboard + TShark
* **Attacker Laptop** → Runs scanning & brute-force attacks
* **Client 1** → IoT Sensor Publisher
* **Client 2** → IoT Subscriber / Message Logger

---

# 🧩 **Core Components**

## **1. Data Pipeline (Offline ML Training)**

Located in:

```
scripts/
```

### ✔ `prepare_combined_csv.py`

Merges raw CSVs from:

* `packet_features/`
* `uniflow_features/`
* `biflow_features/`

Then creates:

```
data/combined/<mode>/<mode>_train.csv
data/combined/<mode>/<mode>_test.csv
```

---

### ✔ `train_model.py` (research-paper-faithful)

Trains:

* **Decision Tree (entropy)** for packet
* **Random Forest (n=10, entropy)** for uniflow
* **Random Forest (n=10, entropy)** for biflow

Saves artifacts inside:

```
model_outputs/<mode>/<model>/
```

Artifacts saved:

* `model_*.joblib`
* `preprocessor.joblib`
* `feature_names.json`
* `train_metadata.json`
* Evaluation CSV/TXT/PNG

---

### ✔ `evaluate_model.py`

Performs:

* prediction using `preprocessor.joblib`
* classification report
* accuracy
* confusion matrix plot
* summary JSON

---

### ✔ `run_all.py`

Incremental pipeline runner (skips steps if outputs exist).

### ✔ `run_man.py`

Mandatory full rebuild (deletes folders and retrains everything).

---

# 🔥 **2. Real-Time IDS Pipeline**

Located in:

```
live_scripts/
```

### ✔ `extractor.py`

Transforms incoming packet-level PCAPs into:

* Packet-level features
* Uniflow rows
* Biflow rows (29-feature flow vectors)

### ✔ `heuristics.py`

Rule-based detectors for:

* MQTT brute force
* SSH brute force
* TCP scan (Scan-A)
* UDP scan (Scan-sU)

### ✔ `live_ids.py`

Real-time IDS engine:

1. Reads rotating PCAPs in `pcap_files/`
2. Converts to features via extractor
3. Applies preprocessor + model
4. Applies heuristics
5. Writes alerts to:

```
commands/logs/<date>/ids_alerts.log
commands/ids_summary.csv
```

### ✔ `live_ids_dashboard.py`

Live graphical dashboard for viewing alerts in real time.

---

# 🧨 **3. Attacks (for testing detection)**

Located in:

```
attacks/
```

Includes:

* Nmap TCP Scan → **scan_A**
* Nmap UDP Scan → **scan_sU**
* SSH brute-force → **sparta**
* MQTT brute-force → **mqtt_bruteforce**

Master launcher:
`run_full_attacks.ps1`

---

# 📡 **4. MQTT IoT Clients**

Located in:

```
clients/
```

### ✔ Publisher → `pi_publisher.py`

Simulates IoT sensor readings:

* temperature
* humidity
* pressure
* light
* motion
* CO₂

### ✔ Subscriber → `pi_subscriber.py`

Logs all MQTT messages to:

```
iot_messages_TIMESTAMP.csv
```

Launchers:

* `run_publisher.ps1`
* `run_subscriber.ps1`
* `run_clients_env.ps1` (starts both)

---

# 🏠 **5. Broker Environment (Main Control Scripts)**

Located in:

```
commands/
```

### ✔ `start_broker_env.ps1`

Starts:

* Mosquitto Broker
* TShark rotating capture
* Live IDS
* Dashboard
* Cleans old PCAP files

### ✔ `stop_broker_env.ps1`

Gracefully shuts down everything.

---

# 🧪 **6. Training & Running the ML Pipeline**

## **Option A — Mandatory Full Rebuild**

Deletes previous outputs and rebuilds everything:

```
python scripts/run_man.py
```

## **Option B — Incremental Pipeline (Fast)**

Skips steps if output folders already exist:

```
python scripts/run_all.py
```

---

# 🧠 **7. Model Output Structure**

Located at:

```
model_outputs/
```

Each feature mode has:

```
model_outputs/<mode>/<algorithm>/
    model_*.joblib
    preprocessor.joblib
    feature_names.json
    train_metadata.json
    evaluation_results/
```

These files are used by `live_ids.py` during real-time classification.

---

# 🔧 **8. Requirements**

Install dependencies:

```
pip install -r requirements.txt
```

Requires:

* Python 3.10–3.12
* TShark installed and available in PATH
* Mosquitto MQTT Broker installed

---

# 🚀 **9. How to Run the Full IDS System**

### **Step 1 — Start Broker Environment**

On Broker Laptop:

```
commands/start_broker_env.ps1
```

### **Step 2 — Start IoT Devices**

On Publisher Laptop:

```
clients/run_publisher.ps1
```

On Subscriber Laptop:

```
clients/run_subscriber.ps1
```

### **Step 3 — Start Attacks**

On Attacker Laptop:

```
attacks/run_full_attacks.ps1
```

### **Step 4 — View Real-Time Alerts**

Dashboard starts automatically from `start_broker_env.ps1`.

---

# 🎯 **10. Conclusion**

This repository forms a **complete MQTT-based IDS laboratory**, with:

* Offline ML Training
* Real-time Detection Pipeline
* Automated Attacker Scripts
* IoT Traffic Simulation
* Full Automation (PowerShell)
* Real PCAP → Feature Pipeline
* Reproducible evaluation framework

Perfect for:

* Academic research
* Thesis/Dissertation work
* Demonstration environments
* Dataset reproduction
* ML experimentation

