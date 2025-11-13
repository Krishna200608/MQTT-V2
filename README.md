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
├── attack_synthetic_generator.py
├── attacks
│   ├── mqtt_bruteforce.py
│   ├── passwords.txt
│   ├── run_all_attacks.bat
│   ├── run_attacks_loop.bat
│   ├── run_full_attacks.bat
│   ├── scan_A.bat
│   ├── scan_sU.bat
│   ├── ssh_bruteforce_nmap.bat
│   └── users.txt
├── clients
│   ├── pi_publisher.py
│   ├── pi_subscriber.py
│   ├── README.md
│   ├── run_publisher.bat
│   └── run_subscriber.bat
├── commands
│   ├── start_broker_env.bat
│   └── stop_broker_env.bat
├── data
│   ├── biflow_features
│   │   ├── biflow_mqtt_bruteforce.csv
│   │   ├── biflow_normal.csv
│   │   ├── biflow_scan_A.csv
│   │   ├── biflow_scan_sU.csv
│   │   └── biflow_sparta.csv
│   ├── combined
│   │   ├── biflow_test.csv
│   │   ├── biflow_train.csv
│   │   ├── packet_test.csv
│   │   ├── packet_train.csv
│   │   ├── split_metadata.json
│   │   ├── uniflow_test.csv
│   │   └── uniflow_train.csv
│   ├── packet_features
│   │   ├── mqtt_bruteforce.csv
│   │   ├── normal.csv
│   │   ├── scan_A.csv
│   │   ├── scan_sU.csv
│   │   └── sparta.csv
│   ├── pcap_files
│   │   ├── mqtt_bruteforce.pcap
│   │   ├── normal.pcap
│   │   ├── scan_A.pcap
│   │   ├── scan_sU.pcap
│   │   └── sparta.pcap
│   └── uniflow_features
│       ├── uniflow_mqtt_bruteforce.csv
│       ├── uniflow_normal.csv
│       ├── uniflow_scan_A.csv
│       ├── uniflow_scan_sU.csv
│       └── uniflow_sparta.csv
├── folder_structure.txt
├── helper
│   ├── addresse_commands.md
│   ├── biflow.md
│   └── uniflow.md
├── live_ids.py
├── live_ids_dashboard.py
├── model_outputs
│   ├── biflow
│   │   └── random_forest
│   │       ├── evaluation_results
│   │       │   ├── confusion_matrix.png
│   │       │   ├── eval_classification_report.csv
│   │       │   ├── eval_classification_report.txt
│   │       │   └── eval_summary.json
│   │       ├── model_comparison.csv
│   │       ├── model_comparison.png
│   │       ├── random_forest
│   │       │   ├── feature_importance_rf.csv
│   │       │   ├── feature_importance_rf.png
│   │       │   └── model_rf.joblib
│   │       └── train_metadata.json
│   ├── packet
│   │   └── decision_tree
│   │       ├── evaluation_results
│   │       │   ├── confusion_matrix.png
│   │       │   ├── eval_classification_report.csv
│   │       │   ├── eval_classification_report.txt
│   │       │   └── eval_summary.json
│   │       ├── model_comparison.csv
│   │       ├── model_comparison.png
│   │       ├── model_dt
│   │       │   ├── feature_importance_dt.csv
│   │       │   ├── feature_importance_dt.png
│   │       │   └── model_dt.joblib
│   │       └── train_metadata.json
│   └── uniflow
│       └── random_forest
│           ├── evaluation_results
│           │   ├── confusion_matrix.png
│           │   ├── eval_classification_report.csv
│           │   ├── eval_classification_report.txt
│           │   └── eval_summary.json
│           ├── model_comparison.csv
│           ├── model_comparison.png
│           ├── random_forest
│           │   ├── feature_importance_rf.csv
│           │   ├── feature_importance_rf.png
│           │   └── model_rf.joblib
│           └── train_metadata.json
├── print_structure.py
├── README.md
├── requirements.txt
└── scripts
    ├── evaluate_model.py
    ├── pcap_to_features.py
    ├── prepare_combined_csv.py
    ├── run_all.py
    └── train_model.py
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
