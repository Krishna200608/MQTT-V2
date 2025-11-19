# 📘 **MQTT IDS – Attacks Folder README**

This folder contains the **controlled attack scripts** used to evaluate and stress-test the **MQTT Intrusion Detection System (IDS)** running on the broker machine.

All attacks are designed to be:

* reproducible
* safe inside a lab network
* aligned with the MQTT-IoT-IDS2020 dataset
* detectable by both **heuristic rules** and **ML-based** detectors in the IDS pipeline

---

# 📂 **Files in This Folder**

| File                 | Description                                                                                             |
| -------------------- | ------------------------------------------------------------------------------------------------------- |
| `run_attacks.ps1`    | Main PowerShell launcher for controlled attacks (TCP scan, UDP scan, SSH brute-force, MQTT brute-force) |
| `mqtt_bruteforce.py` | MQTT username/password brute-forcing script                                                             |
| `users.txt`          | Username dictionary for brute-force attacks                                                             |
| `passwords.txt`      | Password dictionary for brute-force attacks                                                             |
| `README.md`          | This documentation                                                                                      |

---

# 🧪 **Purpose of These Attacks**

These attacks generate **realistic malicious traffic** against the MQTT broker.
They are used to:

* Validate IDS performance
* Capture PCAPs for ML training
* Reproduce MQTT-IoT-IDS2020 dataset behavior
* Test the real-time IDS pipeline (packet, uniflow, biflow)
* Trigger heuristic detectors (MQTT brute, SSH brute, scans)

---

# ⚙️ **Configuration**

Before running the script, ensure your lab network configuration file exists:

```
configs/network_config.json
```

Example structure:

```json
{
  "broker_ip": "192.168.0.100",
  "attacker_ip": "192.168.0.200",
  "client1_ip": "192.168.0.101",
  "client2_ip": "192.168.0.102"
}
```

The attack script automatically reads:

* **Target Broker IP**
* **Attacker (your current machine’s) IP**
* **Paths for user/password wordlists**

---

# 🚀 **Running the Attack Launcher**

From the **attacker laptop**, open PowerShell:

```powershell
cd attacks
.\run_attacks.ps1
```

You will see an interactive menu:

```
[1] Run all attacks once
[2] Run attacks in loop (25 cycles)
[3] Exit
```

---

# 🔥 **Included Attacks**

## 1️⃣ TCP SYN Scan (scan_A)

```
nmap -sS -p 1-1024 <broker_ip>
```

Simulates aggressive TCP scanning
→ Detected as **scan_A** by IDS models and heuristics.

---

## 2️⃣ UDP Scan (scan_sU)

```
nmap -sU --top-ports 50 <broker_ip>
```

Simulates top-port UDP scanning
→ Detected as **scan_sU**.

---

## 3️⃣ SSH Brute-force (sparta)

```
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt <broker_ip>
```

Repeated password guessing attempts
→ Detected as **sparta** by heuristic (SSH packet thresholds).

---

## 4️⃣ MQTT Brute-force (mqtt_bruteforce)

```
python mqtt_bruteforce.py <broker_ip>
```

Tries multiple MQTT username/password pairs
→ Detected as **mqtt_bruteforce** using MQTT connect/message thresholds.

---

# 🔁 **Loop Mode**

Selecting option **2** executes a controlled attack cycle:

```
TCP Scan → UDP Scan → SSH Brute → MQTT Brute
```

Repeated **25 times**, with a small pause between cycles.
Useful for generating long-running datasets or stressing the IDS.

---

# 🧼 **Safety & Lab Containment**

⚠ **DO NOT RUN THIS OUTSIDE YOUR OWN LAB NETWORK.**

* All attacks are intended strictly for local testing.
* Ensure you are NOT targeting external hosts.
* Use only inside the isolated MQTT IDS test environment.

---

# 📝 **Expected IDS Behavior**

When the IDS (live_ids.py) is running on the broker machine:

* Packet/uniflow/biflow ML models will detect ML-classifiable behaviors
* Heuristic detectors will trigger high-confidence alerts
* Alerts appear in:

```
live_scripts/logs/YYYY-MM-DD/ids_alerts.log
```

* The dashboard (`live_ids_dashboard.py`) will update live:

  * scan_A
  * scan_sU
  * sparta
  * mqtt_bruteforce

---

# 🎯 **Summary**

This folder provides everything required to **simulate realistic MQTT network attacks** in a safe, repeatable environment.
Use it together with:

* `start_broker_env.ps1` on the broker machine
* `run_clients_env.ps1` to generate benign IoT traffic
* `run_attacks.ps1` to simulate malicious events
* `live_ids.py` and `live_ids_dashboard.py` to monitor detections

You now have a full laboratory to evaluate the MQTT IDS pipeline end-to-end.

